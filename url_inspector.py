#!/usr/bin/env python3
"""
url_inspector.py — Final OSINT URL inspector
- Fancy grid tables (tabulate 'fancy_grid')
- SSL, HTTPS, DNS/IPs, WHOIS (domain creation/update/expiry), VirusTotal (v3), Shodan host lookup
- Short Status line above each section (Option A)
- Safe formatting to avoid table breakage
- Keys: CLI > ENV > HARDCODED fallback
"""

from typing import Any, Dict, List, Optional, Tuple
from dateutil.parser import parse as parse_dt
import argparse
import base64
import datetime
import json
import logging
import os
import socket
import ssl
import sys
import time
import shutil
from textwrap import shorten
def print_banner():
    banner = r"""
 _   _   ____   _        ___           _ ___                      _             
| | | | |  _ \ | |      |_ _|_ __  ___| |_| |  __    ___ | |_ ___  _ __ 
| | | | | |_) || |       | || '_ \/ __|  _ _/_/ _ \ / _/ | __/ _ \| '__|
| |_| | |  _ < | |___    | || | | \__ \  |   |  __/| |_  | || (_) |  |   
 \___/  |_| \_\|_____|  |___|_| |_|___/|_|    \___||\__\_\__ \___/|_|   
                                                                               
                         BY captainJ
    """
    print(banner)


# optional whois import (graceful if missing)
try:
    import whois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

import idna
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from tabulate import tabulate

# ---------- Configuration ----------
DEFAULT_TIMEOUT = 8.0
VT_API_ENV = "VT_API_KEY"
SHODAN_API_ENV = "SHODAN_API_KEY"

# Hard-coded (insecure) fallback — change or leave empty
HARDCODED_VT_KEY = " "          # Put your VirusTotal v3 API key here if desired
HARDCODED_SHODAN_KEY = " "      # Put your Shodan API key here if desired

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("url_inspector")


# ---------- Utility: safe text for tables ----------
def safe_text(value: Any, max_len: Optional[int] = None) -> str:
    """
    Convert a value to a safe single-line string for table cells.
    - removes newlines
    - shortens long content according to terminal width
    """
    if value is None:
        text = ""
    elif isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, ensure_ascii=False)
        except Exception:
            text = str(value)
    else:
        text = str(value)

    text = text.replace("\r", " ").replace("\n", " ")

    try:
        width = shutil.get_terminal_size((120, 24)).columns
    except Exception:
        width = 120

    default_max = max(40, min(250, int(width * 0.75)))
    limit = max_len if isinstance(max_len, int) else default_max

    if len(text) > limit:
        return shorten(text, width=limit, placeholder="…")
    return text


# ---------- Helpers ----------
def now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def normalize_input(url_or_host: str) -> Tuple[str, str]:
    """Return (hostname, scheme). If scheme absent assume http."""
    if "://" in url_or_host:
        scheme, rest = url_or_host.split("://", 1)
        host = rest.split("/", 1)[0]
    else:
        scheme = "http"
        host = url_or_host.split("/", 1)[0]
    if host.count(":") == 1 and not host.startswith("["):
        hostname = host.split(":", 1)[0]
    else:
        hostname = host
    return hostname.strip(), scheme.strip().lower()


def resolve_ips(hostname: str, timeout: float = DEFAULT_TIMEOUT) -> List[str]:
    ips = set()
    try:
        try:
            host_enc = idna.encode(hostname).decode()
        except Exception:
            host_enc = hostname
        for res in socket.getaddrinfo(host_enc, None, proto=socket.IPPROTO_TCP):
            ips.add(res[4][0])
    except Exception as e:
        log.debug("DNS resolution failed for %s: %s", hostname, e)
    return sorted(ips)


def get_ssl_certificate_info(hostname: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    info: Dict[str, Any] = {"present": False, "error": None}
    try:
        try:
            server_hostname = idna.encode(hostname).decode()
        except Exception:
            server_hostname = hostname

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                info["present"] = bool(der)
                info["tls_version"] = ssock.version()
                try:
                    info["cipher"] = ssock.cipher()[0]
                except Exception:
                    info["cipher"] = ssock.cipher()
                if der:
                    cert = x509.load_der_x509_certificate(der, default_backend())

                    def rdns_to_dict(name):
                        d = {}
                        for attr in name:
                            key = attr.oid._name if getattr(attr.oid, "_name", None) else attr.oid.dotted_string
                            d[key] = attr.value
                        return d

                    info["subject"] = rdns_to_dict(cert.subject)
                    info["issuer"] = rdns_to_dict(cert.issuer)
                    info["not_before"] = cert.not_valid_before.isoformat()
                    info["not_after"] = cert.not_valid_after.isoformat()
                    info["serial_number"] = format(cert.serial_number, "x")
                    try:
                        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        sans = ext.value.get_values_for_type(x509.DNSName)
                        info["san"] = sans
                    except Exception:
                        info["san"] = []
                else:
                    info["error"] = "no_certificate_returned"
    except Exception as e:
        info["error"] = str(e)
    return info


def check_https_request(url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    out: Dict[str, Any] = {"can_connect": False, "status_code": None, "final_url": None, "headers": {}, "error": None}
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        out["can_connect"] = True
        out["status_code"] = r.status_code
        out["final_url"] = r.url
        out["headers"] = dict(r.headers)
    except requests.exceptions.SSLError as e:
        out["error"] = f"SSL Error: {e}"
    except requests.exceptions.RequestException as e:
        out["error"] = str(e)
    return out


# ---------------- VirusTotal v3 ----------------
def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode().rstrip("=")


def query_virustotal_url(url: str, api_key: Optional[str], timeout: float = 10.0) -> Dict[str, Any]:
    result: Dict[str, Any] = {"success": False, "raw": None, "summary": {}, "malicious_engines": []}
    if not api_key:
        result["note"] = "no_api_key_provided"
        return result
    headers = {"x-apikey": api_key}
    url_id = vt_url_id(url)
    api = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        r = requests.get(api, headers=headers, timeout=timeout)
        result["status_code"] = r.status_code
        if r.status_code == 200:
            j = r.json()
            result["raw"] = j
            attrs = j.get("data", {}).get("attributes", {})
            result["summary"] = attrs.get("last_analysis_stats", {})
            engines = attrs.get("last_analysis_results", {})
            for eng_name, eng_info in engines.items():
                cat = eng_info.get("category")
                if cat in ("malicious", "suspicious"):
                    result["malicious_engines"].append({"engine": eng_name, "result": eng_info.get("result"), "category": cat})
            result["success"] = True
        else:
            try:
                result["raw"] = r.json()
            except Exception:
                result["raw"] = {"status_code": r.status_code, "text": r.text}
    except Exception as e:
        result["raw"] = {"error": str(e)}
    return result


# ---------------- Shodan host ----------------
def query_shodan_host(ip: str, api_key: Optional[str], timeout: float = 10.0) -> Dict[str, Any]:
    out: Dict[str, Any] = {"success": False, "raw": None}
    if not api_key:
        out["raw"] = "no_api_key_provided"
        return out
    api = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        r = requests.get(api, timeout=timeout)
        out["status_code"] = r.status_code
        if r.status_code == 200:
            j = r.json()
            out["success"] = True
            out["raw"] = j
            out["ports"] = j.get("ports", [])
            out["org"] = j.get("org")
            out["hostnames"] = j.get("hostnames", [])
            out["vulns"] = j.get("vulns", [])
        else:
            try:
                out["raw"] = r.json()
            except Exception:
                out["raw"] = {"status_code": r.status_code, "text": r.text}
    except Exception as e:
        out["raw"] = {"error": str(e)}
    return out


# ---------------- WHOIS ----------------
def get_domain_whois(hostname: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"success": False}
    if not WHOIS_AVAILABLE:
        out["error"] = "python-whois not installed"
        return out
    try:
        w = whois.whois(hostname)
        out["success"] = True
        # normalize possibly-list fields
        def norm(d):
            if isinstance(d, list):
                return d[0] if d else None
            return d
        created = norm(w.creation_date)
        updated = norm(w.updated_date)
        expires = norm(w.expiration_date)
        out["created"] = created.isoformat() if hasattr(created, "isoformat") else (str(created) if created else None)
        out["updated"] = updated.isoformat() if hasattr(updated, "isoformat") else (str(updated) if updated else None)
        out["expires"] = expires.isoformat() if hasattr(expires, "isoformat") else (str(expires) if expires else None)
        out["registrar"] = w.registrar
    except Exception as e:
        out["error"] = str(e)
    return out


# ---------------- Heuristics for statuses ----------------
SENSITIVE_PORTS = {21, 22, 23, 3389, 445, 3306, 1433, 1521}  # common risky ports


def ssl_status(ssl_info: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Return (status_label, reason_or_None)"""
    if not ssl_info:
        return "BAD", "no_certificate"
    if ssl_info.get("error"):
        return "BAD", ssl_info.get("error")
    # check dates
    try:
        nb = datetime.datetime.fromisoformat(ssl_info["not_before"])
        na = datetime.datetime.fromisoformat(ssl_info["not_after"])
        now = datetime.datetime.utcnow()
        if not (nb <= now <= na):
            if now < nb:
                return "BAD", "certificate_not_yet_valid"
            return "BAD", "certificate_expired"
    except Exception:
        # if date parsing fails, warn but keep as BAD
        return "BAD", "certificate_date_parse_failed"
    return "GOOD", None


def https_status(https_info: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    if not https_info:
        return "BAD", "no_https_info"
    if https_info.get("error"):
        # SSL error vs other errors
        return "BAD", safe_text(https_info.get("error"))
    code = https_info.get("status_code")
    if code and 200 <= int(code) < 400:
        return "GOOD", None
    if code and 300 <= int(code) < 400:
        return "WARNING", f"redirect_{code}"
    return "BAD", f"status_{code}"


def vt_status(vt_info: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    if not isinstance(vt_info, dict):
        return "UNKNOWN", None
    if vt_info.get("note"):
        return "UNKNOWN", vt_info.get("note")
    if vt_info.get("success"):
        stats = vt_info.get("summary", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        if malicious + suspicious > 0:
            return "BAD", f"malicious={malicious}_suspicious={suspicious}"
        return "GOOD", None
    if vt_info.get("raw") and isinstance(vt_info.get("raw"), dict):
        # might contain error details
        return "UNKNOWN", safe_text(vt_info.get("raw"))
    if vt_info.get("raw"):
        return "UNKNOWN", safe_text(vt_info.get("raw"))
    if vt_info.get("error"):
        return "UNKNOWN", safe_text(vt_info.get("error"))
    return "UNKNOWN", None


def shodan_status(shodan_data: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    # shodan_data is a dict per IP or a map of ips -> results; this helper expects per-IP dict
    if not shodan_data:
        return "UNKNOWN", "no_shodan_data"
    if isinstance(shodan_data, dict) and "raw" in shodan_data and shodan_data.get("raw") == "no_api_key_provided":
        return "UNKNOWN", "no_api_key_provided"
    if not shodan_data.get("success"):
        # include raw if present
        raw = shodan_data.get("raw")
        if isinstance(raw, dict):
            # try to find an error message
            return "UNKNOWN", safe_text(raw)
        return "UNKNOWN", safe_text(shodan_data.get("raw") or shodan_data.get("error"))
    ports = set(shodan_data.get("ports", []) or [])
    if ports & SENSITIVE_PORTS:
        return "BAD", f"exposed_ports={','.join(map(str, sorted(ports & SENSITIVE_PORTS)))}"
    if ports:
        # if only web ports or common, mark warning or good
        web_ports = {80, 443, 8080, 8443}
        if ports <= web_ports:
            return "GOOD", None
        return "WARNING", f"open_ports={','.join(map(str, sorted(ports)))}"
    return "UNKNOWN", None


# ---------------- Assemble report ----------------
def assemble_report(input_url: str, vt_key: Optional[str], shodan_key: Optional[str]) -> Dict[str, Any]:
    hostname, scheme = normalize_input(input_url)
    report: Dict[str, Any] = {
        "meta": {"started_local": datetime.datetime.now().replace(microsecond=0).isoformat(),
                 "started_utc": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"},
        "query": {"input": input_url, "host": hostname, "scheme": scheme, "checked_at": now_iso()},
        "ips": [],
        "ssl": {},
        "https": {},
        "whois": {},
        "virustotal": {},
        "shodan": {},
        "summary": {},
    }

    # Resolve IPs
    report["ips"] = resolve_ips(hostname)

    # SSL certificate info
    report["ssl"] = get_ssl_certificate_info(hostname)

    # HTTPS request
    try_url = input_url if input_url.startswith("http") else f"https://{hostname}"
    report["https"] = check_https_request(try_url)

    # WHOIS
    report["whois"] = get_domain_whois(hostname)

    # VirusTotal
    report["virustotal"] = query_virustotal_url(input_url, vt_key)

    # Shodan per IP (if any)
    if report["ips"]:
        sh_res = {}
        for ip in report["ips"]:
            time.sleep(0.15)
            sh_res[ip] = query_shodan_host(ip, shodan_key)
        report["shodan"] = sh_res
    else:
        report["shodan"] = {}

    # Summary heuristics (combine)
    summary: Dict[str, Any] = {"protected": None, "reasons": []}

    s_ssl, r_ssl = ssl_status(report["ssl"])
    s_https, r_https = https_status(report["https"])
    s_vt, r_vt = vt_status(report["virustotal"])

    # decide protected flag: prefer VirusTotal and HTTPS
    if s_vt == "BAD":
        summary["protected"] = False
        summary["reasons"].append(f"virustotal:{r_vt}")
    elif s_https == "GOOD" and s_ssl == "GOOD":
        summary["protected"] = True
        summary["reasons"].append("https_and_valid_cert")
    else:
        summary["protected"] = False
        summary["reasons"].extend(filter(None, [r_https, r_ssl, r_vt]))

    report["summary"] = summary
    return report


# ---------------- Pretty-print (fancy_grid) ----------------
def print_status_line(status: str, reason: Optional[str] = None) -> None:
    """Print a short single-line status (Option A)"""
    emoji = "❌"
    label = status
    if status == "GOOD":
        emoji = "✅"
    elif status == "WARNING":
        emoji = "⚠️"
    elif status == "UNKNOWN":
        emoji = "❓"
    print(f"Status: {emoji} {label}" + (f" — {reason}" if reason else ""))


def pretty_print(report: Dict[str, Any]) -> None:
    # Header / meta
    q = report.get("query", {})
    meta = report.get("meta", {})
    header_rows = [
        ["Input", safe_text(q.get("input"))],
        ["Host", safe_text(q.get("host"))],
        ["Scheme", safe_text(q.get("scheme"))],
        ["Checked at (UTC)", safe_text(q.get("checked_at"))],
        ["Started (local)", safe_text(meta.get("started_local"))],
        ["Started (UTC)", safe_text(meta.get("started_utc"))],
    ]
    print("\n🔍 URL Inspection Report\n")
    print(tabulate(header_rows, tablefmt="fancy_grid"))

    # IPs
    print("\n🌍 Resolved IPs:")
    ips = report.get("ips", [])
    if ips:
        ip_rows = [[i + 1, safe_text(ip)] for i, ip in enumerate(ips)]
        print(tabulate(ip_rows, headers=["#", "IP Address"], tablefmt="fancy_grid"))
    else:
        print(tabulate([["No IPs resolved"]], tablefmt="fancy_grid"))

    # SSL
    print("\n🔐 SSL Certificate Info")
    s_label, s_reason = ssl_status(report.get("ssl", {}))
    print_status_line(s_label, s_reason)
    sslinfo = report.get("ssl", {})
    ssl_rows = []
    if sslinfo:
        ssl_rows.append(["Present", safe_text(sslinfo.get("present"))])
        ssl_rows.append(["TLS Version", safe_text(sslinfo.get("tls_version"))])
        ssl_rows.append(["Cipher", safe_text(sslinfo.get("cipher"))])
        ssl_rows.append(["Not Before (UTC)", safe_text(sslinfo.get("not_before"))])
        ssl_rows.append(["Not After (UTC)", safe_text(sslinfo.get("not_after"))])
        subj = sslinfo.get("subject") or {}
        issuer = sslinfo.get("issuer") or {}
        ssl_rows.append(["Subject CN", safe_text(subj.get("CommonName") or subj.get("CN") or next(iter(subj.values()), "") if subj else "")])
        ssl_rows.append(["Issuer CN", safe_text(issuer.get("CommonName") or issuer.get("CN") or next(iter(issuer.values()), "") if issuer else "")])
        ssl_rows.append(["SANs", safe_text(", ".join(sslinfo.get("san", [])) or "None")])
        if sslinfo.get("error"):
            ssl_rows.append(["Error", safe_text(sslinfo.get("error"))])
    else:
        ssl_rows.append(["Info", "No SSL data"])
    print(tabulate(ssl_rows, tablefmt="fancy_grid"))

    # HTTPS
    print("\n🌐 HTTPS Connection")
    h_label, h_reason = https_status(report.get("https", {}))
    print_status_line(h_label, h_reason)
    https = report.get("https", {})
    https_rows = [
        ["Can Connect", safe_text(https.get("can_connect"))],
        ["Status Code", safe_text(https.get("status_code"))],
        ["Final URL", safe_text(https.get("final_url"))],
        ["Error", safe_text(https.get("error"))],
    ]
    print(tabulate(https_rows, tablefmt="fancy_grid"))

    # Important headers (server, date, content-type)
    headers = https.get("headers", {}) if isinstance(https.get("headers"), dict) else {}
    if headers:
        key_headers = {k: headers[k] for k in ("Server", "Date", "Content-Type") if k in headers}
        if key_headers:
            print("\n📬 Important HTTP Headers:")
            rows = [[k, safe_text(v)] for k, v in key_headers.items()]
            print(tabulate(rows, tablefmt="fancy_grid"))

    # WHOIS
   # print("\n📅 Domain WHOIS Information")
   # who = report.get("whois", {})
  #  if who.get("success"):
        # short status on age
       # created = who.get("created")
       # age_months = None
      #  try:
     #       if created:
    #            created_dt = datetime.datetime.fromisoformat(created)
   #             age_days = (datetime.datetime.utcnow() - created_dt).days
  #              age_months = age_days / 30.0
 #       except Exception:
#            age_months = None

# WHOIS SECTION
    print("\n📅 Domain WHOIS Information")
    who = report.get("whois", {})
    if who.get("success"):
        
        # >>> THIS IS WHERE THE CREATED-DATE BLOCK SITS <<<
        created = who.get("created")
        age_months = None
        try:
            ...
        except Exception:
            age_months = None
        # determine status by age
        if age_months is None:
            w_status, w_reason = "UNKNOWN", None
        elif age_months < 1:
            w_status, w_reason = "BAD", f"domain_age_months={age_months:.1f}"
        elif age_months < 6:
            w_status, w_reason = "WARNING", f"domain_age_months={age_months:.1f}"
        else:
            w_status, w_reason = "GOOD", f"domain_age_months={age_months:.1f}"
        print_status_line(w_status, w_reason)
        who_rows = [
            ["Domain Created", safe_text(who.get("created"))],
            ["Domain Updated", safe_text(who.get("updated"))],
            ["Domain Expires", safe_text(who.get("expires"))],
            ["Registrar", safe_text(who.get("registrar"))],
        ]
        print(tabulate(who_rows, tablefmt="fancy_grid"))
    else:
        print_status_line("UNKNOWN", safe_text(who.get("error")))
        print(tabulate([["Info", safe_text(who.get("error") or "WHOIS not available")]], tablefmt="fancy_grid"))

    # VirusTotal
    print("\n🧪 VirusTotal")
    vt = report.get("virustotal", {})
    v_label, v_reason = vt_status(vt)
    print_status_line(v_label, v_reason)
    if isinstance(vt, dict):
        if vt.get("success"):
            stats = vt.get("summary", {})
            vt_rows = [
                ["harmless", safe_text(stats.get("harmless"))],
                ["malicious", safe_text(stats.get("malicious"))],
                ["suspicious", safe_text(stats.get("suspicious"))],
                ["undetected", safe_text(stats.get("undetected"))],
            ]
            print(tabulate(vt_rows, tablefmt="fancy_grid"))
            if vt.get("malicious_engines"):
                engines = [[safe_text(e.get("engine")), safe_text(e.get("result")), safe_text(e.get("category"))] for e in vt.get("malicious_engines")]
                print("\nVirusTotal - malicious engines:")
                print(tabulate(engines, headers=["Engine", "Result", "Category"], tablefmt="fancy_grid"))
        else:
            # show note/raw/error
            note_val = vt.get("raw") or vt.get("note") or vt.get("error")
            print(tabulate([["note", safe_text(note_val)]], tablefmt="fancy_grid"))
    else:
        print(tabulate([["info", safe_text(str(vt))]], tablefmt="fancy_grid"))

    # Shodan
    print("\n🛰️ Shodan Results")
    sh = report.get("shodan", {})
    # compute overall shodan verdict across IPs
    overall_sh_status = "UNKNOWN"
    overall_sh_reasons: List[str] = []
    sh_rows: List[List[str]] = []
    if isinstance(sh, dict) and sh:
        for ip, data in sh.items():
            if not isinstance(data, dict):
                sh_rows.append([safe_text(ip), "N/A", "N/A", "N/A", safe_text(str(data))])
                continue
            s, reason = shodan_status(data)
            if s == "BAD":
                overall_sh_status = "BAD"
                if reason:
                    overall_sh_reasons.append(f"{ip}:{reason}")
            elif s == "WARNING" and overall_sh_status != "BAD":
                overall_sh_status = "WARNING"
                if reason:
                    overall_sh_reasons.append(f"{ip}:{reason}")
            elif s == "GOOD" and overall_sh_status not in ("BAD", "WARNING"):
                overall_sh_status = "GOOD"
            # display per ip
            if data.get("success"):
                ports = ", ".join(map(str, data.get("ports", []) or [])) or "N/A"
                org = data.get("org") or ""
                hosts = ", ".join(data.get("hostnames", []) or []) or "N/A"
                vulns = ", ".join(data.get("vulns", []) or []) or "None"
                sh_rows.append([safe_text(ip), safe_text(org), safe_text(ports), safe_text(hosts), safe_text(vulns)])
            else:
                # try raw message
                raw = data.get("raw")
                err = ""
                if isinstance(raw, dict):
                    err = safe_text(raw)
                else:
                    err = safe_text(data.get("raw") or data.get("error") or "")
                sh_rows.append([safe_text(ip), "N/A", "N/A", "N/A", err])
    else:
        sh_rows.append(["note", safe_text(sh or "no shodan results")])

    print_status_line(overall_sh_status, "; ".join(overall_sh_reasons) if overall_sh_reasons else None)
    print(tabulate(sh_rows, headers=["IP", "Org", "Ports", "Hostnames", "Vulns/Error"], tablefmt="fancy_grid"))

    # Summary
    print("\n🔎 Summary")
    summary = report.get("summary", {})
    sum_rows = [
        ["Protected", safe_text(summary.get("protected"))],
        ["Reasons", safe_text("; ".join(summary.get("reasons", []) or []))],
    ]
    print(tabulate(sum_rows, tablefmt="fancy_grid"))


# ---------------- CLI / main ----------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OSINT URL inspector (SSL, IPs, WHOIS, VirusTotal, Shodan)")
    p.add_argument("url", help="URL or hostname to inspect (e.g. https://example.com or example.com)")
    p.add_argument("--vt", help="VirusTotal v3 API key (optional). CLI > ENV > HARDCODED", default=None)
    p.add_argument("--shodan", help="Shodan API key (optional). CLI > ENV > HARDCODED", default=None)
    p.add_argument("--output", "-o", help="Save full JSON report to file (optional)", default=None)
    p.add_argument("--quiet", action="store_true", help="Reduce logging verbosity")
    return p.parse_args()


def main():
    args = parse_args()
    print_banner()  # <-- ADD THIS EXACTLY HERE

    if args.quiet:
        log.setLevel(logging.WARNING)

    vt_key = args.vt or os.getenv(VT_API_ENV) or HARDCODED_VT_KEY or None
    shodan_key = args.shodan or os.getenv(SHODAN_API_ENV) or HARDCODED_SHODAN_KEY or None

    log.info("Starting inspection for %s", args.url)
    try:
        report = assemble_report(args.url, vt_key, shodan_key)
    except Exception as e:
        log.exception("Error while assembling report: %s", e)
        print("Fatal error:", e)
        sys.exit(1)

    # print tabular fancy output
    pretty_print(report)

    # optionally write JSON
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
            log.info("Report saved to %s", args.output)
        except Exception as e:
            log.error("Failed to save report: %s", e)


if __name__ == "__main__":
    main()
