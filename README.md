🔍 URL Inspector

A command-line OSINT tool for deep URL analysis integrating DNS, WHOIS, SSL, Shodan, and VirusTotal intelligence.

📌 Overview

URL Inspector is a Python-based security and OSINT tool designed to gather detailed intelligence about any URL.
It performs automated checks across multiple layers — domain, network, SSL, reputation, and infrastructure — and outputs everything in a clean, color-coded terminal report.

This is my first cybersecurity tool, built to learn Python automation, API integration, and multi-source intelligence gathering.


🚀 Features

URL Analysis — scheme, redirects, headers, status codes

DNS & Network Lookup — IPv4/IPv6 resolution, hostname mapping

WHOIS Data — domain age, registrar, creation/expiration details

SSL Certificate Inspection — TLS version, cipher suite, SANs, validity

HTTPS Connectivity Check — certificate validity + final URL behavior

VirusTotal Integration — multi-engine reputation scoring

Shodan Intelligence — open ports, hosting provider, infrastructure insights

Structured Output — clean, color-coded, neatly formatted tables


🛠️ Installation

git clone https://github.com/yourusername/url_inspector.git

cd url_inspector

pip install -r requirements.txt


🔑 API Keys

To enable VirusTotal and Shodan integrations, set your API keys:

export VT_API_KEY="your_key_here"

export SHODAN_API_KEY="your_key_here"

Or create a .env file:

VT_API_KEY=your_key_here

SHODAN_API_KEY=your_key_here


▶️ Usage

python url_inspector.py https://example.com


Example with verbose output:
python url_inspector.py https://example.com --full
