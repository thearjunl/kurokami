#!/usr/bin/env bash
# KUROKAMI Setup Script for Debian-based/Parrot OS
set -euo pipefail

echo "[*] KUROKAMI Penetration Testing Framework - Initializer"

# Ensure we're running as root or have sudo access (useful for packages)
if [[ $EUID -ne 0 ]]; then
   echo "[WARNING] Some dependencies might require sudo."
fi

echo "[*] Installing required system packages (nmap, nikto, whois, etc...)"
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv nmap nikto whois dnsutils whatweb curl gobuster smbclient

echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Generating /config path if needed..."
mkdir -p ~/.config/kurokami

echo "[*] Running lightweight test suite..."
pytest -q || true

echo "[+] Done! Run 'source venv/bin/activate' then 'python3 -m core.cli --help'."
