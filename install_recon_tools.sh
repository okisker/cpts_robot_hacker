#!/bin/bash
echo "[*] Installing required tools..."

# Update & common packages
sudo apt update && sudo apt install -y \
  nmap httpx whatweb gobuster feroxbuster ffuf nikto nuclei \
  hydra ncrack ssh-audit enum4linux smbclient crackmapexec smbmap \
  snmp snmpwalk onesixtyone ldap-utils smtp-user-enum \
  rpcbind dnsutils dnsenum nfs-common ftp pandoc git

# rdpscan (requires manual download)
if ! command -v rdpscan &> /dev/null; then
  echo "[*] Installing rdpscan..."
  git clone https://github.com/robertdavidgraham/rdpscan.git /tmp/rdpscan
  cd /tmp/rdpscan && make
  sudo cp rdpscan /usr/local/bin/
  cd -
fi

# searchsploit (ExploitDB)
if ! command -v searchsploit &> /dev/null; then
  echo "[*] Installing ExploitDB..."
  git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
  sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
  sudo cp /opt/exploitdb/.searchsploit_rc ~/
fi

echo "[+] All tools installed."
