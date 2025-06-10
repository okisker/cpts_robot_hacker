#!/bin/bash

set -e

echo "[*] Updating package lists..."
if sudo apt-get update; then
  echo "[+] Package lists updated."
else
  echo "[!] Failed to update package lists."
fi

echo "[*] Upgrading installed packages..."
if sudo apt-get upgrade -y; then
  echo "[+] Packages upgraded successfully."
else
  echo "[!] Package upgrade failed."
fi

echo "[*] Removing unused packages..."
if sudo apt autoremove -y; then
  echo "[+] Unused packages removed."
else
  echo "[!] Failed to remove unused packages."
fi

echo "[*] Installing required tools..."
REQUIRED_PACKAGES=(nmap whatweb gobuster ffuf hydra ncrack smbclient smbmap snmp ldap-utils rpcbind dnsutils nfs-common ftp gcc make python3-pip nuclei onesixtyone pandoc polenum ssh-audit)

FAILED_PACKAGES=()
for pkg in "${REQUIRED_PACKAGES[@]}"; do
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    echo "[*] $pkg is already installed."
  else
    if sudo apt-get install -y "$pkg"; then
      echo "[+] Installed $pkg successfully."
    else
      echo "[!] Failed to install $pkg."
      FAILED_PACKAGES+=("$pkg")
    fi
  fi
done

if [ ${#FAILED_PACKAGES[@]} -eq 0 ]; then
  echo "[+] All required tools installed successfully."
else
  echo "[!] Some packages failed to install: ${FAILED_PACKAGES[*]}"
  echo "    This might be due to dependency issues or held packages."
fi

echo "[*] Checking for Perl dependency issues..."
PERL_ISSUES=0
if ! sudo apt-get install -f; then
  echo "[!] Fix broken dependencies failed."
  PERL_ISSUES=1
fi

# Check if perl dependency problem still exists
if dpkg -s perl-base | grep -q "Version: 5.36.0-7+deb12u2" && dpkg -s perl | grep -q "Depends: perl-base (= 5.36.0-7+deb12u1)"; then
  echo "[!] Perl package dependency conflict detected:"
  echo "    - perl-base version: 5.36.0-7+deb12u2 installed"
  echo "    - perl requires version: 5.36.0-7+deb12u1"
  echo "    Please run these commands to fix:"
  echo "      sudo apt-mark unhold perl perl-base libperl5.36"
  echo "      sudo apt-get update"
  echo "      sudo apt-get install -f"
  echo "      sudo apt-get upgrade"
  PERL_ISSUES=1
fi

if [ $PERL_ISSUES -eq 0 ]; then
  echo "[+] No Perl dependency issues detected."
fi

echo "[*] Installing Rust toolchain..."
if command -v rustc >/dev/null 2>&1; then
  echo "[*] Rust is already installed: $(rustc --version)"
else
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  if [ $? -eq 0 ]; then
    echo "[+] Rust installed successfully."
  else
    echo "[!] Rust installation failed."
  fi
fi

echo
echo "=== Next Steps ==="
echo "1) If you installed Rust just now, restart your terminal or run:"
echo "     source ~/.cargo/env"
echo "2) If you have Perl dependency errors, please run:"
echo "     sudo apt-mark unhold perl perl-base libperl5.36"
echo "     sudo apt-get update"
echo "     sudo apt-get install -f"
echo "     sudo apt-get upgrade"
echo "3) You may want to clean unused packages:"
echo "     sudo apt autoremove"
echo
echo "[*] Installation script finished."
