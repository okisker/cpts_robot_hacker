#!/bin/bash

# Colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"

echo -e "${BLUE}[*] Updating package lists...${RESET}"
if sudo apt-get -qq update > /dev/null; then
  echo -e "${GREEN}[+] Package lists updated.${RESET}"
else
  echo -e "${RED}[!] Failed to update package lists.${RESET}"
fi

echo -e "${BLUE}[*] Upgrading installed packages...${RESET}"
if sudo apt-get -qq upgrade -y > /dev/null; then
  echo -e "${GREEN}[+] Packages upgraded successfully.${RESET}"
else
  echo -e "${RED}[!] Package upgrade failed.${RESET}"
fi

echo -e "${BLUE}[*] Removing unused packages...${RESET}"
if sudo apt-get -qq autoremove -y > /dev/null; then
  echo -e "${GREEN}[+] Unused packages removed.${RESET}"
else
  echo -e "${RED}[!] Failed to remove unused packages.${RESET}"
fi

echo -e "${BLUE}[*] Installing required tools...${RESET}"
REQUIRED_PACKAGES=(git nmap whatweb gobuster ffuf hydra ncrack smbclient smbmap snmp ldap-utils rpcbind dnsutils nfs-common ftp gcc make python3-pip nuclei onesixtyone pandoc polenum ssh-audit)

FAILED_PACKAGES=()
for pkg in "${REQUIRED_PACKAGES[@]}"; do
  if dpkg -s "$pkg" &>/dev/null; then
    echo -e "${YELLOW}[*] $pkg is already installed.${RESET}"
  else
    if sudo apt-get install -y "$pkg" > /dev/null; then
      echo -e "${GREEN}[+] Installed $pkg successfully.${RESET}"
    else
      echo -e "${RED}[!] Failed to install $pkg.${RESET}"
      FAILED_PACKAGES+=("$pkg")
    fi
  fi
done

# Extra git verification
if ! sudo command -v git &>/dev/null; then
  echo -e "${RED}[!] 'git' is missing from sudo PATH. Attempting to reinstall...${RESET}"
  if sudo apt-get install -y --reinstall git > /dev/null; then
    echo -e "${GREEN}[+] Reinstalled git successfully.${RESET}"
  else
    echo -e "${RED}[!] Reinstallation of git failed. Check PATH or manually reinstall git.${RESET}"
  fi
fi

if [ ${#FAILED_PACKAGES[@]} -eq 0 ]; then
  echo -e "${GREEN}[+] All required APT packages installed successfully.${RESET}"
else
  echo -e "${RED}[!] Some packages failed: ${FAILED_PACKAGES[*]}${RESET}"
fi

# Git-based tools install
echo -e "${BLUE}[*] Checking and installing additional tools (git-based)...${RESET}"

TOOLS_DIR=~/recon-tools
mkdir -p "$TOOLS_DIR"

# 1. Nikto
echo -e "${BLUE}[*] Installing nikto from source...${RESET}"
if git clone --quiet https://github.com/sullo/nikto.git "$TOOLS_DIR/nikto"; then
  chmod +x "$TOOLS_DIR/nikto/nikto.pl"
  echo -e "${GREEN}[+] Nikto installed to $TOOLS_DIR/nikto${RESET}"
else
  echo -e "${RED}[!] Failed to clone/install nikto.${RESET}"
fi

# 2. Enum4linux
echo -e "${BLUE}[*] Installing enum4linux...${RESET}"
if git clone --quiet https://github.com/CiscoCXSecurity/enum4linux.git "$TOOLS_DIR/enum4linux"; then
  chmod +x "$TOOLS_DIR/enum4linux/enum4linux.pl"
  echo -e "${GREEN}[+] Enum4linux installed to $TOOLS_DIR/enum4linux${RESET}"
else
  echo -e "${RED}[!] Failed to clone/install enum4linux.${RESET}"
fi

# 3. SMTP-user-enum
echo -e "${BLUE}[*] Installing smtp-user-enum...${RESET}"
if git clone --quiet https://github.com/pentestmonkey/smtp-user-enum.git "$TOOLS_DIR/smtp-user-enum"; then
  chmod +x "$TOOLS_DIR/smtp-user-enum/smtp-user-enum.pl"
  echo -e "${GREEN}[+] smtp-user-enum installed to $TOOLS_DIR/smtp-user-enum${RESET}"
else
  echo -e "${RED}[!] Failed to clone/compile smtp-user-enum.${RESET}"
fi

# 4. DNSenum
echo -e "${BLUE}[*] Installing dnsenum...${RESET}"
if git clone --quiet https://github.com/fwaeytens/dnsenum.git "$TOOLS_DIR/dnsenum"; then
  chmod +x "$TOOLS_DIR/dnsenum/dnsenum.pl"
  echo -e "${GREEN}[+] dnsenum installed to $TOOLS_DIR/dnsenum${RESET}"
else
  echo -e "${RED}[!] Failed to clone/install dnsenum.${RESET}"
fi

# Perl Conflict Check
echo -e "${BLUE}[*] Checking for Perl dependency issues...${RESET}"
if sudo apt-get install -f -y > /dev/null; then
  echo -e "${GREEN}[+] No broken dependencies found.${RESET}"
else
  echo -e "${RED}[!] Fix broken dependencies failed.${RESET}"
fi

if dpkg -s perl-base 2>/dev/null | grep -q "Version: 5.36.0-7+deb12u2" && \
   dpkg -s perl 2>/dev/null | grep -q "Depends: perl-base (= 5.36.0-7+deb12u1)"; then
  echo -e "${RED}[!] Perl package dependency conflict detected:${RESET}"
  echo "    - perl-base version: 5.36.0-7+deb12u2 installed"
  echo "    - perl requires version: 5.36.0-7+deb12u1"
  echo "    Please run these commands to fix:"
  echo "      sudo apt-mark unhold perl perl-base libperl5.36"
  echo "      sudo apt-get update"
  echo "      sudo apt-get install -f"
  echo "      sudo apt-get upgrade"
else
  echo -e "${GREEN}[+] No Perl dependency issues detected.${RESET}"
fi

# Rust Install
echo -e "${BLUE}[*] Installing Rust toolchain...${RESET}"
if command -v rustc >/dev/null 2>&1; then
  echo -e "${YELLOW}[*] Rust is already installed: $(rustc --version)${RESET}"
else
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Rust installed successfully.${RESET}"
  else
    echo -e "${RED}[!] Rust installation failed.${RESET}"
  fi
fi

echo
echo -e "${BLUE}=== Next Steps ===${RESET}"
echo -e "${YELLOW}1) If you installed Rust just now, restart your terminal or run:${RESET}"
echo "     source ~/.cargo/env"
echo -e "${YELLOW}2) If you have Perl dependency errors, please run:${RESET}"
echo "     sudo apt-mark unhold perl perl-base libperl5.36"
echo "     sudo apt-get update"
echo "     sudo apt-get install -f"
echo "     sudo apt-get upgrade"
echo -e "${YELLOW}3) You may want to clean unused packages:${RESET}"
echo "     sudo apt autoremove"
echo
echo -e "${GREEN}[*] Installation script finished.${RESET}"
