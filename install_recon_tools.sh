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
# openvas  # Commented out for now

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

# Metasploit Framework install (from apt or Rapid7 repo)
echo -e "${BLUE}[*] Checking for Metasploit Framework...${RESET}"
if command -v msfconsole >/dev/null 2>&1; then
  echo -e "${YELLOW}[*] Metasploit is already installed: $(msfconsole --version 2>&1 | head -1)${RESET}"
else
  echo -e "${BLUE}[*] Installing Metasploit Framework...${RESET}"
  if sudo apt-get install -y metasploit-framework > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Metasploit Framework installed via apt.${RESET}"
  else
    echo -e "${YELLOW}[*] apt install failed, attempting Rapid7 installer...${RESET}"
    curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/scripts/msfupdate.sh -o msfinstall.sh
    chmod +x msfinstall.sh
    sudo ./msfinstall.sh
    rm msfinstall.sh
    if command -v msfconsole >/dev/null 2>&1; then
      echo -e "${GREEN}[+] Metasploit Framework installed successfully via Rapid7 installer.${RESET}"
    else
      echo -e "${RED}[!] Metasploit installation failed.${RESET}"
      FAILED_PACKAGES+=("metasploit-framework")
    fi
  fi
fi

# BloodHound install - COMMENTED OUT for future integration
: '
echo -e "${BLUE}[*] Installing BloodHound...${RESET}"
TOOLS_DIR=~/recon-tools
mkdir -p "$TOOLS_DIR"
if [ -d "$TOOLS_DIR/BloodHound" ]; then
  echo -e "${YELLOW}[*] BloodHound repo already cloned.${RESET}"
else
  if git clone --quiet https://github.com/BloodHoundAD/BloodHound.git "$TOOLS_DIR/BloodHound"; then
    echo -e "${GREEN}[+] Cloned BloodHound to $TOOLS_DIR/BloodHound${RESET}"
  else
    echo -e "${RED}[!] Failed to clone BloodHound.${RESET}"
    FAILED_PACKAGES+=("BloodHound")
  fi
fi

echo -e "${BLUE}[*] Installing Node.js and npm for BloodHound...${RESET}"
if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  echo -e "${YELLOW}[*] Node.js and npm already installed.${RESET}"
else
  curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
  if sudo apt-get install -y nodejs > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Node.js and npm installed successfully.${RESET}"
  else
    echo -e "${RED}[!] Failed to install Node.js and npm.${RESET}"
    FAILED_PACKAGES+=("nodejs/npm for BloodHound")
  fi
fi

echo -e "${BLUE}[*] Building BloodHound...${RESET}"
cd "$TOOLS_DIR/BloodHound" || exit
if npm install > /dev/null 2>&1 && npm run build > /dev/null 2>&1; then
  echo -e "${GREEN}[+] BloodHound built successfully.${RESET}"
else
  echo -e "${RED}[!] Failed to build BloodHound.${RESET}"
  FAILED_PACKAGES+=("BloodHound build")
fi
cd - > /dev/null || exit
'

# 5. OpenVAS (commented out for now)
# echo -e "${BLUE}[*] Installing OpenVAS...${RESET}"
# if sudo apt-get install -y gvm > /dev/null; then
#   echo -e "${GREEN}[+] OpenVAS installed.${RESET}"
#   sudo gvm-setup && sudo gvm-check-setup
# else
#   echo -e "${RED}[!] Failed to install OpenVAS.${RESET}"
# fi

# 6. BloodHound (commented out for now)
# echo -e "${BLUE}[*] Installing BloodHound...${RESET}"
# if sudo apt-get install -y bloodhound > /dev/null; then
#   echo -e "${GREEN}[+] BloodHound installed.${RESET}"
# else
#   echo -e "${RED}[!] Failed to install BloodHound.${RESET}"
# fi

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

# Rust Install (unchanged)
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
