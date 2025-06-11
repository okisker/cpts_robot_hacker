notes to self:
- change crackmapexec to netexec
- add wordpress
-   - sudo apt install wpscan
-   - wpscan --url https://targetsite.com --enumerate vp,vt,cb,dbe,u
nikto produced no results and didn't look to be running

# Hacker green
GREEN="\033[1;32m"
RESET="\033[0m"

# Function to print specific ASCII art
print_hacker_banner() {
  local word="$1"

  echo -e "${GREEN}"

  case "$word" in
    "ACCESS")
cat << "EOF"
    _    ____ ____ ____ ____ ____ 
   / \  |  _ \ ___|  _ \ ___|  _ \
  / _ \ | | | / __| | | / __| | | |
 / ___ \| |_| \__ \ |_| \__ \ |_| |
/_/   \_\____/|___/____/|___/____/ 
EOF
    ;;
    "GRANTED")
cat << "EOF"
   ____ ____    _    _   _ _____ _____ ____  
  / ___|  _ \  / \  | \ | | ____| ____|  _ \ 
 | |  _| | | |/ _ \ |  \| |  _| |  _| | |_) |
 | |_| | |_| / ___ \| |\  | |___| |___|  _ < 
  \____|____/_/   \_\_| \_|_____|_____|_| \_\
EOF
    ;;
    "DENIED")
cat << "EOF"
  ____  _____ _   _ _____ ___ ____  
 |  _ \| ____| \ | | ____|_ _|  _ \ 
 | | | |  _| |  \| |  _|  | || | | |
 | |_| | |___| |\  | |___ | || |_| |
 |____/|_____|_| \_|_____|___|____/ 
EOF
    ;;
    *)
      echo "No ASCII art defined for: $word"
    ;;
  esac

  echo -e "${RESET}"
}

# Example usage
print_hacker_banner "ACCESS"
print_hacker_banner "GRANTED"
sleep 1
print_hacker_banner "DENIED"
