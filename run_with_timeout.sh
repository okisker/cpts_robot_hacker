#!/bin/bash

TARGET=$1
OUTDIR="recon_$TARGET"
NMAP_OUT="$OUTDIR/nmap_full.txt"
REPORT_MD="$OUTDIR/report_${TARGET}.md"
REPORT_PDF="$OUTDIR/report_${TARGET}.pdf"
NUCLEI_OUT="$OUTDIR/nuclei_http.txt"
EXPLOIT_OUT="$OUTDIR/searchsploit_results.txt"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip>"
    exit 1
fi

# Tool check function
tools=(nmap httpx whatweb gobuster feroxbuster ffuf nikto nuclei hydra ncrack ssh-audit enum4linux smbclient crackmapexec smbmap snmpwalk onesixtyone ldapsearch smtp-user-enum rpcclient dig dnsenum showmount searchsploit pandoc)
missing_tools=()

for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "[!] The following tools are missing: ${missing_tools[*]}"
    echo "[*] Attempting to install missing tools via install_recon_tools.sh..."
    if [ -f ./install_recon_tools.sh ]; then
        bash ./install_recon_tools.sh
    else
        echo "[!] install_recon_tools.sh not found. Please install the missing tools manually."
        exit 1
    fi
fi

mkdir -p "$OUTDIR"

# Add run_with_timeout_skip function here
run_with_timeout_skip() {
    local cmd="$1"
    local timeout_duration="${2:-300}"  # default 300 seconds = 5 minutes
    echo "[*] Running (with timeout ${timeout_duration}s): $cmd"
   

    #trap 'echo -e "\n[!] Skipping current command due to Ctrl+C"; return 130' SIGINT

    timeout "${timeout_duration}s" bash -c "exec $cmd"
    local status=$?

    if [ $status -eq 124 ]; then
        echo "[!] Command timed out after ${timeout_duration}s and was killed."
    elif [ $status -eq 130 ]; then
    	echo "[!] Command skipped by user (Ctrl+C)."
    fi

    #trap - SIGINT
    return $status
}

# Hacker green
GREEN="\033[1;32m"
RESET="\033[0m"

# Function to print ASCII art
print_hacker_banner() {
    local word="$1"
    echo -e "${GREEN}"
    case "$word" in
        "NMAP")
            cat << "EOF"
  _  _ __  __   _   ___ 
 | \| |  \/  | /_\ | _ \
 | .` | |\/| |/ _ \|  _/
 |_|\_|_|  |_/_/ \_\_|  
EOF
            ;;
        "WHATWEB")
            cat << "EOF"
 __      ___  _   _ _______      _____ ___ 
 \ \    / / || | /_\_   _\ \    / / __| _ )
  \ \/\/ /| __ |/ _ \| |  \ \/\/ /| _|| _ \
   \_/\_/ |_||_/_/ \_\_|   \_/\_/ |___|___/	                           
EOF
            ;;
        "HTTPX")
            cat << "EOF"
  _  _ _____ _____ _____  __
 | || |_   _|_   _| _ \ \/ /
 | __ | | |   | | |  _/>  < 
 |_||_| |_|   |_| |_| /_/\_\     
EOF
            ;;
        "GOBUSTER")
            cat << "EOF"
   ___  ___  ___ _   _ ___ _____ ___ ___ 
  / __|/ _ \| _ ) | | / __|_   _| __| _ \
 | (_ | (_) | _ \ |_| \__ \ | | | _||   /
  \___|\___/|___/\___/|___/ |_| |___|_|_\                                                  
EOF
            ;;
        "NUCLEI")
            cat << "EOF"
  _  _ _   _  ___ _    ___ ___ 
 | \| | | | |/ __| |  | __|_ _|
 | .` | |_| | (__| |__| _| | | 
 |_|\_|\___/ \___|____|___|___|                     
EOF
            ;;
        "NIKTO")
            cat << "EOF"
  _  _ ___ _  _______ ___  
 | \| |_ _| |/ /_   _/ _ \ 
 | .` || || ' <  | || (_) |
 |_|\_|___|_|\_\ |_| \___/                 
EOF
            ;;
        "FEROXBUSTER")
            cat << "EOF"
  ___ ___ ___  _____  _____ _   _ ___ _____ ___ ___ 
 | __| __| _ \/ _ \ \/ / _ ) | | / __|_   _| __| _ \
 | _|| _||   / (_) >  <| _ \ |_| \__ \ | | | _||   /
 |_| |___|_|_\\___/_/\_\___/\___/|___/ |_| |___|_|_\                                
EOF
            ;;
        "FUFF")
            cat << "EOF"
  ___ _   _ ___ ___ 
 | __| | | | __| __|
 | _|| |_| | _|| _| 
 |_|  \___/|_| |_|  
EOF
            ;;
        *)
            echo "No ASCII art for: $word"
            ;;
    esac
    echo -e "${RESET}"
}

# NMAP
# TCP Full scan
print_hacker_banner "NMAP"
nmap -p- -T4 -oN "$OUTDIR/nmap_tcp.txt" "$TARGET"

# Extract TCP ports
TCP_PORTS=$(grep '/tcp' "$OUTDIR/nmap_tcp.txt" | cut -d '/' -f1 | paste -sd ',' -)

# TCP Service detection
nmap -sC -sV -p $TCP_PORTS -oN "$OUTDIR/nmap_tcp_services.txt" "$TARGET"

# UDP Top 100 scan (adjust as needed)
nmap -sU --top-ports 100 -T4 -oN "$OUTDIR/nmap_udp.txt" "$TARGET"

# Save combined nmap services output for later checks
cat "$OUTDIR/nmap_tcp_services.txt" "$OUTDIR/nmap_udp.txt" "$OUTDIR/nmap_tcp.txt"> "$OUTDIR/nmap_services.txt"

# Enumeration tools
function run_enum_tools {
    echo "[*] Checking services for enumeration..."

    # HTTP/HTTPS
    if grep -iE '^[0-9]+/(tcp|udp).*http' "$OUTDIR/nmap_services.txt" > /dev/null; then
        echo "[+] HTTP detected"
        echo "http://$TARGET" > urls.txt
        echo "https://$TARGET" >> urls.txt
	
	print_hacker_banner "WHATWEB"
        run_with_timeout_skip "whatweb -i urls.txt --log-verbose=\"$OUTDIR/whatweb.txt\""
        print_hacker_banner "HTTPX"
        run_with_timeout_skip "httpx http://$TARGET --follow-redirects --download \"$OUTDIR/httpx.txt\""
        print_hacker_banner "GOBUSTER"
        run_with_timeout_skip "gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o \"$OUTDIR/gobuster_http.txt\""
        run_with_timeout_skip "gobuster dir -u https://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o \"$OUTDIR/gobuster_https.txt\""
        print_hacker_banner "NUCLEI"
        run_with_timeout_skip "nuclei -list urls.txt -silent -o \"$NUCLEI_OUT\""
        print_hacker_banner "NIKTO"
        run_with_timeout_skip "nikto -h urls.txt -Format txt -output \"$OUTDIR/nikto.txt\" -Display V"
        print_hacker_banner "FEROXBUSTER"
        run_with_timeout_skip "feroxbuster -u http://$TARGET --scan-dir-listings -o \"$OUTDIR/feroxbuster.txt\""        
        run_with_timeout_skip "feroxbuster -u https://$TARGET --scan-dir-listings -o \"$OUTDIR/feroxbuster_https.txt\""
        #print_hacker_banner "FUFF"
        #run_with_timeout_skip "ffuf -u http://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -v -o \"$OUTDIR/ffuf.txt\" -c -fc 404,403"
        #run_with_timeout_skip "ffuf -u https://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -v -o \"$OUTDIR/ffufs.txt\" -c -fc 404,403"
        echo "HTTP scan done!"
    fi

    # FTP
    if grep -qi "ftp" "$OUTDIR/nmap_services.txt"; then
        echo "[+] FTP detected"
        echo -e "open $TARGET\nanonymous\nanonymous\nls\nbye" | ftp -n > "$OUTDIR/ftp_check.txt"
        run_with_timeout_skip "hydra -l anonymous -P /usr/share/wordlists/rockyou.txt -t 4 ftp://$TARGET -o \"$OUTDIR/ftp_hydra.txt\""
    fi

    # SMB
    if grep -qi "smb" "$OUTDIR/nmap_services.txt" || grep -qi "netbios" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SMB detected"
        run_with_timeout_skip "enum4linux -a \"$TARGET\" > \"$OUTDIR/enum4linux.txt\""
        run_with_timeout_skip "smbclient -L \\\\$TARGET -N > \"$OUTDIR/smbclient.txt\""
        run_with_timeout_skip "crackmapexec smb $TARGET --shares > \"$OUTDIR/cme_shares.txt\""
        run_with_timeout_skip "smbmap -H $TARGET > \"$OUTDIR/smbmap.txt\""
    fi

    # SSH
    if grep -qi "ssh" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SSH detected"
        run_with_timeout_skip "ssh -v -o BatchMode=yes -o ConnectTimeout=3 user@$TARGET 2>&1 | grep 'SSH- > \"$OUTDIR/ssh_version.txt\"'"
        run_with_timeout_skip "ssh-audit $TARGET > \"$OUTDIR/ssh_audit.txt\""
    fi

    # RDP
    if grep -qi "ms-wbt-server" "$OUTDIR/nmap_services.txt"; then
        echo "[+] RDP detected"
        run_with_timeout_skip "rdpscan $TARGET > \"$OUTDIR/rdpscan.txt\""
        run_with_timeout_skip "ncrack -p 3389 -U /usr/share/wordlists/usernames.txt -P /usr/share/wordlists/rockyou.txt $TARGET -oN \"$OUTDIR/rdp_ncrack.txt\""
    fi

    # SNMP
    if grep -qi "snmp" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SNMP detected"
        run_with_timeout_skip "snmpwalk -v1 -c public $TARGET > \"$OUTDIR/snmpwalk.txt\""
        run_with_timeout_skip "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $TARGET > \"$OUTDIR/onesixtyone.txt\""
    fi

    # LDAP
    if grep -qi "ldap" "$OUTDIR/nmap_services.txt"; then
        echo "[+] LDAP detected"
        run_with_timeout_skip "ldapsearch -x -H ldap://$TARGET -s base > \"$OUTDIR/ldapsearch.txt\""
    fi

    # SMTP
    if grep -qi "smtp" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SMTP detected"
        run_with_timeout_skip "smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t $TARGET > \"$OUTDIR/smtp_enum.txt\""
    fi

    # RPC
    if grep -qi "rpcbind" "$OUTDIR/nmap_services.txt"; then
        echo "[+] RPC detected"
        run_with_timeout_skip "rpcclient -U \"\" $TARGET -c enumdomusers > \"$OUTDIR/rpc_enum.txt\""
    fi

    # DNS
    if grep -qi "domain" "$OUTDIR/nmap_services.txt"; then
        echo "[+] DNS detected"
        run_with_timeout_skip "dig axfr @$TARGET example.com > \"$OUTDIR/dns_zone.txt\""
        run_with_timeout_skip "dnsenum $TARGET > \"$OUTDIR/dnsenum.txt\""
    fi

    # NFS
    if grep -qi "nfs" "$OUTDIR/nmap_services.txt"; then
        echo "[+] NFS detected"
        run_with_timeout_skip "showmount -e $TARGET > \"$OUTDIR/nfs_exports.txt\""
    fi
}

# SearchSploit integration
function run_searchsploit {
    echo "[*] Running SearchSploit on service versions..."
    > "$EXPLOIT_OUT"

    while IFS= read -r line; do
        if [[ "$line" =~ [0-9]+/tcp ]]; then
            service_line=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | xargs)
            if [ -n "$service_line" ]; then
                echo "[+] Searching: $service_line"
                echo "### $service_line" >> "$EXPLOIT_OUT"
                run_with_timeout_skip "searchsploit \"$service_line\"" 60
                echo >> "$EXPLOIT_OUT"
            fi
        fi
    done < "$OUTDIR/nmap_services.txt"
}

# Run all tools
run_enum_tools
run_searchsploit

# Report generation
{
echo "# Recon Report for $TARGET"
echo "_Generated: $TIMESTAMP_"
echo

for file in "$OUTDIR"/*.txt; do
    echo "## $(basename "$file")"
    echo '```'
    cat "$file"
    echo '```'
    echo

done
} > "$REPORT_MD"

if command -v pandoc &> /dev/null; then
    pandoc "$REPORT_MD" -o "$REPORT_PDF"
    echo "[+] PDF report saved to: $REPORT_PDF"
else
    echo "[!] pandoc not found — skipping PDF generation"
fi

echo "[*] Done. All results saved in $OUTDIR/"

