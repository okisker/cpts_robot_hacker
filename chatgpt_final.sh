#!/bin/bash

TARGET=$1
OUTDIR="recon_$TARGET"
NMAP_OUT="$OUTDIR/nmap_full.txt"
REPORT_MD="$OUTDIR/report_${TARGET}.md"
REPORT_PDF="$OUTDIR/report_${TARGET}.pdf"
NUCLEI_OUT="$OUTDIR/nuclei_http.txt"
EXPLOIT_OUT="$OUTDIR/searchsploit_results.txt"
METASPLOIT_OUT="$OUTDIR/metasploit_scan.txt"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip>"
    exit 1
fi

# Tool check function (unchanged)
tools=(nmap httpx whatweb gobuster feroxbuster ffuf nikto nuclei hydra ncrack ssh-audit enum4linux smbclient crackmapexec smbmap snmpwalk onesixtyone ldapsearch smtp-user-enum rpcclient dig dnsenum showmount searchsploit pandoc msfconsole)
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

# Add run_with_timeout_skip function
run_with_timeout_skip() {
    local cmd="$1"
    local timeout_duration="${2:-300}"  # default 300 seconds = 5 minutes

    trap 'echo -e "\n[!] Skipping current command due to Ctrl+C"; return 130' SIGINT

    timeout "${timeout_duration}s" bash -c "$cmd"
    local status=$?

    if [ $status -eq 124 ]; then
        echo "[!] Command timed out after ${timeout_duration}s and was killed."
    fi

    trap - SIGINT
    return $status
}

# NMAP
# TCP Full scan
run_with_timeout_skip "nmap -p- -T4 -oN \"$OUTDIR/nmap_tcp.txt\" \"$TARGET\""

# Extract open TCP ports
TCP_PORTS=$(grep '/tcp open' "$OUTDIR/nmap_tcp.txt" | cut -d '/' -f1 | paste -sd ',' -)

if [ -z "$TCP_PORTS" ]; then
    echo "[!] No open TCP ports found. Skipping TCP service detection."
else
    run_with_timeout_skip "nmap -sC -sV -p $TCP_PORTS -oN \"$OUTDIR/nmap_tcp_services.txt\" \"$TARGET\""
fi

# UDP Top 100 scan
run_with_timeout_skip "nmap -sU --top-ports 100 -T4 -oN \"$OUTDIR/nmap_udp.txt\" \"$TARGET\""

# Save combined nmap services output for later checks
cat "$OUTDIR/nmap_tcp_services.txt" "$OUTDIR/nmap_udp.txt" > "$OUTDIR/nmap_services.txt"

# Enumeration tools function (unchanged, but using run_with_timeout_skip where needed)
function run_enum_tools {
    echo "[*] Checking services for enumeration..."

    SERVICE_FILE="$OUTDIR/nmap_tcp_services.txt"
    if [ ! -f "$SERVICE_FILE" ]; then
        SERVICE_FILE="$OUTDIR/nmap_tcp.txt"
    fi

    if grep -qiE "http|https" "$SERVICE_FILE"; then
        echo "[+] HTTP detected"
        echo "http://$TARGET" > urls.txt
        echo "https://$TARGET" >> urls.txt

        run_with_timeout_skip "whatweb -i urls.txt --log-verbose=\"$OUTDIR/whatweb.txt\"" 300
        run_with_timeout_skip "httpx -l urls.txt -status-code -tech-detect -title -web-server -favicon -o \"$OUTDIR/httpx.txt\"" 300
        run_with_timeout_skip "gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o \"$OUTDIR/gobuster_http.txt\"" 300
        run_with_timeout_skip "gobuster dir -u https://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o \"$OUTDIR/gobuster_https.txt\"" 300
        run_with_timeout_skip "nuclei -list urls.txt -silent -o \"$NUCLEI_OUT\"" 300
        run_with_timeout_skip "nikto -h urls.txt -output \"$OUTDIR/nikto.txt\" -Format txt" 300
        run_with_timeout_skip "feroxbuster -u http://$TARGET -o \"$OUTDIR/feroxbuster.txt\"" 300
        run_with_timeout_skip "ffuf -u http://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -o \"$OUTDIR/ffuf.txt\" -c -fc 404,403" 300
        run_with_timeout_skip "ffuf -u https://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -o \"$OUTDIR/ffufs.txt\" -c -fc 404,403" 300
    fi

    if grep -qi "ftp" "$SERVICE_FILE"; then
        echo "[+] FTP detected"
        echo -e "open $TARGET\nanonymous\nanonymous\nls\nbye" | ftp -n > "$OUTDIR/ftp_check.txt"
        run_with_timeout_skip "hydra -l anonymous -P /usr/share/wordlists/rockyou.txt -t 4 ftp://$TARGET -o \"$OUTDIR/ftp_hydra.txt\"" 300
    fi

    if grep -qi "smb" "$SERVICE_FILE" || grep -qi "netbios" "$SERVICE_FILE"; then
        echo "[+] SMB detected"
        run_with_timeout_skip "enum4linux -a \"$TARGET\" > \"$OUTDIR/enum4linux.txt\"" 300
        run_with_timeout_skip "smbclient -L \\\\$TARGET -N > \"$OUTDIR/smbclient.txt\"" 300
        run_with_timeout_skip "crackmapexec smb $TARGET --shares > \"$OUTDIR/cme_shares.txt\"" 300
        run_with_timeout_skip "smbmap -H $TARGET > \"$OUTDIR/smbmap.txt\"" 300
    fi

    if grep -qi "ssh" "$SERVICE_FILE"; then
        echo "[+] SSH detected"
        run_with_timeout_skip "ssh -v -o BatchMode=yes -o ConnectTimeout=3 user@$TARGET 2>&1 | grep 'SSH- > \"$OUTDIR/ssh_version.txt\"'" 120
        run_with_timeout_skip "ssh-audit $TARGET > \"$OUTDIR/ssh_audit.txt\"" 300
    fi

    if grep -qi "ms-wbt-server" "$SERVICE_FILE"; then
        echo "[+] RDP detected"
        run_with_timeout_skip "rdpscan $TARGET > \"$OUTDIR/rdpscan.txt\"" 300
        run_with_timeout_skip "ncrack -p 3389 -U /usr/share/wordlists/usernames.txt -P /usr/share/wordlists/rockyou.txt $TARGET -oN \"$OUTDIR/rdp_ncrack.txt\"" 300
    fi

    if grep -qi "snmp" "$SERVICE_FILE"; then
        echo "[+] SNMP detected"
        run_with_timeout_skip "snmpwalk -v1 -c public $TARGET > \"$OUTDIR/snmpwalk.txt\"" 300
        run_with_timeout_skip "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $TARGET > \"$OUTDIR/onesixtyone.txt\"" 300
    fi

    if grep -qi "ldap" "$SERVICE_FILE"; then
        echo "[+] LDAP detected"
        run_with_timeout_skip "ldapsearch -x -H ldap://$TARGET -s base > \"$OUTDIR/ldapsearch.txt\"" 300
    fi

    if grep -qi "smtp" "$SERVICE_FILE"; then
        echo "[+] SMTP detected"
        run_with_timeout_skip "smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t $TARGET > \"$OUTDIR/smtp_enum.txt\"" 300
    fi

    if grep -qi "rpcbind" "$SERVICE_FILE"; then
        echo "[+] RPC detected"
        run_with_timeout_skip "rpcclient -U \"\" $TARGET -c enumdomusers > \"$OUTDIR/rpc_enum.txt\"" 300
    fi

    if grep -qi "domain" "$SERVICE_FILE"; then
        echo "[+] DNS detected"
        run_with_timeout_skip "dig axfr @$TARGET example.com > \"$OUTDIR/dns_zone.txt\"" 300
        run_with_timeout_skip "dnsenum $TARGET > \"$OUTDIR/dnsenum.txt\"" 300
    fi

    if grep -qi "nfs" "$SERVICE_FILE"; then
        echo "[+] NFS detected"
        run_with_timeout_skip "showmount -e $TARGET > \"$OUTDIR/nfs_exports.txt\"" 300
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
                run_with_timeout_skip "searchsploit \"$service_line\" >> \"$EXPLOIT_OUT\"" 60
                echo >> "$EXPLOIT_OUT"
            fi
        fi
    done < "$OUTDIR/nmap_services.txt"
}

# Metasploit scanning function
function run_metasploit_scan {
    echo "[*] Running Metasploit auxiliary scanner..."

    # Create a temporary resource script for msfconsole
    local msf_rc="$OUTDIR/msf_scan.rc"

    cat > "$msf_rc" << EOF
use auxiliary/scanner/portscan/tcp
set RHOSTS $TARGET
set THREADS 10
run
exit
EOF

    # Run msfconsole with the resource script and timeout
    run_with_timeout_skip "msfconsole -q -r \"$msf_rc\" > \"$METASPLOIT_OUT\" 2>&1" 600

    rm -f "$msf_rc"
}

# Run all tools
run_enum_tools
run_searchsploit
run_metasploit_scan

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

# Suggested installation command:
# bash install_recon_tools.sh
