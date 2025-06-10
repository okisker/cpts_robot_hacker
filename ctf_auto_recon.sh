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

# Run full Nmap scan
echo "[*] Running full TCP Nmap scan on $TARGET..."
nmap -p- -T4 -oN "$NMAP_OUT" "$TARGET"

# Extract open ports
PORTS=$(grep ^[0-9] "$NMAP_OUT" | cut -d '/' -f1 | paste -sd "," -)

# Run service version detection
nmap -sC -sV -p $PORTS -oN "$OUTDIR/nmap_services.txt" "$TARGET"

# Enumeration tools
function run_enum_tools {
    echo "[*] Checking services for enumeration..."

    # HTTP/HTTPS
    if grep -qiE "http|https" "$OUTDIR/nmap_services.txt"; then
        echo "[+] HTTP detected"
        whatweb http://$TARGET > "$OUTDIR/whatweb.txt"
        httpx -u http://$TARGET -status-code -tech-detect -title -web-server -favicon -tls -o "$OUTDIR/httpx.txt"
        gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o "$OUTDIR/gobuster_http.txt"
        nuclei -u http://$TARGET -silent -o "$NUCLEI_OUT"
        nikto -h http://$TARGET -output "$OUTDIR/nikto.txt"
        feroxbuster -u http://$TARGET -o "$OUTDIR/feroxbuster.txt"
        ffuf -u http://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -o "$OUTDIR/ffuf.txt"
    fi

    # FTP
    if grep -qi "ftp" "$OUTDIR/nmap_services.txt"; then
        echo "[+] FTP detected"
        echo -e "open $TARGET\nanonymous\nanonymous\nls\nbye" | ftp -n > "$OUTDIR/ftp_check.txt"
        hydra -l anonymous -P /usr/share/wordlists/rockyou.txt ftp://$TARGET -o "$OUTDIR/ftp_hydra.txt"
    fi

    # SMB
    if grep -qi "smb" "$OUTDIR/nmap_services.txt" || grep -qi "netbios" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SMB detected"
        enum4linux -a "$TARGET" > "$OUTDIR/enum4linux.txt"
        smbclient -L \\$TARGET -N > "$OUTDIR/smbclient.txt"
        crackmapexec smb $TARGET --shares > "$OUTDIR/cme_shares.txt"
        smbmap -H $TARGET > "$OUTDIR/smbmap.txt"
    fi

    # SSH
    if grep -qi "ssh" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SSH detected"
        ssh -v -o BatchMode=yes -o ConnectTimeout=3 user@$TARGET 2>&1 | grep "SSH-" > "$OUTDIR/ssh_version.txt"
        ssh-audit $TARGET > "$OUTDIR/ssh_audit.txt"
    fi

    # RDP
    if grep -qi "ms-wbt-server" "$OUTDIR/nmap_services.txt"; then
        echo "[+] RDP detected"
        rdpscan $TARGET > "$OUTDIR/rdpscan.txt"
        ncrack -p 3389 -U /usr/share/wordlists/usernames.txt -P /usr/share/wordlists/rockyou.txt $TARGET -oN "$OUTDIR/rdp_ncrack.txt"
    fi

    # SNMP
    if grep -qi "snmp" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SNMP detected"
        snmpwalk -v1 -c public $TARGET > "$OUTDIR/snmpwalk.txt"
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $TARGET > "$OUTDIR/onesixtyone.txt"
    fi

    # LDAP
    if grep -qi "ldap" "$OUTDIR/nmap_services.txt"; then
        echo "[+] LDAP detected"
        ldapsearch -x -H ldap://$TARGET -s base > "$OUTDIR/ldapsearch.txt"
    fi

    # SMTP
    if grep -qi "smtp" "$OUTDIR/nmap_services.txt"; then
        echo "[+] SMTP detected"
        smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t $TARGET > "$OUTDIR/smtp_enum.txt"
    fi

    # RPC
    if grep -qi "rpcbind" "$OUTDIR/nmap_services.txt"; then
        echo "[+] RPC detected"
        rpcclient -U "" $TARGET -c enumdomusers > "$OUTDIR/rpc_enum.txt"
    fi

    # DNS
    if grep -qi "domain" "$OUTDIR/nmap_services.txt"; then
        echo "[+] DNS detected"
        dig axfr @$TARGET example.com > "$OUTDIR/dns_zone.txt"
        dnsenum $TARGET > "$OUTDIR/dnsenum.txt"
    fi

    # NFS
    if grep -qi "nfs" "$OUTDIR/nmap_services.txt"; then
        echo "[+] NFS detected"
        showmount -e $TARGET > "$OUTDIR/nfs_exports.txt"
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
                searchsploit "$service_line" >> "$EXPLOIT_OUT"
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

# Suggested installation command:
# bash install_recon_tools.sh
