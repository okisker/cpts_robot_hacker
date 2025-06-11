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

# Tool check function (unchanged)
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

# NMAP
# TCP Full scan
nmap -p- -T4 -oN "$OUTDIR/nmap_tcp.txt" "$TARGET"

# Improved port extraction: only open TCP ports for service detection
TCP_PORTS=$(grep '/tcp open' "$OUTDIR/nmap_tcp.txt" | cut -d '/' -f1 | paste -sd ',' -)

if [ -z "$TCP_PORTS" ]; then
    echo "[!] No open TCP ports found. Skipping TCP service detection."
else
    # TCP Service detection
    nmap -sC -sV -p $TCP_PORTS -oN "$OUTDIR/nmap_tcp_services.txt" "$TARGET"
fi

# UDP Top 100 scan (unchanged)
nmap -sU --top-ports 100 -T4 -oN "$OUTDIR/nmap_udp.txt" "$TARGET"

# Enumeration tools
function run_enum_tools {
    echo "[*] Checking services for enumeration..."

    # HTTP/HTTPS detection from service scan output file or fallback to nmap tcp scan
    SERVICE_FILE="$OUTDIR/nmap_tcp_services.txt"
    if [ ! -f "$SERVICE_FILE" ]; then
        SERVICE_FILE="$OUTDIR/nmap_tcp.txt"
    fi

    if grep -qiE "http|https" "$SERVICE_FILE"; then
        echo "[+] HTTP detected"

        # Prepare URLs file
        echo "http://$TARGET" > urls.txt
        echo "https://$TARGET" >> urls.txt

        # Parallelize HTTP enumeration tools
        whatweb -i urls.txt --log-verbose="$OUTDIR/whatweb.txt" &
        httpx -l urls.txt -status-code -tech-detect -title -web-server -favicon -o "$OUTDIR/httpx.txt" &
        gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o "$OUTDIR/gobuster_http.txt" &
        gobuster dir -u https://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o "$OUTDIR/gobuster_https.txt" &
        nuclei -list urls.txt -silent -o "$NUCLEI_OUT" &
        nikto -h urls.txt -output "$OUTDIR/nikto.txt" -Format txt &
        feroxbuster -u http://$TARGET -o "$OUTDIR/feroxbuster.txt" &
        ffuf -u http://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -o "$OUTDIR/ffuf.txt" -c -fc 404,403 &
        ffuf -u https://$TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -o "$OUTDIR/ffufs.txt" -c -fc 404,403 &

        wait  # Wait for all parallel HTTP enumeration tools to finish
    fi

    # FTP detection (unchanged)
    if grep -qi "ftp" "$SERVICE_FILE"; then
        echo "[+] FTP detected"
        echo -e "open $TARGET\nanonymous\nanonymous\nls\nbye" | ftp -n > "$OUTDIR/ftp_check.txt"
        hydra -l anonymous -P /usr/share/wordlists/rockyou.txt -t 4 ftp://$TARGET -o "$OUTDIR/ftp_hydra.txt"
    fi

    # SMB detection (unchanged)
    if grep -qi "smb" "$SERVICE_FILE" || grep -qi "netbios" "$SERVICE_FILE"; then
        echo "[+] SMB detected"
        enum4linux -a "$TARGET" > "$OUTDIR/enum4linux.txt"
        smbclient -L \\$TARGET -N > "$OUTDIR/smbclient.txt"
        crackmapexec smb $TARGET --shares > "$OUTDIR/cme_shares.txt"
        smbmap -H $TARGET > "$OUTDIR/smbmap.txt"
    fi

    # SSH detection (unchanged)
    if grep -qi "ssh" "$SERVICE_FILE"; then
        echo "[+] SSH detected"
        ssh -v -o BatchMode=yes -o ConnectTimeout=3 user@$TARGET 2>&1 | grep "SSH-" > "$OUTDIR/ssh_version.txt"
        ssh-audit $TARGET > "$OUTDIR/ssh_audit.txt"
    fi

    # RDP detection (unchanged)
    if grep -qi "ms-wbt-server" "$SERVICE_FILE"; then
        echo "[+] RDP detected"
        rdpscan $TARGET > "$OUTDIR/rdpscan.txt"
        ncrack -p 3389 -U /usr/share/wordlists/usernames.txt -P /usr/share/wordlists/rockyou.txt $TARGET -oN "$OUTDIR/rdp_ncrack.txt"
    fi

    # SNMP detection (unchanged)
    if grep -qi "snmp" "$SERVICE_FILE"; then
        echo "[+] SNMP detected"
        snmpwalk -v1 -c public $TARGET > "$OUTDIR/snmpwalk.txt"
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $TARGET > "$OUTDIR/onesixtyone.txt"
    fi

    # LDAP detection (unchanged)
    if grep -qi "ldap" "$SERVICE_FILE"; then
        echo "[+] LDAP detected"
        ldapsearch -x -H ldap://$TARGET -s base > "$OUTDIR/ldapsearch.txt"
    fi

    # SMTP detection (unchanged)
    if grep -qi "smtp" "$SERVICE_FILE"; then
        echo "[+] SMTP detected"
        smtp-user-enum -M VRFY -U /usr/share/wordlists/usernames.txt -t $TARGET > "$OUTDIR/smtp_enum.txt"
    fi

    # RPC detection (unchanged)
    if grep -qi "rpcbind" "$SERVICE_FILE"; then
        echo "[+] RPC detected"
        rpcclient -U "" $TARGET -c enumdomusers > "$OUTDIR/rpc_enum.txt"
    fi

    # DNS detection (unchanged)
    if grep -qi "domain" "$SERVICE_FILE"; then
        echo "[+] DNS detected"
        dig axfr @$TARGET example.com > "$OUTDIR/dns_zone.txt"
        dnsenum $TARGET > "$OUTDIR/dnsenum.txt"
    fi

    # NFS detection (unchanged)
    if grep -qi "nfs" "$SERVICE_FILE"; then
        echo "[+] NFS detected"
        showmount -e $TARGET > "$OUTDIR/nfs_exports.txt"
    fi
}

# (rest of your script unchanged)

# Run all tools
run_enum_tools
run_searchsploit

# Report generation unchanged...

