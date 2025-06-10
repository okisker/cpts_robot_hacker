#!/usr/bin/env python3
import os
import subprocess
import sys
import re
from datetime import datetime

TARGET = sys.argv[1] if len(sys.argv) > 1 else None
if not TARGET:
    print("Usage: python3 recon.py <target-ip>")
    sys.exit(1)

OUTDIR = f"recon_{TARGET}"
NMAP_OUT = os.path.join(OUTDIR, "nmap_full.txt")
SERVICES_OUT = os.path.join(OUTDIR, "nmap_services.txt")
REPORT_MD = os.path.join(OUTDIR, f"report_{TARGET}.md")
REPORT_PDF = os.path.join(OUTDIR, f"report_{TARGET}.pdf")
EXPLOIT_OUT = os.path.join(OUTDIR, "searchsploit_results.txt")
TIMESTAMP = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

TOOLS = [
    "nmap", "httpx", "whatweb", "gobuster", "feroxbuster", "ffuf", "nikto", "nuclei", "hydra",
    "ncrack", "ssh-audit", "enum4linux", "smbclient", "crackmapexec", "smbmap", "snmpwalk",
    "onesixtyone", "ldapsearch", "smtp-user-enum", "rpcclient", "dig", "dnsenum", "showmount",
    "searchsploit", "pandoc"
]

def check_tools():
    missing = [tool for tool in TOOLS if not shutil.which(tool)]
    if missing:
        print(f"[!] Missing tools: {', '.join(missing)}")
        if os.path.exists("install_recon_tools.sh"):
            subprocess.run(["bash", "install_recon_tools.sh"])
        else:
            print("[!] install_recon_tools.sh not found. Please install manually.")
            sys.exit(1)

import shutil
os.makedirs(OUTDIR, exist_ok=True)

print(f"[*] Running full TCP Nmap scan on {TARGET}...")
subprocess.run(["nmap", "-p-", "-T4", "-oN", NMAP_OUT, TARGET])

with open(NMAP_OUT) as f:
    ports = ",".join(re.findall(r"^(\d+)/tcp", f.read(), re.M))

print("[*] Running Nmap service version detection...")
subprocess.run(["nmap", "-sC", "-sV", "-p", ports, "-oN", SERVICES_OUT, TARGET])

def run_cmd(cmd, outfile):
    with open(outfile, "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)

def run_enum():
    with open(SERVICES_OUT) as f:
        services = f.read().lower()

    if "http" in services:
        run_cmd(["whatweb", f"http://{TARGET}"], os.path.join(OUTDIR, "whatweb.txt"))
        run_cmd(["httpx", "-u", f"http://{TARGET}", "-status-code", "-tech-detect", "-title", "-web-server", "-favicon", "-tls"], os.path.join(OUTDIR, "httpx.txt"))
        run_cmd(["gobuster", "dir", "-u", f"http://{TARGET}", "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"], os.path.join(OUTDIR, "gobuster_http.txt"))
        run_cmd(["nikto", "-h", f"http://{TARGET}"], os.path.join(OUTDIR, "nikto.txt"))
        run_cmd(["nuclei", "-u", f"http://{TARGET}", "-silent"], os.path.join(OUTDIR, "nuclei_http.txt"))

    if "ftp" in services:
        run_cmd(["hydra", "-l", "anonymous", "-P", "/usr/share/wordlists/rockyou.txt", f"ftp://{TARGET}"], os.path.join(OUTDIR, "ftp_hydra.txt"))

    if "smb" in services or "netbios" in services:
        run_cmd(["enum4linux", "-a", TARGET], os.path.join(OUTDIR, "enum4linux.txt"))
        run_cmd(["smbclient", "-L", f"\\\\{TARGET}", "-N"], os.path.join(OUTDIR, "smbclient.txt"))

    if "ssh" in services:
        run_cmd(["ssh-audit", TARGET], os.path.join(OUTDIR, "ssh_audit.txt"))

    if "snmp" in services:
        run_cmd(["snmpwalk", "-v1", "-c", "public", TARGET], os.path.join(OUTDIR, "snmpwalk.txt"))

    if "ldap" in services:
        run_cmd(["ldapsearch", "-x", "-H", f"ldap://{TARGET}", "-s", "base"], os.path.join(OUTDIR, "ldapsearch.txt"))

def run_searchsploit():
    with open(SERVICES_OUT) as f, open(EXPLOIT_OUT, "w") as out:
        for line in f:
            if "/tcp" in line:
                parts = line.strip().split()
                service_line = " ".join(parts[3:])
                if service_line:
                    out.write(f"### {service_line}\n")
                    subprocess.run(["searchsploit", service_line], stdout=out)
                    out.write("\n")

print("[*] Running enumeration tools...")
run_enum()
print("[*] Running SearchSploit...")
run_searchsploit()

print("[*] Generating report...")
with open(REPORT_MD, "w") as report:
    report.write(f"# Recon Report for {TARGET}\n_Generated: {TIMESTAMP}_\n\n")
    for fname in os.listdir(OUTDIR):
        if fname.endswith(".txt"):
            report.write(f"## {fname}\n\n```
")
            with open(os.path.join(OUTDIR, fname)) as f:
                report.write(f.read())
            report.write("\n```
\n")

if shutil.which("pandoc"):
    subprocess.run(["pandoc", REPORT_MD, "-o", REPORT_PDF])
    print(f"[+] PDF report saved to: {REPORT_PDF}")
else:
    print("[!] pandoc not found — skipping PDF generation")

print(f"[*] Done. All results saved in {OUTDIR}/")
