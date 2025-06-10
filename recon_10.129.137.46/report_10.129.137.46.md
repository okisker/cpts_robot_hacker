# Recon Report for 10.129.137.46
_Generated: 

## dnsenum.txt
```
dnsenum VERSION:1.3.1
[1;34m
-----   10.129.137.46   -----
[0m[1;31m

Host's addresses:
__________________

[0m[1;31m

Name Servers:
______________

[0m```

## dns_zone.txt
```

; <<>> DiG 9.20.9-1-Debian <<>> axfr @10.129.137.46 example.com
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

## ffuf.txt
```
{"commandline":"ffuf -u http://10.129.137.46/FUZZ -w /usr/share/wordlists/dirb/common.txt -o recon_10.129.137.46/ffuf.txt","time":"2025-06-09T21:11:38-07:00","results":[{"input":{"FFUFHASH":"630d845a","FUZZ":"css"},"position":1114,"status":301,"length":312,"words":20,"lines":10,"content-type":"text/html; charset=iso-8859-1","redirectlocation":"http://10.129.137.46/css/","scraper":{},"duration":29461082,"resultfile":"","url":"http://10.129.137.46/css","host":"10.129.137.46"},{"input":{"FFUFHASH":"630d8670","FUZZ":"fonts"},"position":1648,"status":301,"length":314,"words":20,"lines":10,"content-type":"text/html; charset=iso-8859-1","redirectlocation":"http://10.129.137.46/fonts/","scraper":{},"duration":28893468,"resultfile":"","url":"http://10.129.137.46/fonts","host":"10.129.137.46"},{"input":{"FFUFHASH":"630d87c7","FUZZ":"images"},"position":1991,"status":301,"length":315,"words":20,"lines":10,"content-type":"text/html; charset=iso-8859-1","redirectlocation":"http://10.129.137.46/images/","scraper":{},"duration":33994087,"resultfile":"","url":"http://10.129.137.46/images","host":"10.129.137.46"},{"input":{"FFUFHASH":"630d87e4","FUZZ":"index.html"},"position":2020,"status":200,"length":15157,"words":1055,"lines":408,"content-type":"text/html","redirectlocation":"","scraper":{},"duration":27861653,"resultfile":"","url":"http://10.129.137.46/index.html","host":"10.129.137.46"},{"input":{"FFUFHASH":"630d8a0c","FUZZ":"monitoring"},"position":2572,"status":301,"length":319,"words":20,"lines":10,"content-type":"text/html; charset=iso-8859-1","redirectlocation":"http://10.129.137.46/monitoring/","scraper":{},"duration":29864104,"resultfile":"","url":"http://10.129.137.46/monitoring","host":"10.129.137.46"},{"input":{"FFUFHASH":"630d8e04","FUZZ":"server-status"},"position":3588,"status":403,"length":278,"words":20,"lines":10,"content-type":"text/html; charset=iso-8859-1","redirectlocation":"","scraper":{},"duration":28615713,"resultfile":"","url":"http://10.129.137.46/server-status","host":"10.129.137.46"}],"config":{"autocalibration":false,"autocalibration_keyword":"FUZZ","autocalibration_perhost":false,"autocalibration_strategies":["basic"],"autocalibration_strings":[],"colors":false,"cmdline":"ffuf -u http://10.129.137.46/FUZZ -w /usr/share/wordlists/dirb/common.txt -o recon_10.129.137.46/ffuf.txt","configfile":"","postdata":"","debuglog":"","delay":{"value":"0.00"},"dirsearch_compatibility":false,"encoders":[],"extensions":[],"fmode":"or","follow_redirects":false,"headers":{},"ignorebody":false,"ignore_wordlist_comments":false,"inputmode":"clusterbomb","cmd_inputnum":100,"inputproviders":[{"name":"wordlist","keyword":"FUZZ","value":"/usr/share/wordlists/dirb/common.txt","encoders":"","template":""}],"inputshell":"","json":false,"matchers":{"IsCalibrated":false,"Mutex":{},"Matchers":{"status":{"value":"200-299,301,302,307,401,403,405,500"}},"Filters":{},"PerDomainFilters":{}},"mmode":"or","maxtime":0,"maxtime_job":0,"method":"GET","noninteractive":false,"outputdirectory":"","outputfile":"recon_10.129.137.46/ffuf.txt","outputformat":"json","OutputSkipEmptyFile":false,"proxyurl":"","quiet":false,"rate":0,"raw":false,"recursion":false,"recursion_depth":0,"recursion_strategy":"default","replayproxyurl":"","requestfile":"","requestproto":"https","scraperfile":"","scrapers":"all","sni":"","stop_403":false,"stop_all":false,"stop_errors":false,"threads":40,"timeout":10,"url":"http://10.129.137.46/FUZZ","verbose":false,"wordlists":["/usr/share/wordlists/dirb/common.txt"],"http2":false,"client-cert":"","client-key":""}}```

## ftp_check.txt
```
?Invalid command.
?Invalid command.
Please login with USER and PASS.
Please login with USER and PASS.
```

## ftp_hydra.txt
```
# Hydra v9.5 run at 2025-06-09 21:11:40 on 10.129.137.46 ftp (hydra -l anonymous -P /usr/share/wordlists/rockyou.txt -o recon_10.129.137.46/ftp_hydra.txt ftp://10.129.137.46)
[21][ftp] host: 10.129.137.46   login: anonymous   password: 12345
[21][ftp] host: 10.129.137.46   login: anonymous   password: 12345678
[21][ftp] host: 10.129.137.46   login: anonymous   password: babygirl
[21][ftp] host: 10.129.137.46   login: anonymous   password: monkey
[21][ftp] host: 10.129.137.46   login: anonymous   password: 123456
[21][ftp] host: 10.129.137.46   login: anonymous   password: 123456789
[21][ftp] host: 10.129.137.46   login: anonymous   password: password
[21][ftp] host: 10.129.137.46   login: anonymous   password: iloveyou
[21][ftp] host: 10.129.137.46   login: anonymous   password: princess
[21][ftp] host: 10.129.137.46   login: anonymous   password: 1234567
[21][ftp] host: 10.129.137.46   login: anonymous   password: rockyou
[21][ftp] host: 10.129.137.46   login: anonymous   password: abc123
[21][ftp] host: 10.129.137.46   login: anonymous   password: nicole
[21][ftp] host: 10.129.137.46   login: anonymous   password: daniel
[21][ftp] host: 10.129.137.46   login: anonymous   password: lovely
[21][ftp] host: 10.129.137.46   login: anonymous   password: jessica
```

## gobuster_http.txt
```
/images              [36m (Status: 301)[0m [Size: 315][34m [--> http://10.129.137.46/images/][0m
/css                 [36m (Status: 301)[0m [Size: 312][34m [--> http://10.129.137.46/css/][0m
/fonts               [36m (Status: 301)[0m [Size: 314][34m [--> http://10.129.137.46/fonts/][0m
/monitoring          [36m (Status: 301)[0m [Size: 319][34m [--> http://10.129.137.46/monitoring/][0m
/server-status       [33m (Status: 403)[0m [Size: 278]
```

## nikto.txt
```
- Nikto v2.5.0/
```

## nmap_full.txt
```
# Nmap 7.94 scan initiated Mon Jun  9 20:40:02 2025 as: nmap -p- -T4 -oN recon_10.129.137.46/nmap_full.txt 10.129.137.46
Nmap scan report for 10.129.137.46
Host is up (0.038s latency).
Not shown: 65524 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
110/tcp  open  pop3
111/tcp  open  rpcbind
143/tcp  open  imap
993/tcp  open  imaps
995/tcp  open  pop3s
8080/tcp open  http-proxy

# Nmap done at Mon Jun  9 20:40:17 2025 -- 1 IP address (1 host up) scanned in 15.64 seconds
```

## nmap_services.txt
```
# Nmap 7.94 scan initiated Mon Jun  9 20:40:18 2025 as: nmap -sC -sV -p 21,22,25,53,80,110,111,143,993,995,8080 -oN recon_10.129.137.46/nmap_services.txt 10.129.137.46
Nmap scan report for 10.129.137.46
Host is up (0.030s latency).

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              38 May 30  2022 flag.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.24
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
25/tcp   open  smtp     Postfix smtpd
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp   open  domain   (unknown banner: 1337_HTB_DNS)
| dns-nsid: 
|_  bind.version: 1337_HTB_DNS
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
|_    1337_HTB_DNS
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Inlanefreight
|_http-server-header: Apache/2.4.41 (Ubuntu)
110/tcp  open  pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_pop3-capabilities: TOP SASL RESP-CODES CAPA AUTH-RESP-CODE STLS PIPELINING UIDL
|_ssl-date: TLS randomness does not represent time
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
143/tcp  open  imap     Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: have post-login IDLE more LITERAL+ SASL-IR ENABLE OK STARTTLS listed ID IMAP4rev1 LOGINDISABLEDA0001 capabilities LOGIN-REFERRALS Pre-login
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_imap-capabilities: post-login IDLE more LITERAL+ SASL-IR ENABLE OK have listed ID IMAP4rev1 capabilities Pre-login AUTH=PLAINA0001 LOGIN-REFERRALS
995/tcp  open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Not valid before: 2022-05-30T17:15:40
|_Not valid after:  2032-05-27T17:15:40
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: TOP SASL(PLAIN) RESP-CODES CAPA USER AUTH-RESP-CODE PIPELINING UIDL
8080/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Support Center
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.94%I=7%D=6/9%Time=6847A92D%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,39,"\x007\0\x06\x85\0\0\x01\0\x01\0\0\0\0\x07version\x0
SF:4bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\r\x0c1337_HTB_DNS");
Service Info: Host:  ubuntu; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun  9 20:40:52 2025 -- 1 IP address (1 host up) scanned in 34.28 seconds
```

## nuclei_http.txt
```
[missing-sri] [http] [info] http://10.129.137.46 ["//fonts.googleapis.com/css?family=Poppins:100,100i,200,200i,300,300i,400,400i,500,500i,600,600i,700,700i,800,800i,900,900i&subset=devanagari,latin-ext"]
[waf-detect:apachegeneric] [http] [info] http://10.129.137.46
[CVE-2023-48795] [javascript] [medium] 10.129.137.46:22 ["Vulnerable to Terrapin"]
[ssh-auth-methods] [javascript] [info] 10.129.137.46:22 ["["publickey","password"]"]
[ssh-password-auth] [javascript] [info] 10.129.137.46:22
[ssh-server-enumeration] [javascript] [info] 10.129.137.46:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"]
[ssh-sha1-hmac-algo] [javascript] [info] 10.129.137.46:22
[rpcbind-portmapper-detect] [tcp] [info] 10.129.137.46:111
[openssh-detect] [tcp] [info] 10.129.137.46:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"]
[old-copyright] [http] [info] http://10.129.137.46 ["\u00a9 2019"]
[http-missing-security-headers:permissions-policy] [http] [info] http://10.129.137.46
[http-missing-security-headers:x-content-type-options] [http] [info] http://10.129.137.46
[http-missing-security-headers:referrer-policy] [http] [info] http://10.129.137.46
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://10.129.137.46
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://10.129.137.46
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://10.129.137.46
[http-missing-security-headers:strict-transport-security] [http] [info] http://10.129.137.46
[http-missing-security-headers:x-frame-options] [http] [info] http://10.129.137.46
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://10.129.137.46
[http-missing-security-headers:clear-site-data] [http] [info] http://10.129.137.46
[http-missing-security-headers:content-security-policy] [http] [info] http://10.129.137.46
[options-method] [http] [info] http://10.129.137.46 ["GET,POST,OPTIONS,HEAD"]
[ftp-anonymous-login] [tcp] [medium] 10.129.137.46:21
[form-detection] [http] [info] http://10.129.137.46
[addeventlistener-detect] [http] [info] http://10.129.137.46
[email-extractor] [http] [info] http://10.129.137.46 ["info@example.com"]
[apache-detect] [http] [info] http://10.129.137.46 ["Apache/2.4.41 (Ubuntu)"]
[tech-detect:font-awesome] [http] [info] http://10.129.137.46
[tech-detect:bootstrap] [http] [info] http://10.129.137.46
[tech-detect:google-font-api] [http] [info] http://10.129.137.46
```

## rpc_enum.txt
```
```

## searchsploit_results.txt
```
### vsftpd 3.0.3
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                  |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
[01;31m[Kvsftpd[m[K [01;31m[K3.0.3[m[K - Remote Denial of Service                                                                                                                                         | multiple/remote/49719.py
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

### OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
Exploits: No Results
Shellcodes: No Results

### Postfix smtpd
Exploits: No Results
Shellcodes: No Results

### (unknown banner: 1337_HTB_DNS)
Exploits: No Results
Shellcodes: No Results

### Apache httpd 2.4.41 ((Ubuntu))
Exploits: No Results
Shellcodes: No Results

### Dovecot pop3d
Exploits: No Results
Shellcodes: No Results

### 2-4 (RPC #100000)
Exploits: No Results
Shellcodes: No Results

### 111/tcp rpcbind
Exploits: No Results
Shellcodes: No Results

### 111/tcp6 rpcbind
Exploits: No Results
Shellcodes: No Results

### Dovecot imapd (Ubuntu)
Exploits: No Results
Shellcodes: No Results

### Dovecot imapd (Ubuntu)
Exploits: No Results
Shellcodes: No Results

### Dovecot pop3d
Exploits: No Results
Shellcodes: No Results

### Apache httpd 2.4.41 ((Ubuntu))
Exploits: No Results
Shellcodes: No Results

```

## smtp_enum.txt
```
```

## ssh_audit.txt
```
[0;36m# general[0m
[0;32m(gen) banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5[0m
[0;32m(gen) software: OpenSSH 8.2p1[0m
[0;32m(gen) compatibility: OpenSSH 7.4+, Dropbear SSH 2020.79+[0m
[0;32m(gen) compression: enabled (zlib@openssh.com)[0m

[0;36m# key exchange algorithms[0m
[0;32m(kex) curve25519-sha256                     -- [info] available since OpenSSH 7.4, Dropbear SSH 2018.76[0m
[0;32m                                            `- [info] default key exchange from OpenSSH 7.4 to 8.9[0m
[0;32m(kex) curve25519-sha256@libssh.org          -- [info] available since OpenSSH 6.4, Dropbear SSH 2013.62[0m
[0;32m                                            `- [info] default key exchange from OpenSSH 6.5 to 7.3[0m
[0;31m(kex) ecdh-sha2-nistp256                    -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency[0m
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
[0;31m(kex) ecdh-sha2-nistp384                    -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency[0m
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
[0;31m(kex) ecdh-sha2-nistp521                    -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency[0m
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
[0;32m(kex) diffie-hellman-group-exchange-sha256 (3072-bit) -- [info] available since OpenSSH 4.4[0m
[0;32m                                                      `- [info] OpenSSH's GEX fallback mechanism was triggered during testing. Very old SSH clients will still be able to create connections using a 2048-bit modulus, though modern clients will use 3072. This can only be disabled by recompiling the code (see https://github.com/openssh/openssh-portable/blob/V_9_4/dh.c#L477).[0m
[0;32m(kex) diffie-hellman-group16-sha512         -- [info] available since OpenSSH 7.3, Dropbear SSH 2016.73[0m
[0;32m(kex) diffie-hellman-group18-sha512         -- [info] available since OpenSSH 7.3[0m
[0;33m(kex) diffie-hellman-group14-sha256         -- [warn] 2048-bit modulus only provides 112-bits of symmetric strength[0m
                                            `- [info] available since OpenSSH 7.3, Dropbear SSH 2016.73

[0;36m# host-key algorithms[0m
[0;32m(key) rsa-sha2-512 (3072-bit)               -- [info] available since OpenSSH 7.2[0m
[0;32m(key) rsa-sha2-256 (3072-bit)               -- [info] available since OpenSSH 7.2, Dropbear SSH 2020.79[0m
[0;31m(key) ssh-rsa (3072-bit)                    -- [fail] using broken SHA-1 hash algorithm[0m
                                            `- [info] available since OpenSSH 2.5.0, Dropbear SSH 0.28
                                            `- [info] deprecated in OpenSSH 8.8: https://www.openssh.com/txt/release-8.8
[0;31m(key) ecdsa-sha2-nistp256                   -- [fail] using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency[0m
[0;33m                                            `- [warn] using weak random number generator could reveal the key[0m
                                            `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
[0;32m(key) ssh-ed25519                           -- [info] available since OpenSSH 6.5, Dropbear SSH 2020.79[0m

[0;36m# encryption algorithms (ciphers)[0m
[0;33m(enc) chacha20-poly1305@openssh.com         -- [warn] vulnerable to the Terrapin attack (CVE-2023-48795), allowing message prefix truncation[0m
                                            `- [info] available since OpenSSH 6.5, Dropbear SSH 2020.79
                                            `- [info] default cipher since OpenSSH 6.9
[0;32m(enc) aes128-ctr                            -- [info] available since OpenSSH 3.7, Dropbear SSH 0.52[0m
[0;32m(enc) aes192-ctr                            -- [info] available since OpenSSH 3.7[0m
[0;32m(enc) aes256-ctr                            -- [info] available since OpenSSH 3.7, Dropbear SSH 0.52[0m
[0;32m(enc) aes128-gcm@openssh.com                -- [info] available since OpenSSH 6.2[0m
[0;32m(enc) aes256-gcm@openssh.com                -- [info] available since OpenSSH 6.2[0m

[0;36m# message authentication code algorithms[0m
[0;33m(mac) umac-64-etm@openssh.com               -- [warn] using small 64-bit tag size[0m
                                            `- [info] available since OpenSSH 6.2
[0;32m(mac) umac-128-etm@openssh.com              -- [info] available since OpenSSH 6.2[0m
[0;32m(mac) hmac-sha2-256-etm@openssh.com         -- [info] available since OpenSSH 6.2[0m
[0;32m(mac) hmac-sha2-512-etm@openssh.com         -- [info] available since OpenSSH 6.2[0m
[0;31m(mac) hmac-sha1-etm@openssh.com             -- [fail] using broken SHA-1 hash algorithm[0m
                                            `- [info] available since OpenSSH 6.2
[0;33m(mac) umac-64@openssh.com                   -- [warn] using encrypt-and-MAC mode[0m
[0;33m                                            `- [warn] using small 64-bit tag size[0m
                                            `- [info] available since OpenSSH 4.7
[0;33m(mac) umac-128@openssh.com                  -- [warn] using encrypt-and-MAC mode[0m
                                            `- [info] available since OpenSSH 6.2
[0;33m(mac) hmac-sha2-256                         -- [warn] using encrypt-and-MAC mode[0m
                                            `- [info] available since OpenSSH 5.9, Dropbear SSH 2013.56
[0;33m(mac) hmac-sha2-512                         -- [warn] using encrypt-and-MAC mode[0m
                                            `- [info] available since OpenSSH 5.9, Dropbear SSH 2013.56
[0;31m(mac) hmac-sha1                             -- [fail] using broken SHA-1 hash algorithm[0m
[0;33m                                            `- [warn] using encrypt-and-MAC mode[0m
                                            `- [info] available since OpenSSH 2.1.0, Dropbear SSH 0.28

[0;36m# fingerprints[0m
[0;32m(fin) ssh-ed25519: SHA256:HfXWue9Dnk+UvRXP6ytrRnXKIRSijm058/zFrj/1LvY[0m
[0;32m(fin) ssh-rsa: SHA256:i6dYI/SB51/FIkHHmQ3XUvCHrnX/QM28X440VxlxK4I[0m

[0;36m# algorithm recommendations (for OpenSSH 8.2)[0m
[0;31m(rec) -ecdh-sha2-nistp256                   -- kex algorithm to remove [0m
[0;31m(rec) -ecdh-sha2-nistp384                   -- kex algorithm to remove [0m
[0;31m(rec) -ecdh-sha2-nistp521                   -- kex algorithm to remove [0m
[0;31m(rec) -ecdsa-sha2-nistp256                  -- key algorithm to remove [0m
[0;31m(rec) -hmac-sha1                            -- mac algorithm to remove [0m
[0;31m(rec) -hmac-sha1-etm@openssh.com            -- mac algorithm to remove [0m
[0;31m(rec) -ssh-rsa                              -- key algorithm to remove [0m
[0;33m(rec) -chacha20-poly1305@openssh.com        -- enc algorithm to remove [0m
[0;33m(rec) -diffie-hellman-group14-sha256        -- kex algorithm to remove [0m
[0;33m(rec) -hmac-sha2-256                        -- mac algorithm to remove [0m
[0;33m(rec) -hmac-sha2-512                        -- mac algorithm to remove [0m
[0;33m(rec) -umac-128@openssh.com                 -- mac algorithm to remove [0m
[0;33m(rec) -umac-64-etm@openssh.com              -- mac algorithm to remove [0m
[0;33m(rec) -umac-64@openssh.com                  -- mac algorithm to remove [0m

[0;36m# additional info[0m
[0;33m(nfo) For hardening guides on common OSes, please see: <https://www.ssh-audit.com/hardening_guides.html>[0m
[0;33m(nfo) Potentially insufficient connection throttling detected, resulting in possible vulnerability to the DHEat DoS attack (CVE-2002-20001).  38 connections were created in 0.837 seconds, or 45.4 conns/sec; server must respond with a rate less than 20.0 conns/sec per IPv4/IPv6 source address to be considered safe.  For rate-throttling options, please see <https://www.ssh-audit.com/hardening_guides.html>.  Be aware that using 'PerSourceMaxStartups 1' properly protects the server from this attack, but will cause this test to yield a false positive.  Suppress this test and message with the --skip-rate-test option.[0m

```

## ssh_version.txt
```
debug1: Local version string SSH-2.0-OpenSSH_9.9p2 Debian-1
```

## whatweb.txt
```
[1m[34mhttp://10.129.137.46[0m [200 OK] [1mApache[0m[[1m[32m2.4.41[0m], [1mBootstrap[0m, [1mCountry[0m[[0m[22mRESERVED[0m][[1m[31mZZ[0m], [1mEmail[0m[[0m[22minfo@example.com,info@inlanefreight.loca[0m], [1mHTML5[0m, [1mHTTPServer[0m[[1m[31mUbuntu Linux[0m][[1m[36mApache/2.4.41 (Ubuntu)[0m], [1mIP[0m[[0m[22m10.129.137.46[0m], [1mScript[0m, [1mTitle[0m[[1m[33mInlanefreight[0m]
```

