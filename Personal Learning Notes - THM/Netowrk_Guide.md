# Network Servies 1 + 2

## SMB

### Understanding SMB
~~~
What is SMB?

SMB - Server Message Block Protocol - is a client-server communication protocol used for sharing access to files, printers, serial ports and other resources on a network. [source]

Servers make file systems and other resources (printers, named pipes, APIs) available to clients on the network. Client computers may have their own hard disks, but they also want access to the shared file systems and printers on the servers.

The SMB protocol is known as a response-request protocol, meaning that it transmits multiple messages between the client and server to establish a connection. Clients connect to servers using TCP/IP (actually NetBIOS over TCP/IP as specified in RFC1001 and RFC1002), NetBEUI or IPX/SPX.

How does SMB work?

Once they have established a connection, clients can then send commands (SMBs) to the server that allow them to access shares, open files, read and write files, and generally do all the sort of things that you want to do with a file system. However, in the case of SMB, these things are done over the network.

What runs SMB?

Microsoft Windows operating systems since Windows 95 have included client and server SMB protocol support. Samba, an open source server that supports the SMB protocol, was released for Unix systems.
~~~

### Understanding SMB - Questions
~~~
1. What does SMB stand for? Server Messaage Block
2. What type of protocol is SMB? response-request  
3. What do clients connect to servers using? TCP/IP
4. What systems does Samba run on? Unix
~~~

### Enumerating SMB
~~~
Enumeration

Enumeration is the process of gathering information on a target in order to find potential attack vectors and aid in exploitation.

This process is essential for an attack to be successful, as wasting time with exploits that either don't work or can crash the system can be a waste of energy. Enumeration can be used to gather usernames, passwords, network information, hostnames, application data, services, or any other information that may be valuable to an attacker.

SMB

Typically, there are SMB share drives on a server that can be connected to and used to view or transfer files. SMB can often be a great starting point for an attacker looking to discover sensitive information — you'd be surprised what is sometimes included on these shares.

Port Scanning

The first step of enumeration is to conduct a port scan, to find out as much information as you can about the services, applications, structure and operating system of the target machine.

If you haven't already looked at port scanning, I recommend checking out the Nmap room here.

Enum4Linux

Enum4linux is a tool used to enumerate SMB shares on both Windows and Linux systems. It is basically a wrapper around the tools in the Samba package and makes it easy to quickly extract information from the target pertaining to SMB. It's installed by default on Parrot and Kali, however if you need to install it, you can do so from the official github.

The syntax of Enum4Linux is nice and simple: "enum4linux [options] ip"

TAG            FUNCTION

-U             get userlist
-M             get machine list
-N             get namelist dump (different from -U and-M)
-S             get sharelist
-P             get password policy information
-G             get group and member list

-a             all of the above (full basic enumeration)
~~~

### Enumerating SMB - Questions
~~~
1. Conduct an nmap scan of your choosing, How many ports are open? 3
2. What ports is SMB running on? 139/445
3. Let's get started with Enum4Linux, what is the workgroup name? WORKGROUP
4. What comes up as the name of the machine? polosmb
5. What operating system version is running? 6.1
6. What share sticks out as something we might want to investigate?   
~~~

### Exploiting SMB
~~~
Types of SMB Exploit

While there are vulnerabilities such as CVE-2017-7494 that can allow remote code execution by exploiting SMB, you're more likely to encounter a situation where the best way into a system is due to misconfigurations in the system. In this case, we're going to be exploiting anonymous SMB share access- a common misconfiguration that can allow us to gain information that will lead to a shell.

Method Breakdown

So, from our enumeration stage, we know:

    - The SMB share location

    - The name of an interesting SMB share

SMBClient

Because we're trying to access an SMB share, we need a client to access resources on servers. We will be using SMBClient because it's part of the default samba suite. While it is available by default on Kali and Parrot, if you do need to install it, you can find the documentation here.

We can remotely access the SMB share using the syntax:

smbclient //[IP]/[SHARE]

Followed by the tags:

-U [name] : to specify the user

-p [port] : to specify the port
~~~

### Exploiting SMB - Questions

~~~
1. What would be the correct syntax to access an SMB share called "secret" as user "suit" on a machine with the IP 10.10.10.2 on the default port?  smbclient //10.10.10.2/secret -U suit
2. Does the share allow anonymous access? Y/N? Y
3. Who can we assume this profile folder belongs to? john cactus
4. What service has been configured to allow him to work from home? ssh
5. What directory on the share should we look in? .ssh
6. Which of these keys is most useful to us? id_rsa
7. What is the smb.txt flag? THM{smb_is_fun_eh?}
~~~

## Telnet

### Understanding Telnet
~~~
What is Telnet?

Telnet is an application protocol which allows you, with the use of a telnet client, to connect to and execute commands on a remote machine that's hosting a telnet server.

The telnet client will establish a connection with the server. The client will then become a virtual terminal- allowing you to interact with the remote host.

Replacement

Telnet sends all messages in clear text and has no specific security mechanisms. Thus, in many applications and services, Telnet has been replaced by SSH in most implementations.
 
How does Telnet work?

The user connects to the server by using the Telnet protocol, which means entering "telnet" into a command prompt. The user then executes commands on the server by using specific Telnet commands in the Telnet prompt. You can connect to a telnet server with the following syntax: "telnet [ip] [port]"
~~~

## Understanding Telnet - Questions
~~~
1. What is Telnet ? Application protocol
2. What has slowly replaced Telnet? ssh  
3. How would you connect to a Telnet server with the IP 10.10.10.3 on port 23? telnet 10.10.10.3 23
4. The lack of what, means that all Telnet communication is in plaintext? encryption
~~~

## Enumerating Telnet
~~~
Enumeration

We've already seen how key enumeration can be in exploiting a misconfigured network service. However, vulnerabilities that could be potentially trivial to exploit don't always jump out at us. For that reason, especially when it comes to enumerating network services, we need to be thorough in our method. 

Port Scanning

Let's start out the same way we usually do, a port scan, to find out as much information as we can about the services, applications, structure and operating system of the target machine. Scan the machine with nmap.
~~~

## Enumerating Telnet - Questions
~~~
1. How many ports are open on the target machine? 1
2. What port is this? 8012
3. This port is unassigned, but still lists the protocol it's using, what protocol is this? tcp
4. Now re-run the nmap scan, without the -p- tag, how many ports show up as open? 0
5. Based on the title returned to us, what do we think this port could be used for? a backdoor
6. Who could it belong to? Gathering possible usernames is an important step in enumeration. skidy
~~~


## Exploiting Telnet
~~~
Types of Telnet Exploit

Telnet, being a protocol, is in and of itself insecure for the reasons we talked about earlier. It lacks encryption, so sends all communication over plaintext, and for the most part has poor access control. There are CVE's for Telnet client and server systems, however, so when exploiting you can check for those on:

https://www.cvedetails.com/
https://cve.mitre.org/
A CVE, short for Common Vulnerabilities and Exposures, is a list of publicly disclosed computer security flaws. When someone refers to a CVE, they usually mean the CVE ID number assigned to a security flaw.

However, you're far more likely to find a misconfiguration in how telnet has been configured or is operating that will allow you to exploit it.

Method Breakdown

So, from our enumeration stage, we know:

    - There is a poorly hidden telnet service running on this machine

    - The service itself is marked "backdoor"

    - We have possible username of "Skidy" implicated

Using this information, let's try accessing this telnet port, and using that as a foothold to get a full reverse shell on the machine!

Connecting to Telnet

You can connect to a telnet server with the following syntax:

    "telnet [ip] [port]"

We're going to need to keep this in mind as we try and exploit this machine.


What is a Reverse Shell?

A "shell" can simply be described as a piece of code or program which can be used to gain code or command execution on a device.

A reverse shell is a type of shell in which the target machine communicates back to the attacking machine.

The attacking machine has a listening port, on which it receives the connection, resulting in code or command execution being achieved.

To make sure commands are being run

Start a tcpdump listener on your local machine.

If using your own machine with the OpenVPN connection, use:

sudo tcpdump ip proto \\icmp -i tun0
If using the AttackBox, use:

sudo tcpdump ip proto \\icmp -i eth0
This starts a tcpdump listener, specifically listening for ICMP traffic, which pings operate on.

ping [local ip] -c 1
~~~

### Exploiting Telnet - Questions
~~~
1. What welcome message do we receive? SKIDY'S BACKDOOR.
2. Let's try executing some commands, do we get a return on any input we enter into the telnet session? (Y/N) n
3. Now, use the command "ping [local THM ip] -c 1" through the telnet session to see if we're able to execute system commands. Do we receive any pings? Note, you need to preface this with .RUN (Y/N) y
4. What word does the generated payload start with? Mkfifo
5. What would the command look like for the listening port we selected in our payload? 4444
6. Success! What is the contents of flag.txt? 4444
~~~

## FTP

### Understanding FTP
~~~
What is FTP?

File Transfer Protocol (FTP) is, as the name suggests , a protocol used to allow remote transfer of files over a network. It uses a client-server model to do this, and- as we'll come on to later- relays commands and data in a very efficient way.

How does FTP work?

A typical FTP session operates using two channels:
a command (sometimes called the control) channel
a data channel.
As their names imply, the command channel is used for transmitting commands as well as replies to those commands, while the data channel is used for transferring data.

FTP operates using a client-server protocol. The client initiates a connection with the server, the server validates whatever login credentials are provided and then opens the session.

While the session is open, the client may execute FTP commands on the server.

Active vs Passive

The FTP server may support either Active or Passive connections, or both. 

In an Active FTP connection, the client opens a port and listens. The server is required to actively connect to it. 
In a Passive FTP connection, the server opens a port and listens (passively) and the client connects to it. 
This separation of command information and data into separate channels is a way of being able to send commands to the server without having to wait for the current data transfer to finish. If both channels were interlinked, you could only enter commands in between data transfers, which wouldn't be efficient for either large file transfers, or slow internet connections.
~~~

### Understnading FTP - Questions
~~~
1. What communications model does FTP use? client-server
2. What's the standard FTP port? 21
3. How many modes of FTP connection are there? 2
~~~

### Enumerating FTP

~~~
Lets Get Started

Before we begin, make sure to deploy the room and give it some time to boot. Please be aware, this can take up to five minutes so be patient!

Enumeration

By now, I don't think I need to explain any further how enumeration is key when attacking network services and protocols. You should, by now, have enough experience with nmap to be able to port scan effectively. If you get stuck using any tool- you can always use "tool [-h / -help / --help]" to find out more about it's function and syntax. Equally, man pages are extremely useful for this purpose. They can be reached using "man [tool]".

Method
We're going to be exploiting an anonymous FTP login, to see what files we can access- and if they contain any information that might allow us to pop a shell on the system. This is a common pathway in CTF challenges, and mimics a real-life careless implementation of FTP servers.

Resources

As we're going to be logging in to an FTP server, we will need to make sure an FTP client is installed on the system. There should be one installed by default on most Linux operating systems, such as Kali or Parrot OS. You can test if there is one by typing "ftp" into the console. If you're brought to a prompt that says: "ftp>", then you have a working FTP client on your system. If not, it's a simple matter of using "sudo apt install ftp" to install one.

Alternative Enumeration Methods
It's worth noting  that some vulnerable versions of in.ftpd and some other FTP server variants return different responses to the "cwd" command for home directories which exist and those that don’t. This can be exploited because you can issue cwd commands before authentication, and if there's a home directory- there is more than likely a user account to go with it. While this bug is found mainly within legacy systems, it's worth knowing about, as a way to exploit FTP.

This vulnerability is documented at: https://www.exploit-db.com/exploits/20745 
~~~

### Enumerating FTP - Questions
~~~
1. How many ports are open on the target machine? 2
2. What port is ftp running on? 21
3. What variant of FTP is running on it? vsFTPd
4. What is the name of the file in the anonymous FTP directory? PUBLIC_NOTICE.txt
5. What do we think a possible username
could be? Mike
~~~

### Exploting FTP
~~~
Types of FTP Exploit

Similarly to Telnet, when using FTP both the command and data channels are unencrypted. Any data sent over these channels can be intercepted and read.

With data from FTP being sent in plaintext, if a man-in-the-middle attack took place an attacker could reveal anything sent through this protocol (such as passwords). An article written by JSCape demonstrates and explains this process using ARP-Poisoning to trick a victim into sending sensitive information to an attacker, rather than a legitimate source.

When looking at an FTP server from the position we find ourselves in for this machine, an avenue we can exploit is weak or default password configurations.

Method Breakdown

So, from our enumeration stage, we know:

    - There is an FTP server running on this machine

    - We have a possible username

Using this information, let's try and bruteforce the password of the FTP Server.

Hydra

Hydra is a very fast online password cracking tool, which can perform rapid dictionary attacks against more than 50 Protocols, including Telnet, RDP, SSH, FTP, HTTP, HTTPS, SMB, several databases and much more. Hydra comes by default on both Parrot and Kali, however if you need it, you can find the GitHub here.
The syntax for the command we're going to use to find the passwords is this:

"hydra -t 4 -l dale -P /usr/share/wordlists/rockyou.txt -vV 10.10.10.6 ftp"
Let's break it down:

SECTION             FUNCTION

hydra                   Runs the hydra tool

-t 4                    Number of parallel connections per target

-l [user]               Points to the user who's account you're trying to compromise

-P [path to dictionary] Points to the file containing the list of possible passwords

-vV                     Sets verbose mode to very verbose, shows the login+pass combination for each attempt

[machine IP]            The IP address of the target machine

ftp / protocol          Sets the protocol

Let's crack some passwords!
~~~

### Exploiting FTP - Questions
~~~
1. What is the password for the user "mike"? password
2. What is ftp.txt? 
~~~

## Network File System (NFS)

### Understanding NFS
~~~
What is NFS?

NFS stands for "Network File System" and allows a system to share directories and files with others over a network. By using NFS, users and programs can access files on remote systems almost as if they were local files. It does this by mounting all, or a portion of a file system on a server. The portion of the file system that is mounted can be accessed by clients with whatever privileges are assigned to each file.

How does NFS work?

Computer network - Vector stencils library | Computers ...

We don't need to understand the technical exchange in too much detail to be able to exploit NFS effectively- however if this is something that interests you, I would recommend this resource: https://docs.oracle.com/cd/E19683-01/816-4882/6mb2ipq7l/index.html

First, the client will request to mount a directory from a remote host on a local directory just the same way it can mount a physical device. The mount service will then act to connect to the relevant mount daemon using RPC.

The server checks if the user has permission to mount whatever directory has been requested. It will then return a file handle which uniquely identifies each file and directory that is on the server.

If someone wants to access a file using NFS, an RPC call is placed to NFSD (the NFS daemon) on the server. This call takes parameters such as:

 The file handle
 The name of the file to be accessed
 The user's, user ID
 The user's group ID
These are used in determining access rights to the specified file. This is what controls user permissions, I.E read and write of files.

What runs NFS?

Using the NFS protocol, you can transfer files between computers running Windows and other non-Windows operating systems, such as Linux, MacOS or UNIX.

A computer running Windows Server can act as an NFS file server for other non-Windows client computers. Likewise, NFS allows a Windows-based computer running Windows Server to access files stored on a non-Windows NFS server.
~~~

### Understanding NFS - Questions
~~~
1. What does NFS stand for? network file system
2. What process allows an NFS client to interact with a remote directory as though it was a physical device? mounting
3. What does NFS use to represent files and directories on the server? file handle
4. What protocol does NFS use to communicate between the server and client? rpc
5. What two pieces of user data does the NFS server take as parameters for controlling user permissions? Format: parameter 1 / parameter 2 user id / group id
6. Can a Windows NFS server share files with a Linux client? (Y/N) y
7. Can a Linux NFS server share files with a MacOS client? (Y/N) y
8. What is the latest version of NFS? [released in 2016, but is still up to date as of 2020] This will require external research.
~~~

### Enumerating NFS 
~~~
What is Enumeration?

Enumeration is defined as "a process which establishes an active connection to the target hosts to discover potential attack vectors in the system, and the same can be used for further exploitation of the system." - Infosec Institute. It is a critical phase when considering how to enumerate and exploit a remote machine - as the information you will use to inform your attacks will come from this stage

Requirements

In order to do a more advanced enumeration of the NFS server, and shares- we're going to need a few tools. The first of which is key to interacting with any NFS share from your local machine: nfs-common.

NFS-Common

It is important to have this package installed on any machine that uses NFS, either as client or server. It includes programs such as: lockd, statd, showmount, nfsstat, gssd, idmapd and mount.nfs. Primarily, we are concerned with "showmount" and "mount.nfs" as these are going to be most useful to us when it comes to extracting information from the NFS share. If you'd like more information about this package, feel free to read: https://packages.ubuntu.com/jammy/nfs-common.

You can install nfs-common using "sudo apt install nfs-common", it is part of the default repositories for most Linux distributions such as the Kali Remote Machine or AttackBox that is provided to TryHackMe.

Port Scanning

Port scanning has been covered many times before, so I'll only cover the basics that you need for this room here. If you'd like to learn more about nmap in more detail please have a look at the nmap room.

The first step of enumeration is to conduct a port scan, to find out as much information as you can about the services, open ports and operating system of the target machine. You can go as in-depth as you like on this, however, I suggest using nmap with the -A and -p- tags.

Mounting NFS shares

Your client’s system needs a directory where all the content shared by the host server in the export folder can be accessed. You can create
this folder anywhere on your system. Once you've created this mount point, you can use the "mount" command to connect the NFS share to the mount point on your machine like so:

sudo mount -t nfs IP:share /tmp/mount/ -nolock

Let's break this down

Tag Function
sudo    Run as root
mount   Execute the mount command
-t nfs  Type of device to mount, then specifying that it's NFS
IP:share    The IP Address of the NFS server, and the name of the share we wish to mount
-nolock Specifies not to use NLM locking
~~~

### Enumerating NFS - Questions
~~~
1. How many ports are open? 7
2. Which port contains the service we're looking to enumerate? 2049
3. Now, use /usr/sbin/showmount -e [IP] to list the NFS shares, what is the name of the visible share? /home
4. What is the name of the folder inside? cappucino
5. Which of these folders could contain keys that would give us remote access to the server? .ssh
6. Which of these keys is most useful to us? id_rsa
7. Can we log into the machine using ssh -i <key-file> <username>@<ip> ? (Y/N) y
~~~

### Exploiting NFS
~~~
We're done, right?

Not quite, if you have a low privilege shell on any machine and you found that a machine has an NFS share you might be able to use that to escalate privileges, depending on how it is configured.

What is root_squash?

By default, on NFS shares- Root Squashing is enabled, and prevents anyone connecting to the NFS share from having root access to the NFS volume. Remote root users are assigned a user “nfsnobody” when connected, which has the least local privileges. Not what we want. However, if this is turned off, it can allow the creation of SUID bit files, allowing a remote user root access to the connected system.

SUID
So, what are files with the SUID bit set? Essentially, this means that the file or files can be run with the permissions of the file(s) owner/group. In this case, as the super-user. We can leverage this to get a shell with these privileges!

Method

This sounds complicated, but really- provided you're familiar with how SUID files work, it's fairly easy to understand. We're able to upload files to the NFS share, and control the permissions of these files. We can set the permissions of whatever we upload, in this case a bash shell executable. We can then log in through SSH, as we did in the previous task- and execute this executable to gain a root shell!

The Executable

Due to compatibility reasons, we'll use a standard Ubuntu Server 18.04 bash executable, the same as the server's- as we know from our nmap scan. You can download it here. If you want to download it via the command line, be careful not to download the github page instead of the raw script. You can use wget https://github.com/polo-sec/writing/raw/master/Security%20Challenge%20Walkthroughs/Networks%202/bash.

Mapped Out Pathway:

If this is still hard to follow, here's a step by step of the actions we're taking, and how they all tie together to allow us to gain a root shell:


    NFS Access ->

        Gain Low Privilege Shell ->

            Upload Bash Executable to the NFS share ->

                Set SUID Permissions Through NFS Due To Misconfigured Root Squash ->

                    Login through SSH ->

                        Execute SUID Bit Bash Executable ->

                            ROOT ACCESS
~~~

### Exploting NFS - Questions
~~~
1. What letter do we use to set the SUID bit set using chmod? s
2. What does the permission set look like? Make sure that it ends with -sr-x. -rwsr-sr-x
3. Great! If all's gone well you should have a shell as root! What's the root flag? THM{nfs_got_pwned}
~~~

## SMTP

### Understaanding SMTP
~~~
What is SMTP?

SMTP stands for "Simple Mail Transfer Protocol". It is utilised to handle the sending of emails. In order to support email services, a protocol pair is required, comprising of SMTP and POP/IMAP. Together they allow the user to send outgoing mail and retrieve incoming mail, respectively.

The SMTP server performs three basic functions:

 It verifies who is sending emails through the SMTP server.
 It sends the outgoing mail
 If the outgoing mail can't be delivered it sends the message back to the sender
Most people will have encountered SMTP when configuring a new email address on some third-party email clients, such as Thunderbird; as when you configure a new email client, you will need to configure the SMTP server configuration in order to send outgoing emails.
POP and IMAP

POP, or "Post Office Protocol" and IMAP, "Internet Message Access Protocol" are both email protocols who are responsible for the transfer of email between a client and a mail server. The main differences is in POP's more simplistic approach of downloading the inbox from the mail server, to the client. Where IMAP will synchronise the current inbox, with new mail on the server, downloading anything new. This means that changes to the inbox made on one computer, over IMAP, will persist if you then synchronise the inbox from another computer. The POP/IMAP server is responsible for fulfiling this process.

How does SMTP work?

Email delivery functions much the same as the physical mail delivery system. The user will supply the email (a letter) and a service (the postal delivery service), and through a series of steps- will deliver it to the recipients inbox (postbox). The role of the SMTP server in this service, is to act as the sorting office, the email (letter) is picked up and sent to this server, which then directs it to the recipient.
We can map the journey of an email from your computer to the recipient’s like this:

1. The mail user agent, which is either your email client or an external program. connects to the SMTP server of your domain, e.g. smtp.google.com. This initiates the SMTP handshake. This connection works over the SMTP port- which is usually 25. Once these connections have been made and validated, the SMTP session starts.

2. The process of sending mail can now begin. The client first submits the sender, and recipient's email address- the body of the email and any attachments, to the server.

3. The SMTP server then checks whether the domain name of the recipient and the sender is the same.

4. The SMTP server of the sender will make a connection to the recipient's SMTP server before relaying the email. If the recipient's server can't be accessed, or is not available- the Email gets put into an SMTP queue.

5. Then, the recipient's SMTP server will verify the incoming email. It does this by checking if the domain and user name have been recognised. The server will then forward the email to the POP or IMAP server, as shown in the diagram above.

6. The E-Mail will then show up in the recipient's inbox.

This is a very simplified version of the process, and there are a lot of sub-protocols, communications and details that haven't been included. If you're looking to learn more about this topic, this is a really friendly to read breakdown of the finer technical details- I actually used it to write this breakdown:

https://computer.howstuffworks.com/e-mail-messaging/email3.htm

What runs SMTP?

SMTP Server software is readily available on Windows server platforms, with many other variants of SMTP being available to run on Linux.
~~~

### Understanding SMTP - Questions
~~~
1. What does SMTP stand for? simple mail transfer protocol
2. What does SMTP handle the sending of? emails
3. What is the first step in the SMTP process?  SMTP handshake
4. What is the default SMTP port? 25
5. Where does the SMTP server send the email if the recipient's server is not available? SMTP Queue
6. On what server does the Email ultimately end up on? pop/imap
7. Can a Linux machine run an SMTP server? (Y/N) y
8. Can a Windows machine run an SMTP server? (Y/N) y
~~~

### Enumerating SMTP
~~~
Enumerating Server Details

Poorly configured or vulnerable mail servers can often provide an initial foothold into a network, but prior to launching an attack, we want to fingerprint the server to make our targeting as precise as possible. We're going to use the "smtp_version" module in MetaSploit to do this. As its name implies, it will scan a range of IP addresses and determine the version of any mail servers it encounters.

Enumerating Users from SMTP

The SMTP service has two internal commands that allow the enumeration of users: VRFY (confirming the names of valid users) and EXPN (which reveals the actual address of user’s aliases and lists of e-mail (mailing lists). Using these SMTP commands, we can reveal a list of valid users

We can do this manually, over a telnet connection- however Metasploit comes to the rescue again, providing a handy module appropriately called "smtp_enum" that will do the legwork for us! Using the module is a simple matter of feeding it a host or range of hosts to scan and a wordlist containing usernames to enumerate.

Requirements
As we're going to be using Metasploit for this, it's important that you have Metasploit installed. It is by default on both Kali Linux and Parrot OS; however, it's always worth doing a quick update to make sure that you're on the latest version before launching any attacks. You can do this with a simple "sudo apt update", and accompanying upgrade- if any are required.

Alternatives

It's worth noting that this enumeration technique will work for the majority of SMTP configurations; however there are other, non-metasploit tools such as smtp-user-enum that work even better for enumerating OS-level user accounts on Solaris via the SMTP service. Enumeration is performed by inspecting the responses to VRFY, EXPN, and RCPT TO commands.

This technique could be adapted in future to work against other vulnerable SMTP daemons, but this hasn’t been done as of the time of writing. It's an alternative that's worth keeping in mind if you're trying to distance yourself from using Metasploit e.g. in preparation for OSCP.
~~~

### Enumerating SMTP - Questions
~~~
1. What port is SMTP running on? 25
2. What command do we use to do this? msfconsole
3. Let's search for the module "smtp_version", what's it's full module name? auxiliary/scanner/smtp/smtp_version 
4. Great, now- select the module and list the options. How do we do this? options
5. What is the option we need to set? RHOSTS
6. What's the system mail name? polosmtp.home
7. What Mail Transfer Agent (MTA) is running the SMTP server? postfix
8. what's it's full module name? auxiliary/scanner/smtp/smtp_enum 
9. What option do we need to set to the wordlist's path? USER_FILE
10.Once we've set this option, what is the other essential paramater we need to set? RHOSTS
11.What username is returned? administrator
~~~

### Exploiting SMTP
~~~
What do we know?

Okay, at the end of our Enumeration section we have a few vital pieces of information:

1. A user account name

2. The type of SMTP server and Operating System running.

We know from our port scan, that the only other open port on this machine is an SSH login. We're going to use this information to try and bruteforce the password of the SSH login for our user using Hydra.

Preparation

It's advisable that you exit Metasploit to continue the exploitation of this section of the room. Secondly, it's useful to keep a note of the information you gathered during the enumeration stage, to aid in the exploitation.

Hydra

There is a wide array of customisability when it comes to using Hydra, and it allows for adaptive password attacks against of many different services, including SSH. Hydra comes by default on both Parrot and Kali, however if you need it, you can find the GitHub here.

Hydra uses dictionary attacks primarily, both Kali Linux and Parrot OS have many different wordlists in the "/usr/share/wordlists" directory- if you'd like to browse and find a different wordlists to the widely used "rockyou.txt". Likewise I recommend checking out SecLists for a wider array of other wordlists that are extremely useful for all sorts of purposes, other than just password cracking. E.g. subdomain enumeration
The syntax for the command we're going to use to find the passwords is this:

"hydra -t 16 -l USERNAME -P /usr/share/wordlists/rockyou.txt -vV 10.10.251.85 ssh"

Let's break it down:

SECTION FUNCTION
hydra       Runs the hydra tool
-t 16       Number of parallel connections per target
-l [user]   Points to the user who's account you're trying to compromise
-P [path to dictionary] Points to the file containing the list of possible passwords
-vV         Sets verbose mode to very verbose, shows the login+pass combination for each attempt
[machine IP]    The IP address of the target machine
ssh / protocol  Sets the protocol
~~~

### Exploting SMTP - Questions
~~~
1. What is the password of the user we found during our enumeration stage? alejandro
2. WHat is contents of smtp.txt THM{who_knew_email_servers_were_c00l?}
~~~

## MySQL

### Understanding MySQL
~~~
What is MySQL?

In its simplest definition, MySQL is a relational database management system (RDBMS) based on Structured Query Language (SQL). Too many acronyms? Let's break it down:

Database:

A database is simply a persistent, organised collection of structured data

RDBMS:

A software or service used to create and manage databases based on a relational model. The word "relational" just means that the data stored in the dataset is organised as tables. Every table relates in some way to each other's "primary key" or other "key" factors.

SQL:

MYSQL is just a brand name for one of the most popular RDBMS software implementations. As we know, it uses a client-server model. But how do the client and server communicate? They use a language, specifically the Structured Query Language (SQL).

Many other products, such as PostgreSQL and Microsoft SQL server, have the word SQL in them. This similarly signifies that this is a product utilising the Structured Query Language syntax.

How does MySQL work?

MySQL, as an RDBMS, is made up of the server and utility programs that help in the administration of MySQL databases.

The server handles all database instructions like creating, editing, and accessing data. It takes and manages these requests and communicates using the MySQL protocol. This whole process can be broken down into these stages:

MySQL creates a database for storing and manipulating data, defining the relationship of each table.
Clients make requests by making specific statements in SQL.
The server will respond to the client with whatever information has been requested.
What runs MySQL?

MySQL can run on various platforms, whether it's Linux or windows. It is commonly used as a back end database for many prominent websites and forms an essential component of the LAMP stack, which includes: Linux, Apache, MySQL, and PHP.

More Information:

Here are some resources that explain the technical implementation, and working of, MySQL in more detail than I have covered here:

https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_SQL_EXECUTION.html 

https://www.w3schools.com/php/php_mysql_intro.asp
~~~

### Understanding MySQL - Questions
~~~
1. What type of software is MySQL? relational database management system
2. What language is MySQL based on? SQL
3. What communication model does MySQL use? 
4. What is a common application of MySQL?
5. What major social network uses MySQL as their back-end database?
~~~

### Enumerating MySQL
~~~
When you would begin attacking MySQL

MySQL is likely not going to be the first point of call when getting initial information about the server. You can, as we have in previous tasks, attempt to brute-force default account passwords if you really don't have any other information; however, in most CTF scenarios, this is unlikely to be the avenue you're meant to pursue.

The Scenario

Typically, you will have gained some initial credentials from enumerating other services that you can then use to enumerate and exploit the MySQL service. As this room focuses on exploiting and enumerating the network service, for the sake of the scenario, we're going to assume that you found the credentials: "root:password" while enumerating subdomains of a web server. After trying the login against SSH unsuccessfully, you decide to try it against MySQL.

Requirements

You will want to have MySQL installed on your system to connect to the remote MySQL server. In case this isn't already installed, you can install it using sudo apt install default-mysql-client. Don't worry- this won't install the server package on your system- just the client.

Again, we're going to be using Metasploit for this; it's important that you have Metasploit installed, as it is by default on both Kali Linux and Parrot OS.

Alternatives

As with the previous task, it's worth noting that everything we will be doing using Metasploit can also be done either manually or with a set of non-Metasploit tools such as nmap's mysql-enum script: https://nmap.org/nsedoc/scripts/mysql-enum.html or https://www.exploit-db.com/exploits/23081. I recommend that after you complete this room, you go back and attempt it manually to make sure you understand the process that is being used to display the information you acquire.
~~~

### Enumerating MySQL - Questions
~~~
1. What port is MySQL using? 3306
2. What three options do we need to set? password/RHOSTS/USERNAME
3. By default it will test with the "select version()" command, what result does this give you? 5.7.29-0ubuntu0.18.04.1
4. Change the "sql" option to "show databases". how many databases are returned? 4
~~~

### Exploting MySQL
~~~
What do we know?

Let's take a sanity check before moving on to try and exploit the database fully, and gain more sensitive information than just database names. We know:

1. MySQL server credentials

2. The version of MySQL running

3. The number of Databases, and their names.

Key Terminology

In order to understand the exploits we're going to use next- we need to understand a few key terms.

Schema:

In MySQL, physically, a schema is synonymous with a database. You can substitute the keyword "SCHEMA" instead of DATABASE in MySQL SQL syntax, for example using CREATE SCHEMA instead of CREATE DATABASE. It's important to understand this relationship because some other database products draw a distinction. For example, in the Oracle Database product, a schema represents only a part of a database: the tables and other objects owned by a single user.

Hashes:

Hashes are, very simply, the product of a cryptographic algorithm to turn a variable length input into a fixed length output.

In MySQL hashes can be used in different ways, for instance to index data into a hash table. Each hash has a unique ID that serves as a pointer to the original data. This creates an index that is significantly smaller than the original data, allowing the values to be searched and accessed more efficiently

However, the data we're going to be extracting are password hashes which are simply a way of storing passwords not in plaintext format.

Lets get cracking.
~~~

### Exploting MySQL - Questions
~~~
1. What's the module's full name? auxiliary/scanner/mysql/mysql_schemadump  
2. What's the name of the last table that gets dumped? x$waits_global_by_latency
3. What's the module's full name?
4. What non-default user stands out to you? carl
5. What is the user/hash combination string? carl:*EA031893AA21444B170FC2162A56978B8CEECE18
6. Use John the Ripper against it using: "john hash.txt" what is the password of the user we found? doogie
7. What's the contents of MySQL.txt THM{congratulations_you_got_the_mySQL_flag}
~~~

### Futher Reading
~~~
Here's some things that might be useful to read after completing this room, if it interests you:

 https://web.mit.edu/rhel-doc/4/RH-DOCS/rhel-sg-en-4/ch-exploits.html
 https://www.nextgov.com/cybersecurity/2019/10/nsa-warns-vulnerabilities-multiple-vpn-services/160456/

Thank you
~~~
