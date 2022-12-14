## DNS Queries

- Using dig
```bash
# Truncated output
dig example.com +short

# Full output
dig example.com 

# Query for Mail Exchange Servers
dig example.com MX

# Query all DNS records
dig example.com ANY +noall +answer

# Attempt a zone transfer from www. subdomain to the main domain
dig @www.example.com example.com axfr 
```

- Perform a whois request
```bash
whois 10.10.10.10
```

- Using nslookup to find host information
```bash
# Attempt to resolve hostname by IP
nslookup 75.126.153.206

# Attempt to resolve IP via hostname
nslookup example.com
```

## DNS Spoofing

DNS spoofing can occur due to weak configurations in the SPF and DMARC records.
https://github.com/BishopFox/spoofcheck
```bash
./spoofcheck.py example.com
```