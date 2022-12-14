## Kerberoasting

For an overview of how Kerberos works, please check out my blog:

 https://heartburn.dev/kerberos-fundamentals/ 

Services typically run locally as service accounts or from domain service accounts. An SPN (Service Principal Name) is applied to an account running a service so that it can be identified as a "service" account" by the KDC. The secret key for this account is then used for encrypting a TGS (Ticket Granting Service) when a user has requested access. Rather than presenting the ticket to the service after obtaining it, the user takes the ticket offline and attempts to crack it - Similar to ASRep Roasting but instead with a TGS rather than a TGT. 

Sometimes, these service account passwords are weak, and therefore allow a user to compromise them. Service accounts typically run with higher privileges, too, such as SeImpersonate, so generally compromising a service account leads to full control of that server. 

In certain situations, user accounts are also configured to run services, thus making them Kerberoastable when querying for SPNs.

### Kerberoasting On Linux

If it ain't broke, don't fix it! Impacket's GetUserSPNs tool works a dream for requesting service tickets once you have valid credentails.

```bash
GetUserSPNs.py MATRIX.LOCAL/Neo:Passw0rd -dc-ip 10.10.10.10 -request
```

### Kerberoasting On Windows
If on the target already, Rubeus can be used to request the hash of all the accounts associated with an SPN. 

🚩 However, there is OPSEC concerns for querying the whole network. There may be honeypot accounts running to catch this, or an excessive number of 4769 event IDs may trigger an alert! 🚩

```powershell
\rubeus.exe kerberoast /simple /nowrap
```

A better idea may be to identify users with SPN's set, review them, and then Kerberoast the ones you believe are legitimate service accounts.

```powershell
Get-NetUser | select samaccountname,serviceprincipalname
```

Once a user has been identified, use Rubeus again to perform the Kerberoast.

```powershell
\Rubeus.exe kerberoast /user:svc_web /nowrap

# Crack with hashcat
hashcat -a 0 -m 13100 svc_web.hash rockyou.txt --rules onerule.rule
```

### Group Managed Service Accounts

One of the best ways to defend against Kerberoasting is to use GMSA (Group Managed Service Accounts). This allows strong passwords to be set and periodically changed automatically. If you compromise a user with the `GMSAPasswordReader` ACE, we can use the following tool to obtain the hashes for the GMSA.

 https://github.com/rvazarkar/GMSAPasswordReader 

```powershell
.\GMSAPasswordReader.exe --accountname SVC_MATRIX
```
