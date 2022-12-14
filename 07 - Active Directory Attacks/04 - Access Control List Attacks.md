## Access Control List Attacks (ACLs)

Within Active Directory, users and groups have their permissions restricted based on ACLs. ACLs contain ACEs, Access Control Entities, which stipulate what permissions and rights they have over other users and computers in the domain. For example, support users may have the "ForceChangePassword" ACE applied to them which allows them to change users passwords in the domain. Sometimes, these are overly permissive or straight up misconfigured, meaning you can abuse them for lateral movement or privilege escalation.

Honestly, Bloodhound is the 👑 for this. It's actually hard to look past it, so if you're able to use that, I'd recommend it. However, I'll go over using Powerview modules to get a general idea and then some manual commands using Powerview as well.

 https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 

Here is a great resource on attacking ACLs when you find some that you might be able to abuse

 https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces 

Typically, we're looking for anything that resembles GenericAll, WriteProperty, WriteDacl, ForceChangePassword, AllExtendedRights... And more!

### Using Built-in Enumeration Modules

🚩 REMEMBER: These will always be more noisy than doing things with manual queries. 🚩

```powershell
Invoke-ACLScanner
Find-InterestingDomainAcl -Domain matrix.local -ResolveGUIDs
```

### Manual ACL Enumeration

```powershell
# Query all security identifiers who have GenericAll, WriteProperty or WriteDacl over Neo
Get-DomainObjectAcl -Identity Neo | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-3263068140-2042698922-2891547269-[\d]{4,10}" } | select SecurityIdentifier, ActiveDirectoryRights | fl

# Find all users in the Users OU that have GenericAll, WriteProperty or WriteDacl
Get-DomainObjectAcl -SearchBase "CN=Users,DC=MATRIX,DC=local" | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-3263068140-2042698922-2891547269-[\d]{4,10}" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl

# Find users who have ACLs that affect the user Neo
Get-ObjectAcl -Identity Neo -ResolveGUIDs | ForEach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-Sid $_.SecurityIdentifier.value) -Force; $_} | more 
```