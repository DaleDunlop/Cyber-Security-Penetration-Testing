## Host Enumeration

Once on a host, you're now in enemy territory. Remember that every action you take has a potential to be noticed and caught. Whether this matters depends on the scope of your assessment. The idea of this phase is to ingest as much information as you can about the environment and learn what is possible, what isn't, what you may be able to chain together, etc. 

This may feel counter productive if you think you see an exploitable path, but so many times it has been useful to me to slow down, take note of everything in the area, make a checklist, before moving forward. You wouldn't try to break into a bank just because you saw a door open. You'd plan, take note of cameras, security, before moving on with your plan. Remember this when you land in a hostile network!

This section has information about enumerating a targets local properties. If you wish to enumerate in a domain context, please see the Domain Reconaissance file.

## Seatbelt

One of the most in-depth tools you can find and brilliant because it can be loaded into memory if you please, with the majority of C2s.

 https://github.com/GhostPack/Seatbelt 

To build simply open the .sln in Visual Studio, switch to release and hit build. The resulting .exe can be dropped to disk or loaded into memory. Far too many commands to list. Just use the very exhaustive instructions on the Github page. 

Bonus point: Seatbelt can be run remotely if you have adequate permissions over a target machine by invoking the `-computername=dc01` flag.

## Host Recon

Bit of an underrated tool in my opinion. Less heavily fingerprinted than others may be so has a lower detection level. Runs using PowerShell so it's a nice alternative to seatbelt albeit less in-depth.

 https://github.com/dafthack/HostRecon 

Running the tool without arguments will run the primary checks. This includes things such as the AV running, scheduled tasks, where the domain controllers are, etc.

```powershell
Invoke-HostRecon
```

## Native Commands

Whilst using tools is cool and gets the job done, let's not undervalue the power of built in commands to help perform some simple enumeration. This leaves less fingerprint on the target. Though as Rastamouse discusses [here](https://www.youtube.com/watch?v=qIbrozlf2wM&ab_channel=CyberV1s3r1on), sometimes even running native shell commands are enough to get caught in mature environments.

```powershell
# General System Info
systeminfo

# Installed Patches
wmic qfe get Caption,Description,HotFixID,InstalledOn

# View environment variables
dir env:

# Environment variables
Get-ChildItem Env: 

# User Enumeration
net user
net user Toby
net user Toby /domain # OPSEC - Queries the DC

# Group Enumeration
net localgroup
net localgroup Administrators
whoami /groups

# Privilege Enumeration
whoami /all

# Enumerate (local) password policy
net accounts

# Check if LSA Protection, WDigest, and Credential Guard are in use respectively
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags

# View running processes
tasklist # cmd
Get-Process # Powershell

# Enumerate file/folder permissions
icacls C:\Share\File.exe 

# Grant full permissions to another user/group. Here we grant the Management group full control over File.exe
icacls C:\Share\File.exe /grant Management:F /T /C

# Take ownership of a file provided you have sufficient rights
takeown /f C:\Share\File.exe

# Query scheduled tasks
schtasks 

# Query a specific scheduled task called "RunScript"
schtasks /query /tn RunScript /v /fo list

# List running services
sc query 
sc query UserDataSvc
Get-Service # Powershell

# Query a service's configuration 
sc qc svchost

# View DNS entries hardcoded
type C:\Windows\System32\drivers\etc\hosts

# View IP and network interface information
ipconfig /all

# Check shares on a local/remote PC
net share # Local
net view \\dc04.example.com /ALL # View shares on dc04.example.com
net view /all /domain example.com # View all shares on example.com domain
net use z: \\dc04.example.com\backups # Mount backups share from dc04.example.com locally (Type z: to enter it)
```

### Applocker Enumeration

This is a nice command to check for Applocker rules and actually be able to read the output!

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```