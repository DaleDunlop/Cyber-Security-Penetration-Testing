## General Hashcat Usage

This section is unfinished at the moment. 

Find your hash type using the hashcat.net example hashes page:

 https://hashcat.net/wiki/doku.php?id=example_hashes 

Bonus tip: Latest versions of hashcat support automatic hash detection! 

🚩 This may not always work, so be vigilant it is correctly fingerprinting it correctly! 🚩

### Basic Usage

```powershell
# Crack an md5 hash stored in hash.txt with rockyou.txt and use the rules file onerule.rule
hashcat.exe -m 0 -a 0 hash.txt rockyou.txt --rules onerule.rule
```