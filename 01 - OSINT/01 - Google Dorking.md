## Simple Dorking

Dorks allow you to filter out results from various search engines to identify potentially sensitive information 
Imagine you're hunting for internal emails, perhaps you could find a new starter form that a company has left exposed. This in turn may have their naming convention, numbers for internal helpdesks, and names to help pretext a social engineering campaign. Don't underestimate the dork!

```bash
# Find any public pages on linkedin.com with the word mcdonalds present
site:"linkedin.com" "mcdonalds"

# Find all .pdf files available publicly from mcdonalds.com
site:"mcdonalds.com" filetype:pdf

# Look for any pages with the words username and password that are excel documents
"password" and "username" filetype:xlsx
```