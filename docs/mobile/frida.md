# Frida

### Update Frida Tools (CLI)

```
pip install -U frida-tools
```

### Add Frida to device

Download from: [https://github.com/frida/frida/releases](https://github.com/frida/frida/releases)

```
unxz frida-server-12.X.X-android-x86.xz
adb push frida-server-12.X.X-android-x86 /data/local/tmp
```

!!! warning
     On a real device you will need to get the `android-arm` version

### Starting Frida Server

```
adb root
adb shell
cd /data/local/tmp
./frida-server-12.X.X-android-x86 &
```

### Disable SSL pinning

```
frida -U --codeshare sowdust/universal-android-ssl-pinning-bypass-2 --no-paus -f com.name.name
```

### Hooking a Function

```
frida -U -l crack.js --no-paus -f com.package.package
```

```javascript title="crack.js"
Java.perform(function() {
    theClass = Java.use("com.package.package.paywall.PayWallStorageImpl");
    theClass.retrievePayWallIsOpen.implementation = function(v) {
        return true;
    }
})
```
