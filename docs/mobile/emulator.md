# Emulator

```
cd ${ANDROID_HOME}/emulator
./emulator -list-avds
./emulator -avd $(./emulator -list-avds) -writable-system
```

### Modifying system files

```
cd ${ANDROID_HOME}/tools
adb root
adb remount
adb pull /system/etc/hosts ~/Downloads/hosts
echo '192.168.0.17 www.test.com' >> ~/Downloads/hosts
adb push ~/Downloads/hosts /system/etc/hosts
adb reboot
```

!!! warning
    The host file might be in a [different location](https://stackoverflow.com/a/47622017)

Source: [https://medium.com/code-procedure-and-rants/use-modified-hosts-file-on-android-emulator-4f29f5d12ac1](https://medium.com/code-procedure-and-rants/use-modified-hosts-file-on-android-emulator-4f29f5d12ac1)
