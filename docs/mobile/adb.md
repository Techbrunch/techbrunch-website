# ADB

### Install ADB

```
 brew install android-platform-tools
```

### Install APK

```
adb install name.apk
```

### Push file

```
adb push /path/from /path/to
```

### Shell

```
adb shell
```

### Pulling an App with ADB

```
adb shell pm list packages
adb shell pm path com.xxx.xxx
adb pull /path/to/app.apk
```

### Changing proxy settings

```
adb shell settings put global http_proxy <address>:<port>
```

#### Deleting the settings

```
adb shell settings delete global http_proxy
adb shell settings delete global global_http_proxy_host
adb shell settings delete global global_http_proxy_port
adb reboot
```

#### Add Burp certificate as a system certificate

```
openssl x509 -inform DER -in cacert.der -out cacert.pem  
openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1  
mv cacert.pem <hash>.0
adb push 9a5ba575.0 /sdcard
adb shell
su
mount -o rw,remount /system
mv /sdcard/9a5ba575.0 /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/9a5ba575.0
```

Source: [https://0x00sec.org/t/reversing-hackex-an-android-game/16243](https://0x00sec.org/t/reversing-hackex-an-android-game/16243)

!!! warning
    I ran into the error `mount: '/system' not in /proc/mounts` (Nexus 6 API 28) and I fixed it by mounting the root (/) instead. Source: [adb remount fails - mount: 'system' not in /proc/mounts](https://stackoverflow.com/questions/55030788/adb-remount-fails-mount-system-not-in-proc-mounts). You migth have to start the emulator with [-writable-system](emulator.md).

### Enable debugging

You’ll need to edit the `AndroidManifest.xml` generated file, adding the`android:debuggable="true"` attribute to its `application` XML node:

```
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.company.appname" 
                                                                     platformBuildVersionCode="24" 
                                                                     platformBuildVersionName="7.0">
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.INTERNET"/>

    <application android:allowBackup="true" android:icon="@mipmap/ic_launcher" 
        android:label="@string/app_name" 
        android:supportsRtl="true" 
        android:theme="@style/AppTheme"
        android:debuggable="true"> <-- !!! NOTICE ME !!! -->

        <activity android:name="com.company.appname.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
    
</manifest>
```

### Screen recording

```
adb shell screenrecord /sdcard/video.mp4
adb pull /sdcard/video.mp4
adb shell rm /sdcard/video.mp4
```

### Screenshot

```
adb exec-out screencap -p > screenshot.png
```

### Install xapk

Unzip then:

```
adb install-multiple *.apk
```
