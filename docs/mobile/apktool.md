# Apktool

### Install

```
brew install apktool
```

### Update

```
brew upgrade apktool
```

### Decode

```
apktool decode base.apk
```

### Build

```
apktool build base -o base.apk
keytool -genkey -v -keystore my-release-key.keystore -alias alias_name \
                   -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore base.apk alias_name
jarsigner -verify -verbose -certs base.apk
zipalign -v 4 base.apk base-aligned.apk
```
