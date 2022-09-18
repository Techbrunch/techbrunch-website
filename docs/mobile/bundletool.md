---
description: https://github.com/google/bundletool
---

# Bundletool

```
brew install bundletool
bundletool build-apks \
--bundle=app.aab \
--output=app.apks \
--connected-device
bundletool install-apks --apks=app.apks
```

{% hint style="warning" %}
You will need to have a debug keystore available !
{% endhint %}

### Generating a debug keystore

```
keytool \
-genkey \
-v \
-keystore debug.keystore \
-storepass android \
-alias androiddebugkey \
-keypass android \
-keyalg RSA \
-keysize 2048 \
-validity 10000
```

Source: [https://coderwall.com/p/r09hoq/android-generate-release-debug-keystores](https://coderwall.com/p/r09hoq/android-generate-release-debug-keystores)
