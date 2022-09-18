# Objection

### Update

```
pip3 install -U objection
```

### Patching an APK

```
objection patchapk --source app-release.apk
```

{% hint style="warning" %}
You might need to use the flag `--skip-resources` if there is an error while rebuilding the APK.
{% endhint %}

### Explore APK

First you will need to [start the Frida server](https://techbrunch.gitbook.io/workspace/mobile/frida#starting-frida-server) (either you patched the APK to run Frida when starting or you previously started the Frida's server).

```
objection -g com.package.package explore
```

### Disable SSL Pinning

```
android sslpinning disable
```

### Early Instrumentation

```
objection explore --startup-command 'android sslpinning disable'
objection explore --startup-script ssl-pinning.js
```

### List activities

```
android hooking list activities com.package.package
```

### List classes

```
android hooking list classes
```

### Simple hooks for each Class method

```
android hooking generate simple <class name>
```

### Launch Activity

```
android intent launch_activity com.package.package.class.NameActivity
```

### Hook return\_value

```
android hooking set return_value com.package.package.paywall.PayWallStorageImpl.retrievePayWallIsOp
en true
```

### Making a patch permanent

```
objection patchapk -s UnCrackable-Level1.apk -c gadget -l root.js
```

{% tabs %}
{% tab title="gadget" %}
{% code title="gadget" %}
```javascript
{
  "interaction": {
    "type": "script",
    "path": "libfrida-gadget.script.so"
  }
}
```
{% endcode %}
{% endtab %}

{% tab title="root.js" %}
{% code title="root.js" %}
```javascript
Java.perform(function() {
    var c = Java.use("sg.vantagepoint.a.c");
    c.a.implementation = function(v) { return false; }
    c.b.implementation = function(v) { return false; }
    c.c.implementation = function(v) { return false; }
})
```
{% endcode %}
{% endtab %}
{% endtabs %}

