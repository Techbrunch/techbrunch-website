# Patching Smali

Patching the method retrievePaywallIsOpen to always return true (`0x1`)

### Before

```smali
.method public retrievePayWallIsOpen()Z
    .locals 3

    .line 12
    iget-object v0, p0, Lcom/xxx/xxx/paywall/PayWallStorageImpl;->sharedPreferences:Landroid/content/SharedPreferences;

    const-string v1, "pay_wall_is_open"

    const/4 v2, 0x0

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v0

    return v0
.end method
```

### After

```smali
.method public retrievePayWallIsOpen()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method
```
