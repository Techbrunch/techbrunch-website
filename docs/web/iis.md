# IIS

> Microsoft IIS contains a flaw that may lead to an unauthorized information disclosure. The issue is triggered during the parsing of a request that contains a tilde character (\~). This may allow a remote attacker to gain access to file and folder name information.

```
brew install jenv
echo 'export PATH="$HOME/.jenv/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(jenv init -)"' >> ~/.zshrc
brew tap homebrew/cask-versions
jenv add $(/usr/libexec/java_home)
jenv add /Library/Java/JavaVirtualMachines/zulu-7.jdk/Contents/Home/
jenv version
jenv doctor
```

```
git clone https://github.com/irsdl/IIS-ShortName-Scanner
cd IIS-ShortName-Scanner
jenv local 1.7
java -jar iis_shortname_scanner.jar URL
```

{% embed url="https://github.com/irsdl/IIS-ShortName-Scanner" %}

{% embed url="https://www.youtube.com/watch?v=HrJW6Y9kHC4" %}

