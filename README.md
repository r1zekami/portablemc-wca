# portablemc-wca

It's fork of [mindstorm38/portablemc](https://github.com/mindstorm38/portablemc), and portablemc-wca stands for `portablemc with custom auth`. The main goal was to make the launcher compatible with custom Minecraft authentication servers (like [unmojang/drasl](https://github.com/unmojang/drasl)) using the Yggdrasil protocol, along with implementing some QoL improvements.

### Custom Yggdrasil Auth Server Support

To use a custom authentication server, specify it via the `--auth-server` flag:

```
--auth-server="https://your.auth.server/"
```

If specified, native `https://authserver.mojang.com/authenticate` will be changed to your `https://your.auth.server/auth/authenticate`, and the following Yggdrasil endpoints will be automatically passed to jvm-args:
```
-Dminecraft.api.env=custom 
-Dminecraft.api.auth.host=https://your.auth.server/auth 
-Dminecraft.api.account.host=https://your.auth.server/account 
-Dminecraft.api.session.host=https://your.auth.server/session 
-Dminecraft.api.services.host=https://your.auth.server/services
```
---
If your auth server (or reverse-proxy) uses self-signed certificates, this flag can be helpful:
```
--no-ssl-verify
```
**Important!** If you're using a self-signed certificate for your custom authentication server, you may encounter SSL trust issues when launching Minecraft with the new jvm-arg specified endpoints. This happens because Java does not trust your auth server certificate by default as it is self-signed.

To resolve this issue, you must manually add your auth server's certificate to the Java keystore used by the Minecraft client. For this, a new command is available:

```
python -m portablemc addcert --auth-server="https://your.authserver.com/" --jvm="path/to/java"
```

If the JVM path is not specified, default `.minecraft/jvm` will be chosen. Note that, in terms of security, it's better to use the default Java bundled with `.minecraft` directory. Also u may encounter problems to inject certificate to system java due to permission restrictions (If you really need it by some reasons, you can use `crt-inject.py` in `helpers` dir).

The new command generates a `trustedca` folder in the `.minecraft` directory, extracting the certificate from the auth server and saving it there. When any JVM launches, it injects the certificates from this folder into the JVM's keystore (for every JVM in `.minecraft/jvm`).

---

### Summary:

```
--auth-server="https://your.authserver.com/"
--no-ssl-verify
portablemc addcert --auth-server="https://your.authserver.com/"
```

**Usage example:**

```
python -m portablemc addcert --auth-server="https://your.auth.server/"

python -m portablemc login YourLogin --auth-service=yggdrasil --auth-server="https://your.auth.server/" --no-ssl-verify

python -m portablemc start fabric:1.21.6 -l YourLogin --auth-service="yggdrasil" --auth-server="https://your.auth.server/" --no-ssl-verify
```


