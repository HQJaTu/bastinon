# Spam reporter service
Systemd service for reporting received email as spam

## Bus-types
For docs, see: https://dbus.freedesktop.org/doc/dbus-python/tutorial.html#connecting-to-the-bus

* Per user _SessionBus_, `dbus-send --session`
* Global _SystemBus_, `dbus-send --system`

Note: On a request, default is `--session`.

## Install into `--system`
Policy install (as _root_):
1. Copy file `bastinon-dbus.conf` into directory `/etc/dbus-1/system.d/`
2. Make policy change effective: `systemctl reload dbus`
3. List available services:
    ```bash
    dbus-send \
      --system \
      --print-reply \
      --type=method_call \
      --dest=org.freedesktop.DBus \
      /org/freedesktop/DBus org.freedesktop.DBus.ListNames
    ```
   Response will contain published interface:
    ```text
    method return time=123.456 sender=org.freedesktop.DBus -> destination=:1.1234 serial=3 reply_serial=2
    array [
      string "org.freedesktop.DBus"
      string "fi.hqcodeshop.Bastinon"
      ...
    ]
    ```
4. Verify published service details:
    ```bash
    busctl introspect fi.hqcodeshop.Bastinon /fi/hqcodeshop/Bastinon fi.hqcodeshop.Bastinon
    ```
   Response will contain published interface:
    ```text
   NAME                   TYPE      SIGNATURE RESULT/VALUE FLAGS
   .DeleteRule            method    ss        -            -
   .FirewallUpdate        method    -         -            -
   .FirewallUpdatesNeeded method    -         b            -
   .GetProtocols          method    -         as           -
   .GetRules              method    s         a(ssssvvb)   -
   .GetServices           method    -         a(ss)        -
   .Ping                  method    -         s            -
   .UpsertRule            method    ssssvv    s            -
    ```
5. Test service with a ping:
    ```bash
    dbus-send --print-reply \
      --system \
      --type=method_call \
      --dest=fi.hqcodeshop.Bastinon \
      /fi/hqcodeshop/Bastinon fi.hqcodeshop.Bastinon.Ping
    ```
   Response will contain a greeting to the caller:
    ```text
    method return time=1647618215.603226 sender=:1.250 -> destination=:1.252 serial=6 reply_serial=2
       string "Hi in system-bus! pong"
    ```
6. Done!

## Test query for user's rules `--system`
Query for rules of user _nobody_:

```bash
dbus-send \
  --system \
  --print-reply \
  --type=method_call \
  --dest=fi.hqcodeshop.Bastinon \
  /fi/hqcodeshop/Bastinon fi.hqcodeshop.Bastinon.GetRules string:nobody
```

## Test query for currently active firewall rules `--system`
Query for configured networking services:

```bash
dbus-send \
  --system \
  --print-reply \
  --type=method_call \
  --dest=fi.hqcodeshop.Bastinon \
  /fi/hqcodeshop/Bastinon fi.hqcodeshop.Bastinon.GetServices
```

Will return your configured services available for users. Example:
```text
   array [
      string "dns"
      string "smtp"
      string "ssh"
      string "imaps"
      string "ftp"
   ]
```

## Troubleshooting
Monitor with a watch:

```bash
dbus-monitor \
  --system \
  "type=method_call,interface=fi.hqcodeshop.Bastinon" \
  "type=signal,interface=fi.hqcodeshop.Bastinon" \
  "type=error"
```


# SElinux

See subdirectory `SElinux/` for details.

## Test run service

* Use SElinux-tool `runcon`. Set _system_u:system_r:bastinon_t:s0_ as security context.

```bash
runcon system_u:system_r:bastinon_t:s0 \
  /usr/libexec/bastinon/bin/python \
  /usr/libexec/bastinon/bin/bastinon-service.py \
  system
```

* [runcon(1) - Linux man page](https://linux.die.net/man/1/runcon)

## Temporarily disable all don't audit -rules

```bash
semodule -DB
```

Now all possible deny-rules are logged and can be traced with `audit2allow`.
