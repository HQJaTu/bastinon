# Spam reporter service
Systemd service for reporting received email as spam

## Bus-types
For docs, see: https://dbus.freedesktop.org/doc/dbus-python/tutorial.html#connecting-to-the-bus

* Per user _SessionBus_, `dbus-send --session`
* Global _SystemBus_, `dbus-send --system`

Note: On a request, default is `--session`.

## Install into `--system`
Policy install (as _root_):
1. Copy file `firewall-updater-dbus.conf` into directory `/etc/dbus-1/system.d/`
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
      string "fi.hqcodeshop.Firewall"
      ...
    ]
    ```
4. Verify published service details:
    ```bash
    busctl introspect fi.hqcodeshop.Firewall /fi/hqcodeshop/Firewall fi.hqcodeshop.Firewall
    ```
   Response will contain published interface:
    ```text
    NAME                 TYPE      SIGNATURE RESULT/VALUE FLAGS
    .Ping                method    -         s            -
    .ReportFile          method    s         s            -
    ```
5. Test service with a ping:
    ```bash
    dbus-send --print-reply \
      --system \
      --type=method_call \
      --dest=fi.hqcodeshop.Firewall \
      /fi/hqcodeshop/Firewall fi.hqcodeshop.Firewall.Ping
    ```
   Response will contain a greeting to the caller:
    ```text
    method return time=1647618215.603226 sender=:1.250 -> destination=:1.252 serial=6 reply_serial=2
       string "Hi Joe User in system-bus! pong"
    ```
6. Done!

## Test ping `--session`
When service is running, see if D-Bus works.

Run:
```bash
dbus-send \
  --print-reply \
  --type=method_call \
  --dest=fi.hqcodeshop.Firewall \
  /fi/hqcodeshop/Firewall fi.hqcodeshop.Firewall.Ping
```

Response (based on user who sent the ping):
```text
   string "Hi Joe Nobody! pong"
```

## Test query for all user's rules `--system`
Query for requested rules:

```bash
dbus-send \
  --system \
  --print-reply \
  --type=method_call \
  --dest=fi.hqcodeshop.Firewall \
  /fi/hqcodeshop/Firewall fi.hqcodeshop.Firewall.GetRules
```

## Test query for currently active firewall rules `--system`
Query for actual rules:

```bash
dbus-send \
  --system \
  --print-reply \
  --type=method_call \
  --dest=fi.hqcodeshop.Firewall \
  /fi/hqcodeshop/Firewall fi.hqcodeshop.Firewall.GetActiveRules "string:-FILENAME-HERE-"
```
