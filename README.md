# BastiNon
Non-bastion bastion.

Set of tools to remotely update local firewall rules to replace a "jump server" with
secure and controllable direct access.

## Info
Firewalld documentation: https://firewalld.org/documentation/man-pages/firewalld.service.html

# Commands

## bastinon-cmd

Command-line interface to non-bastion rules.

```bash
usage: bastinon-cmd.py [-h] [--user USER] [--log-level LOG_LEVEL] [--stateful] [--force]
                       [--add-rule-user ADD_RULE_USER] [--rule-service RULE_SERVICE]
                       [--rule-source-address RULE_SOURCE_ADDRESS]
                       [--rule-comment RULE_COMMENT]
                       RULE-PATH

Firewall Updates daemon

positional arguments:
  RULE-PATH             User's firewall rules base directory

optional arguments:
  -h, --help            show this help message and exit
  --user USER           (optional) Update rules for single user
  --log-level LOG_LEVEL
                        Set logging level. Python default is: WARNING
  --stateful, --non-stateful
                        Do not use stateful TCP firewall. Default: use stateful
  --force               Force firewall update
  --add-rule-user ADD_RULE_USER
                        Add new firewall rule to user
  --rule-service RULE_SERVICE
                        Service for a rule
  --rule-source-address RULE_SOURCE_ADDRESS
                        Source address for a rule
  --rule-comment RULE_COMMENT
                        Comment for a rule
```

## bastinon-service

In any typical use-case, there is no need to run service from command-line.
This is mostly run via Systemd-service.

```bash
usage: bastinon-service.py [-h] [--watchdog-time WATCHDOG_TIME] [--stateful]
                           [--log-level LOG_LEVEL]
                           BUS-TYPE-TO-USE RULE-PATH

Firewall Updates daemon

positional arguments:
  BUS-TYPE-TO-USE       D-bus type to use. Choices: system, session
  RULE-PATH             User's firewall rules base directory

optional arguments:
  -h, --help            show this help message and exit
  --watchdog-time WATCHDOG_TIME
                        How often systemd watchdog is notified. Default: 5 seconds
  --stateful, --non-stateful
                        Do not use stateful TCP firewall. Default: use stateful
  --log-level LOG_LEVEL
                        Set logging level. Python default is: WARNING
```
