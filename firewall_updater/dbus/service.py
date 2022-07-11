# -*- coding: utf-8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

# This file is part of Firewall Updater library and tool.
# Firewall Updater is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (c) Jari Turkia

import os
from typing import Union, Tuple, List
from dbus import (SessionBus, SystemBus, service, mainloop)
from pwd import getpwuid, getpwnam
from datetime import datetime
from ..base.firewall_base import FirewallBase
from ..rules import RuleReader, ServiceReader, UserRule
import logging

log = logging.getLogger(__name__)

# Docs:
# https://dbus.freedesktop.org/doc/dbus-tutorial.html#bus-names
FIREWALL_UPDATER_SERVICE_BUS_NAME = "fi.hqcodeshop.Firewall"


class FirewallUpdaterService(service.Object):
    SPAM_REPORTER_SERVICE = FIREWALL_UPDATER_SERVICE_BUS_NAME.split('.')
    OPATH = "/" + "/".join(SPAM_REPORTER_SERVICE)

    def __init__(self, use_system_bus: bool,
                 loop: mainloop.NativeMainLoop,
                 firewall: FirewallBase,
                 firewall_rules_path: str):
        # Which bus to use for publishing?
        self._use_system_bus = use_system_bus
        if use_system_bus:
            # Global, system wide
            bus = SystemBus(mainloop=loop)
            log.debug("Using SystemBus for interface {}".format(FIREWALL_UPDATER_SERVICE_BUS_NAME))
        else:
            # User's own
            bus = SessionBus(mainloop=loop)
            log.debug("Using SessionBus for interface {}".format(FIREWALL_UPDATER_SERVICE_BUS_NAME))

        bus.request_name(FIREWALL_UPDATER_SERVICE_BUS_NAME)
        bus_name = service.BusName(FIREWALL_UPDATER_SERVICE_BUS_NAME, bus=bus)
        service.Object.__init__(self, bus_name, self.OPATH)

        self._loop = loop
        self._firewall = firewall
        self._firewall_rules_path = firewall_rules_path

    def _get_creds(self, bus_name: str):
        # See: https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-get-connection-credentials
        from _dbus_bindings import BUS_DAEMON_IFACE, BUS_DAEMON_NAME, BUS_DAEMON_PATH
        response = self.connection.call_blocking(BUS_DAEMON_NAME, BUS_DAEMON_PATH,
                                                 BUS_DAEMON_IFACE, 'GetConnectionCredentials',
                                                 's', (bus_name,))
        from pprint import pprint
        # ProcessID, UnixUserID, LinuxSecurityLabel
        pprint(response.keys())
        if 'LinuxSecurityLabel' in response:
            # linux_security_label = response['LinuxSecurityLabel'].decode('utf-8')
            linux_security_label = bytes(response['LinuxSecurityLabel']).decode('utf-8')
            pprint(linux_security_label)
        else:
            log.error("Nope")

        raise NotImplementedError()

    def _get_user_info(self, user: str) -> Tuple[int, str, str]:
        # Docs: https://dbus.freedesktop.org/doc/dbus-python/dbus.bus.html#dbus.bus.BusConnection.get_unix_user
        # "Get the numeric uid of the process owning the given bus name."
        # unix_user_id = self.connection.get_unix_user(FIREWALL_UPDATER_SERVICE_BUS_NAME)
        # Docs: https://dbus.freedesktop.org/doc/dbus-python/dbus.bus.html?highlight=get_peer_unix_user#dbus.bus.BusConnection.get_peer_unix_user
        # "Get the UNIX user ID at the other end of the connection, if it has been authenticated.
        #  Return None if this is a non-UNIX platform or the connection has not been authenticated."

        # is_authenticated = self.connection.get_is_authenticated()
        # process_id = self.connection.get_peer_unix_process_id()
        # unix_user_id = self.connection.get_peer_unix_user()

        unix_user_passwd_record = getpwnam(user)
        if unix_user_passwd_record:
            user_id = unix_user_passwd_record.pw_uid
            user_login = unix_user_passwd_record.pw_name
            user_full_name = unix_user_passwd_record.pw_name
            if unix_user_passwd_record.pw_gecos:
                gecos = unix_user_passwd_record.pw_gecos.split(',')
                if gecos:
                    user_full_name = gecos
        else:
            user_id = None
            user_login = None
            user_full_name = None

        return user_id, user_login, user_full_name

    # noinspection PyPep8Naming
    @service.method(dbus_interface=FIREWALL_UPDATER_SERVICE_BUS_NAME,
                    in_signature=None, out_signature="s",
                    sender_keyword='sender')
    def Ping(self, sender=None):
        """
        Method docs:
        https://dbus.freedesktop.org/doc/dbus-python/dbus.service.html?highlight=method#dbus.service.method
        Signature docs:
        https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types
        Source code:
        https://github.com/freedesktop/dbus-python/blob/master/dbus/service.py
        :return: str
        """
        log.debug("ping received from sender: {}".format(sender))

        # Get a BusConnection-object of this call and query for more details.
        if self.connection._bus_type == 0:
            bus_type = "session"
        elif self.connection._bus_type == 1:
            bus_type = "system"
        else:
            bus_type = "unknown"

        if False:
            # Get details of user ID making the request
            user_id, user_name = self._get_user_info()
            if user_name:
                greeting = "Hi {}".format(user_name)
            else:
                greeting = "Hi"
            greeting = "{} in {}-bus! pong".format(greeting, bus_type)
        greeting = "Hi in {}-bus! pong".format(bus_type)

        return greeting

    # noinspection PyPep8Naming
    @service.method(dbus_interface=FIREWALL_UPDATER_SERVICE_BUS_NAME,
                    in_signature=None, out_signature="as",
                    sender_keyword='sender')
    def GetServices(self, sender=None) -> list:
        reader = ServiceReader(self._firewall_rules_path)
        services = reader.read_all()

        # Test the newly read rules
        services_out = [str(out) for out in services]

        log.info("GetServices(): Returning list of {} firewall services".format(len(services_out)))

        return services_out

    # noinspection PyPep8Naming
    @service.method(dbus_interface=FIREWALL_UPDATER_SERVICE_BUS_NAME,
                    in_signature=None, out_signature="as",
                    sender_keyword='sender')
    def GetProtocols(self, sender=None) -> list:
        # This is just for UI. Return supported TCP-protocols.
        reader = ServiceReader(self._firewall_rules_path)

        log.info("GetProtocols(): Returning list of {} TCP-protocols".format(len(reader.PROTOCOLS)))

        return reader.PROTOCOLS

    # noinspection PyPep8Naming
    @service.method(dbus_interface=FIREWALL_UPDATER_SERVICE_BUS_NAME,
                    in_signature="s", out_signature="a(sssisvvb)",
                    sender_keyword='sender')
    def GetRules(self, user: str, sender=None) -> List[
        Tuple[str, str, str, int, str, Union[str, None], Union[str, None], bool]
    ]:
        """
        Method docs:
        https://dbus.freedesktop.org/doc/dbus-python/dbus.service.html?highlight=method#dbus.service.method
        Signature docs:
        https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types
        :param user, str, optional user to limit firewall rules into
        :return: list of str, firewall saved rules
        """

        # Get details of user ID making the request
        if user:
            user_id, user_login, user_full_name = self._get_user_info(user)
        else:
            user_id, user_login, user_full_name = (None, '-all-', 'All Users')

        reader = RuleReader(self._firewall_rules_path)
        rules = reader.read_all_users()
        active_rules = self._firewall.query(rules)

        def _rule_tuple_helper(r: Tuple[UserRule, bool]) -> tuple:
            # Notes:
            # - Source address will be converted into a string
            # - Comment is either str or bool, D-Bus cannot return None
            # - Expiry is either str or bool, D-Bus cannot return None

            rule_hash = self._rule_hash(r[0])
            source = str(r.source)
            if r.comment:
                comment = r.comment
            else:
                comment = False
            if r.expiry:
                # ISO 8601: https://tc39.es/ecma262/#sec-date-time-string-format
                # YYYY-MM-DDTHH:mm:ss.sssZ
                expiry = r.expiry.isoformat()
            else:
                expiry = False

            return rule_hash, r.owner, r.proto, r.port, source, comment, expiry, r[1]

        # Rules
        rules_out = []
        if user:
            # rules_out = [r for r in active_rules if r == user]
            #           user,prot,port,src, comment,          expiry,   active
            # r = Tuple[str, str, int, str, Union[str, None], datetime, bool]
            for r in active_rules:
                if r.owner != user:
                    continue
                rule = _rule_tuple_helper(r)
                rules_out.append(rule)
        else:
            # rules_out = active_rules
            for r in active_rules:
                rule = _rule_tuple_helper(r)
                rules_out.append(rule)

        log.info(
            "GetRules({}) [{}]: Returning list of {} firewall rules".format(user_login, user_full_name, len(rules_out)))

        return rules_out

    # noinspection PyPep8Naming
    @service.method(dbus_interface=FIREWALL_UPDATER_SERVICE_BUS_NAME,
                    in_signature="sssisvv", out_signature="s",
                    sender_keyword='sender')
    def UpsertRule(self,
                   existing_rule_hash: str,
                   user: str,
                   proto: str,
                   port: int,
                   source: str,
                   comment: str,
                   expiry: str,
                   sender=None) -> str:
        """
        Update or insert a rule
        :param existing_rule_hash: hash for existing rule, empty string if inserting
        :param user: whose rules we're inserting
        :param proto: protocol
        :param port: port
        :param source: source address
        :param comment: optional comment
        :param expiry: optional rule expiry
        :param sender: D-Bus sender connection
        :return: str, hash of inserted/updated rule
        """
        pass

    # noinspection PyPep8Naming
    @service.method(dbus_interface=FIREWALL_UPDATER_SERVICE_BUS_NAME,
                    in_signature="ss", out_signature=None,
                    sender_keyword='sender')
    def DeleteRule(self,
                   existing_rule_hash: str,
                   user: str,
                   sender=None) -> None:
        """
        Delete existing rule
        :param existing_rule_hash: hash for existing rule
        :param user: whose rules we're inserting
        :param sender: D-Bus sender connection
        :return: str, hash of inserted/updated rule
        """
        pass

    @staticmethod
    def _rule_hash(r: UserRule) -> str:
        """
        Hash of UserRule as a string
        :param r: rule to be hashed
        :return: string
        """

        # 64-bit unsigned integer as hex, hash() returns signed. Skip 0x at the beginning.
        r_tuple = (r.owner, r.proto, r.port, r.source, r.comment, r.expiry)
        rule_hash = hex(hash(r_tuple) & 0xffffffffffffffff)[2:]

        return rule_hash
