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
from typing import Union, Tuple
from dbus import (SessionBus, SystemBus, service, mainloop)
from pwd import getpwuid
from ..base.firewall_base import FirewallBase
from ..rules import RuleReader
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

    def _get_user_info(self) -> Tuple[int, str]:
        unix_user_id = self.connection.get_unix_user(FIREWALL_UPDATER_SERVICE_BUS_NAME)
        unix_user_passwd_record = getpwuid(unix_user_id)
        if unix_user_passwd_record:
            user = unix_user_passwd_record.pw_name
            if unix_user_passwd_record.pw_gecos:
                gecos = unix_user_passwd_record.pw_gecos.split(',')
                if gecos[0]:
                    user = gecos[0]
        else:
            user = None

        return unix_user_id, user

    # noinspection PyPep8Naming
    @service.method(dbus_interface=FIREWALL_UPDATER_SERVICE_BUS_NAME,
                    in_signature=None, out_signature="s")
    def Ping(self):
        """
        Method docs:
        https://dbus.freedesktop.org/doc/dbus-python/dbus.service.html?highlight=method#dbus.service.method
        Signature docs:
        https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types
        Source code:
        https://github.com/freedesktop/dbus-python/blob/master/dbus/service.py
        :return: str
        """
        log.info("ping received")

        # Get a BusConnection-object of this call and query for more details.
        if self.connection._bus_type == 0:
            bus_type = "session"
        elif self.connection._bus_type == 1:
            bus_type = "system"
        else:
            bus_type = "unknown"

        # Get details of user ID making the request
        user_id, user_name = self._get_user_info()
        if user_name:
            greeting = "Hi {}".format(user_name)
        else:
            greeting = "Hi"
        greeting = "{} in {}-bus! pong".format(greeting, bus_type)

        return greeting

    # noinspection PyPep8Naming
    @service.method(dbus_interface=FIREWALL_UPDATER_SERVICE_BUS_NAME,
                    in_signature="s", out_signature="as")
    def GetRules(self, user: str) -> list:
        """
        Method docs:
        https://dbus.freedesktop.org/doc/dbus-python/dbus.service.html?highlight=method#dbus.service.method
        Signature docs:
        https://dbus.freedesktop.org/doc/dbus-specification.html#basic-types
        :param user, str, optional user to limit firewall rules into
        :return: list of str, firewall rules
        """

        reader = RuleReader(self._firewall_rules_path)
        rules = reader.read_all_users()

        # Test the newly read rules
        rules_4, rules_6 = self._firewall.simulate(rules, print_rules=False)
        rules_out = rules_4 + rules_6

        log.info("Returning list of {} firewall rules".format(len(rules_out)))

        return rules_out
