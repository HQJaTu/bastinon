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

import subprocess
import shutil
from typing import Tuple, Optional, Union
import ipaddress
from .base import FirewallBase
import logging

log = logging.getLogger(__name__)


class Iptables(FirewallBase):
    PROTO_TCP = r"tcp"
    PROTO_UDP = r"udp"
    PROTOS = [PROTO_TCP, PROTO_UDP]

    def __init__(self, chain_name: str):
        if not chain_name:
            raise ValueError("Need valid IPtables chain name!")
        self._chain = chain_name
        self._iptables_cmd = shutil.which("iptables")
        if not self._iptables_cmd:
            raise ValueError("Cannot find exact location of iptables-command! Failing to continue.")
        self._ip6tables_cmd = shutil.which("ip6tables")

    def query(self) -> list:
        raise NotImplementedError("Get IPtables rules not implemented yet!")

    def set(self, rules: list) -> list:
        raise NotImplementedError("Set IPtables rules not implemented yet!")

    def simulate(self, rules: list) -> list:
        rules_out = []
        print("IPv4 rules:")
        for rule in rules:
            rule_out = self._rule_to_ipchain(4, rule)
            if rule_out:
                rule_str = ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)
                print(rule_str)

        print("IPv6 rules:")
        for rule in rules:
            rule_out = self._rule_to_ipchain(6, rule)
            if rule_out:
                rule_str = ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)
                print(rule_str)

    def _clear_chain(self):
        return
        p = subprocess.Popen(
            [self._iptables_cmd, "-A", self._chain, "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"],
            stdout=subprocess.PIPE)
        output, err = p.communicate()

    def _rule_to_ipchain(self, proto_ver: int, rule: Tuple[str, int, str]) -> Union[list, None]:
        proto = rule[0]
        port = rule[1]
        source = rule[2]

        # Sanity: We only know protocols TCP and UDP
        if proto not in self.PROTOS:
            raise ValueError("Rule has unknown protocol '{}'!".format(proto))

        # Sanity: IPv4 or IPv6 address
        try:
            source_parsed = ipaddress.ip_address(source)
        except ValueError:
            try:
                source_parsed = ipaddress.ip_network(source)
            except ValueError:
                raise ValueError("Rule has really weird source definition '{}'!".format(source))

        if isinstance(source_parsed, ipaddress.IPv4Address) or isinstance(source_parsed, ipaddress.IPv4Network):
            # IPv4
            if proto_ver != 4:
                return None
        if isinstance(source_parsed, ipaddress.IPv6Address) or isinstance(source_parsed, ipaddress.IPv6Network):
            # IPv6
            if proto_ver != 6:
                return None

        # Output
        ipchain_rule = [
            "-A", self._chain, "-p", proto, "-m", proto, "--source", source, "--dport", port, "-j", "ACCEPT"
        ]

        return ipchain_rule
