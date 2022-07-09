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

import io
import subprocess
import shutil
from typing import Tuple, Optional, Union, List
import ipaddress
import re
from datetime import datetime
from .base import FirewallBase
from .rules import ServiceReader
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
        if not self._ip6tables_cmd:
            raise ValueError("Cannot find exact location of ip6tables-command! Failing to continue.")

    def query(self) -> List[Tuple[str, int, str]]:
        active_v4_rules = self._read_chain(4)
        active_v6_rules = self._read_chain(6)

        rules_out = []
        if active_v4_rules:
            rules_out = active_v4_rules

        if active_v6_rules:
            rules_out.extend(active_v6_rules)

        return rules_out

    def set(self, rules: List[Tuple[str, int, str]]) -> list:
        raise NotImplementedError("Set IPtables rules not implemented yet!")

    def simulate(self, rules: List[Tuple[str, int, str, Union[datetime, None]]], print_rules: bool) -> Tuple[
        List[str], List[str]
    ]:
        now = datetime.utcnow()
        rules_out_4 = []
        if print_rules:
            print("IPv4 rules:")
        for rule in rules:
            rule_out = self._rule_to_ipchain(4, rule)
            if rule_out:
                rule_str = ""
                if rule[3] and now > rule[3]:
                    # Ah. Expired already.
                    rule_str = "# "

                rule_str += ' '.join(str(r) for r in rule_out)
                rules_out_4.append(rule_str)
                if print_rules:
                    print(rule_str)

        rules_out_6 = []
        if print_rules:
            print("IPv6 rules:")
        for rule in rules:
            rule_out = self._rule_to_ipchain(6, rule)
            if rule_out:
                rule_str = ""
                if rule[3] and rule[3] > now:
                    # Ah. Expired already.
                    rule_str = "# "

                rule_str += ' '.join(str(r) for r in rule_out)
                rules_out_6.append(rule_str)
                if print_rules:
                    print(rule_str)

        return rules_out_4, rules_out_6

    def needs_update(self, rules: List[Tuple[str, int, str, Union[datetime, None]]]) -> bool:
        now = datetime.utcnow()
        matched_rules = {}
        for idx, rule in enumerate(rules):
            if rule[3] and rule[3] > now:
                # Ah. Expired already. We won't be needing this rule in active ones.
                continue

            matched_rules[idx] = False

        active_ipv4_rules = self._read_chain(4)
        ipv4_rules_to_remove = []
        for active_rule in active_ipv4_rules:
            # Search for this active rule in set of user-rules
            found_it = False
            for idx, rule in enumerate(rules):
                if active_rule[0] == rule[0] and active_rule[1] == rule[1] and active_rule[2] == rule[2]:
                    # Found match!
                    log.debug("Matched rule: '{}'!".format(rule))
                    matched_rules[idx] = True
                    found_it = True
                    break

            if not found_it:
                log.debug("Active rule '{}' not found in user rules".format(active_rule))
                ipv4_rules_to_remove.append(active_rule)

        matches_found = len([True for match in matched_rules.values() if match is True])
        log.debug("Out of {} rules, {} match. {} active rules to remove".format(
            len(matched_rules), matches_found, len(ipv4_rules_to_remove)
        ))

        return matches_found == len(matched_rules)

    def _clear_chain(self):
        return
        p = subprocess.Popen(
            [self._iptables_cmd, "-A", self._chain, "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"],
            stdout=subprocess.PIPE)
        output, err = p.communicate()

    def _read_chain(self, ip_version: int) -> List[Tuple[str, int, str]]:
        if ip_version == 4:
            command_to_run = self._iptables_cmd
        elif ip_version == 6:
            command_to_run = self._ip6tables_cmd
        else:
            raise ValueError("IP-version needs to be 4 or 6!")

        # Note!
        # iptables-command can be run only as root
        p = subprocess.Popen(
            [command_to_run, "-n", "--line-numbers", "-L", self._chain],
            stdout=subprocess.PIPE)
        output, err = p.communicate()
        if p.returncode != 0:
            raise RuntimeError("Failed to query for IPtables rules with command: {}".format(command_to_run))

        """
Chain Example-Chain-INPUT (1 references)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  192.0.2.0/24         0.0.0.0/0            tcp dpt:22
2    ACCEPT     tcp  --  198.51.100.0/24      0.0.0.0/0            tcp dpt:993
        """

        line_nro = 0
        rules_out = []
        for line in io.StringIO(output.decode('UTF-8')):
            line_nro += 1
            if line_nro == 1:
                # First line contains chain name
                match = re.search('^Chain\s+(\S+)\s+', line)
                if not match:
                    raise ValueError("IPchain output error! First line cannot be parsed: '{}'".format(line.strip()))

                chain_name = match.group(1)
                if chain_name != self._chain:
                    raise ValueError("IPchain output error! Attempt to query for chain '{}' failed, "
                                     "got: '{}'".format(self._chain, line.strip()))

                continue
            elif line_nro == 2:
                # Skip header row
                continue

            # Regular rows
            #                     1:      2:      3:      4:      5:      6:      7:
            match = re.search(r'^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)', line.rstrip())
            if not match:
                raise ValueError("IPchain output error! Rule cannot be parsed: '{}'".format(line.strip()))

            rule_num = int(match.group(1))
            destination_chain = match.group(2)
            proto = match.group(3)
            options = match.group(4)
            source_addr = match.group(5)
            destination_addr = match.group(6)
            destination = match.group(7)

            if destination_chain != "ACCEPT":
                raise ValueError("IPchain output error! Rule isn't an ACCEPT-rule, "
                                 "is a '{}', rule: '{}'".format(destination_chain, line.strip()))
            if proto not in ServiceReader.PROTOCOLS:
                raise ValueError("IPchain output error! Rule has unsupported proto '{}', "
                                 "rule: '{}'".format(proto, line.strip()))
            if options != "--":
                raise ValueError("IPchain output error! Options is rules not supported, "
                                 "rule: '{}'".format(line.strip()))

            # Parse destination, it contains all possible options of iptables-rule
            port = None
            match = re.search(r'^\w+\s+dpt:(\d+)$', destination)
            if not match:
                raise ValueError("IPchain output error! Rule destination needs to be a simple port definition, "
                                 "rule: '{}'".format(line.strip()))
            port = int(match.group(1))

            # XXX Debug noise:
            # log.debug("Parsed rule {}: {}, {}, {}".format(rule_num, proto, port, source_addr))
            rule_out = (proto, port, source_addr)
            rules_out.append(rule_out)

        return rules_out

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
