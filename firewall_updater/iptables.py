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
from subprocess import Popen
from typing import Tuple, Optional, Union, List, Any
import re
import ipaddress
from .base import FirewallBase
from .rules import ServiceReader, Rule
import logging

log = logging.getLogger(__name__)


class IptablesRule(Rule):

    def __init__(self, rule_num: int, proto: str, port: int, source_address, comment: str = None):
        super().__init__(proto, port, source_address, comment=comment)
        self.rule_num = rule_num
        self.expiry = None

    def has_expired(self) -> bool:
        raise RuntimeError("IptablesRule has no expiry!")

    def __str__(self) -> str:
        return "iptables IPv{} rule {}: {}/{} allowed from {}".format(
            self.source_address_family,
            self.rule_num,
            self.proto.upper(), self.port, self.source
        )


class Iptables(FirewallBase):

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

    def query(self) -> List[Tuple[str, int, str, Union[str, None]]]:
        """
        Query for currently active firewall rules
        :return: list of tuples, tuple will contain proto, port, source address and comment
        """
        active_v4_rules = self._read_chain(4)
        active_v6_rules = self._read_chain(6)

        rules_out = []
        if active_v4_rules:
            # Notes:
            # - Source address will be converted into a string
            # - A comment is either str or bool, D-Bus cannot return None
            rules_out = [(r.proto, r.port, str(r.source_address), r.comment if r.comment else False)
                         for r in active_v4_rules]

        if active_v6_rules:
            # Note: For transformation, see IPv4 above
            rules_out.extend([(r.proto, r.port, str(r.source_address), r.comment if r.comment else False)
                              for r in active_v6_rules])

        return rules_out

    def query_readable(self, rules: List[Rule]) -> List[str]:
        rules_out = []

        for rule in rules:
            rule_out = self._rule_to_ipchain_append(4, rule, with_command=True)
            if rule_out:
                rule_str = ""
                if rule.has_expired():
                    # Ah. Expired already.
                    rule_str = "# "

                rule_str += ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)

        for rule in rules:
            rule_out = self._rule_to_ipchain_append(6, rule, with_command=True)
            if rule_out:
                rule_str = ""
                if rule.has_expired():
                    # Ah. Expired already.
                    rule_str = "# "

                rule_str += ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)

        return rules_out

    def set(self, rules: List[Rule], force=False) -> None:
        """
        Set rules to firewall
        :param rules: List of firewall rules to set
        :param force: Force flush the chain with new rules
        :return:
        """
        ipv4_rules_to_remove, ipv4_rules_to_add, ipv6_rules_to_remove, ipv6_rules_to_add, changes_needed = \
            self._sync_rules(rules)

        if not changes_needed:
            log.info("No changes needed")
            return

        def _exec_helper(rule_out: list) -> Tuple[subprocess.Popen, bytes, bytes]:
            rule_out_str = [str(out) for out in rule_out]
            log.debug("Executing: '{}'".format(' '.join(rule_out_str)))
            p = subprocess.Popen(
                rule_out_str,
                stdout=subprocess.PIPE)
            output, err = p.communicate()

            return p, output, err

        # IPv4:
        for rule in sorted(ipv4_rules_to_remove, key=lambda x: x.rule_num, reverse=True):
            rule_out = self._rule_to_ipchain_delete(4, rule, with_command=True)
            if rule_out:
                p, output, err = _exec_helper(rule_out)
                if p.returncode != 0:
                    raise RuntimeError("Failed to delete IPtables IPv4 rule #{}".format(rule.rule_num))

        for rule in ipv4_rules_to_add:
            rule_out = self._rule_to_ipchain_append(4, rule, with_command=True)
            if rule_out:
                p, output, err = _exec_helper(rule_out)
                if p.returncode != 0:
                    raise RuntimeError("Failed to add IPtables IPv4 rule: '{}'".format(str(rule)))

        # IPv6:
        for rule in sorted(ipv6_rules_to_remove, key=lambda x: x.rule_num, reverse=True):
            rule_out = self._rule_to_ipchain_delete(6, rule, with_command=True)
            if rule_out:
                p, output, err = _exec_helper(rule_out)
                if p.returncode != 0:
                    raise RuntimeError("Failed to delete IPtables IPv6 rule #{}".format(rule.rule_num))

        for rule in ipv6_rules_to_add:
            rule_out = self._rule_to_ipchain_append(6, rule, with_command=True)
            if rule_out:
                p, output, err = _exec_helper(rule_out)
                if p.returncode != 0:
                    raise RuntimeError("Failed to add IPtables IPv6 rule: '{}'".format(str(rule)))

    def simulate(self, rules: List[Rule]) -> Union[bool, List[str]]:
        """
        Show what would happen if set rules to firewall
        :param rules:
        :return:
        """
        ipv4_rules_to_remove, ipv4_rules_to_add, ipv6_rules_to_remove, ipv6_rules_to_add, changes_needed = \
            self._sync_rules(rules)

        if not changes_needed:
            return False

        rules_out = []

        # IPv4:
        for rule in sorted(ipv4_rules_to_remove, key=lambda x: x.rule_num, reverse=True):
            rule_out = self._rule_to_ipchain_delete(4, rule, with_command=True)
            if rule_out:
                rule_str = ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)
        for rule in ipv4_rules_to_add:
            rule_out = self._rule_to_ipchain_append(4, rule, with_command=True)
            if rule_out:
                rule_str = ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)

        # IPv6:
        for rule in sorted(ipv6_rules_to_remove, key=lambda x: x.rule_num, reverse=True):
            rule_out = self._rule_to_ipchain_delete(6, rule, with_command=True)
            if rule_out:
                rule_str = ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)
        for rule in ipv6_rules_to_add:
            rule_out = self._rule_to_ipchain_append(6, rule, with_command=True)
            if rule_out:
                rule_str = ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)

        return rules_out

    def needs_update(self, rules: List[Rule]) -> bool:
        ipv4_rules_to_remove, ipv4_rules_to_add, ipv6_rules_to_remove, ipv6_rules_to_add, \
        changes_needed = self._sync_rules(rules)

        return changes_needed

    def _sync_rules(self, rules: List[Rule]) -> Tuple[list, List[Rule], list, List[Rule], bool]:
        # Prep:
        # Index for all of the rules
        matched_rules = {}
        for idx, rule in enumerate(rules):
            if rule.has_expired():
                # Ah. Expired already. We won't be needing this rule in active ones.
                continue

            matched_rules[idx] = False

        # IPv4 matching:
        active_ipv4_rules = self._read_chain(4)
        ipv4_rules_to_add = []
        ipv4_rules_to_remove = []
        for active_rule in active_ipv4_rules:
            # Search for this active rule in set of user-rules
            found_it = False
            for idx, rule in enumerate(rules):
                # Match:
                # 1) Proto
                # 2) Port
                # 3) Source address
                if rule == active_rule:
                    # Found match!
                    # XXX Debug noise:
                    # log.debug("Matched IPv4 rule: '{}'!".format(rule))
                    matched_rules[idx] = True
                    found_it = True
                    break

            if not found_it:
                log.debug("Active IPv4 rule '{}' not found in user rules".format(active_rule))
                ipv4_rules_to_remove.append(active_rule)

        # IPv6 matching:
        active_ipv6_rules = self._read_chain(6)
        ipv6_rules_to_add = []
        ipv6_rules_to_remove = []
        for active_rule in active_ipv6_rules:
            # Search for this active rule in set of user-rules
            found_it = False
            for idx, rule in enumerate(rules):
                # Match:
                # 1) Proto
                # 2) Port
                # 3) Source address
                if rule == active_rule:
                    # Found match!
                    # XXX Debug noise:
                    # log.debug("Matched IPv6 rule: '{}'!".format(rule))
                    matched_rules[idx] = True
                    found_it = True
                    break

            if not found_it:
                log.debug("Active IPv6 rule '{}' not found in user rules".format(active_rule))
                ipv6_rules_to_remove.append(active_rule)

        # Un-matched rules:
        for idx, rule in enumerate(rules):
            if matched_rules[idx]:
                # This one is already matched
                continue

            if rule.source_address_family == 4:
                ipv4_rules_to_add.append(rule)
            elif rule.source_address_family == 6:
                ipv6_rules_to_add.append(rule)

        # Stats matched rules
        matches_found = len([True for match in matched_rules.values() if match is True])

        # Logging
        log.debug("Out of {} rules, {} match, {} need to be added. {} active rules to remove.".format(
            len(matched_rules), matches_found,
            len(ipv4_rules_to_add) + len(ipv6_rules_to_add),
            len(ipv4_rules_to_remove) + len(ipv6_rules_to_remove)
        ))

        return ipv4_rules_to_remove, ipv4_rules_to_add, ipv6_rules_to_remove, ipv6_rules_to_add, matches_found != len(
            matched_rules)

    def _clear_chain(self):
        return
        p = subprocess.Popen(
            [self._iptables_cmd, "-A", self._chain, "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"],
            stdout=subprocess.PIPE)
        output, err = p.communicate()

    def _read_chain(self, ip_version: int) -> List[IptablesRule]:
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
            if ip_version == 4:
                #                     1:      2:      3:      4:      5:      6:      7:
                match = re.search(r'^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)', line.rstrip())
                if not match:
                    raise ValueError("IPchain output error! Rule cannot be parsed: '{}'".format(line.strip()))

                rule_num = int(match.group(1))
                destination_chain = match.group(2)
                proto = match.group(3)
                options = match.group(4)
                address_in = match.group(5)
                destination_addr = match.group(6)
                destination = match.group(7)

                if options != "--":
                    raise ValueError("IPchain output error! Options is rules not supported, "
                                     "rule: '{}'".format(line.strip()))

                # Parse the source address
                try:
                    source_addr = ipaddress.ip_address(address_in)
                except ValueError:
                    try:
                        source_addr = ipaddress.ip_network(address_in)
                    except ValueError:
                        raise ValueError("Really weird IP-address definition '{}'!".format(address_in))

                if not isinstance(source_addr, ipaddress.IPv4Address) and not isinstance(source_addr,
                                                                                         ipaddress.IPv4Network):
                    raise ValueError("Really weird IPv4-address definition '{}'!".format(address_in))

            elif ip_version == 6:
                #                     1:      2:      3:      4:      5:      6:
                match = re.search(r'^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)', line.rstrip())
                if not match:
                    raise ValueError("IPchain output error! Rule cannot be parsed: '{}'".format(line.strip()))
                rule_num = int(match.group(1))
                destination_chain = match.group(2)
                proto = match.group(3)
                address_in = match.group(4)
                destination_addr = match.group(5)
                destination = match.group(6)

                # Parse the source address
                try:
                    source_addr = ipaddress.ip_address(address_in)
                except ValueError:
                    try:
                        source_addr = ipaddress.ip_network(address_in)
                    except ValueError:
                        raise ValueError("Really weird IP-address definition '{}'!".format(address_in))

                if not isinstance(source_addr, ipaddress.IPv6Address) and not isinstance(source_addr,
                                                                                         ipaddress.IPv6Network):
                    raise ValueError("Really weird IPv6-address definition '{}'!".format(address_in))

            else:
                raise RuntimeError("Internal: Don't know if IPv4 or IPv6!")

            # Common part:
            if destination_chain != "ACCEPT":
                raise ValueError("IPchain output error! Rule isn't an ACCEPT-rule, "
                                 "is a '{}', rule: '{}'".format(destination_chain, line.strip()))
            if proto not in ServiceReader.PROTOCOLS:
                raise ValueError("IPchain output error! Rule has unsupported proto '{}', "
                                 "rule: '{}'".format(proto, line.strip()))
            # Parse destination, it contains all possible options of iptables-rule
            port = None
            match = re.search(r'^\w+\s+dpt:(\d+)(\s+/\*\s+(.+)\s+\*/)?$', destination)
            if not match:
                raise ValueError("IPchain output error! Rule destination needs to be a simple port definition, "
                                 "rule: '{}'".format(line.strip()))
            port = int(match.group(1))
            if match.group(2):
                comment = match.group(3)
                # log.debug("Comment: '{}'".format(comment))
            else:
                comment = None

            # XXX Debug noise:
            # log.debug("Parsed rule {}: {}, {}, {}".format(rule_num, proto, port, source_addr))
            rule_out = IptablesRule(rule_num, proto, port, source_addr, comment)
            rules_out.append(rule_out)

        return rules_out

    def _rule_to_ipchain_append(self, proto_ver: int, rule: Rule, with_command=False) -> Union[list, None]:
        # Sanity: IPv4 or IPv6 address
        if rule.source_address_family != proto_ver:
            return None

        # Output
        ipchain_rule = [
            "-A", self._chain, "-p", rule.proto, "-m", rule.proto, "--source", rule.source, "--dport", rule.port
        ]
        if rule.comment:
            ipchain_rule.extend(["-m", "comment", "--comment", rule.comment])
        ipchain_rule.extend(["-j", "ACCEPT"])

        if with_command:
            if rule.source_address_family == 4:
                command_to_run = self._iptables_cmd
            elif rule.source_address_family == 6:
                command_to_run = self._ip6tables_cmd
            else:
                raise ValueError("IP-version needs to be 4 or 6! Has: '{}'".format(rule.source_address_family))

            ipchain_rule.insert(0, command_to_run)

        return ipchain_rule

    def _rule_to_ipchain_delete(self, proto_ver: int, rule: IptablesRule, with_command=False) -> Union[list, None]:
        # Sanity: IPv4 or IPv6 address
        if rule.source_address_family != proto_ver:
            return None

        # Output
        ipchain_rule = [
            "-D", self._chain, rule.rule_num
        ]

        if with_command:
            if rule.source_address_family == 4:
                command_to_run = self._iptables_cmd
            elif rule.source_address_family == 6:
                command_to_run = self._ip6tables_cmd
            else:
                raise ValueError("IP-version needs to be 4 or 6! Has: '{}'".format(rule.source_address_family))

            ipchain_rule.insert(0, command_to_run)

        return ipchain_rule
