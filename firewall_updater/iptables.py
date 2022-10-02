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
from typing import Tuple, Optional, Union, List, Any, Dict
import re
import ipaddress
from datetime import datetime
from .base import FirewallBase
from .rules import ServiceReader, Rule, UserRule, FirewallRule, Service
import logging

log = logging.getLogger(__name__)


class IptablesRule(FirewallRule):

    def __init__(self, rule_number_in_chain: int, proto: str, port: int, service: Service, source_address,
                 comment: str = None):
        super().__init__(proto, port, service, source_address, comment=comment)
        self.rule_number_in_chain = rule_number_in_chain
        self.expiry = None


class MatchedIptablesRule(UserRule):

    def __init__(self, rule_number_in_chain: int, user_rule: UserRule):
        super().__init__(user_rule.owner, user_rule.service, user_rule.source_address,
                         expiry=user_rule.expiry, comment=user_rule.comment)
        self.rule_number_in_chain = rule_number_in_chain

    def __str__(self) -> str:
        return "User {} iptables IPv{} rule {}: {} allowed from {}".format(
            self.owner,
            self.source_address_family,
            self.rule_number_in_chain,
            self.service, self.source
        )


class Iptables(FirewallBase):

    def __init__(self, services: Dict[str, Service], chain_name: str, stateful: bool):
        """
        Initialize Linux IPtables firewall
        :param services: List of defined services
        :param chain_name: Name of IPtables ipchain
        :param stateful: TCP and UDP, True = -m state --state NEW, False = don't add
        """
        super().__init__(services)

        if not chain_name:
            raise ValueError("Need valid IPtables chain name!")
        self._chain = chain_name
        self._iptables_cmd = shutil.which("iptables")
        if not self._iptables_cmd:
            raise ValueError("Cannot find exact location of iptables-command! Failing to continue.")
        self._ip6tables_cmd = shutil.which("ip6tables")
        if not self._ip6tables_cmd:
            raise ValueError("Cannot find exact location of ip6tables-command! Failing to continue.")

        self.stateful = stateful

    #
    # Abstract implementation for IPtables
    #

    def query(self, rules: List[UserRule]) -> List[Tuple[UserRule, bool]]:
        """
        Query for currently active firewall rules
        :return: list of tuples, tuple: user rule object, rule in effect
        """

        ipv4_rules_matched, _, ipv4_rules_to_add, \
        ipv6_rules_matched, _, ipv6_rules_to_add, \
        _ = \
            self._sync_rules(rules, False)

        rules_out = []
        if ipv4_rules_matched:
            rules_out.extend([(r, True) for r in ipv4_rules_matched])
        if ipv4_rules_to_add:
            rules_out.extend([(r, False) for r in ipv4_rules_to_add])

        if ipv6_rules_matched:
            rules_out.extend([(r, True) for r in ipv6_rules_matched])
        if ipv6_rules_to_add:
            rules_out.extend([(r, False) for r in ipv6_rules_to_add])

        return rules_out

    def query_readable(self, rules: List[UserRule]) -> List[str]:
        """
        Query for currently active firewall rules.
        Match the rules against all users' rules.
        :param rules: Users' rules
        :param services: All servies
        :return: list of strings
        """

        rules_out = []

        for rule in rules:
            service_rules = self._rule_to_ipchain_append(4, rule, with_command=True)
            for rule_out in service_rules:
                rule_str = ""
                if rule.has_expired():
                    # Ah. Expired already.
                    rule_str = "# "

                rule_str += ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)

        for rule in rules:
            service_rules = self._rule_to_ipchain_append(6, rule, with_command=True)
            for rule_out in service_rules:
                rule_str = ""
                if rule.has_expired():
                    # Ah. Expired already.
                    rule_str = "# "

                rule_str += ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)

        return rules_out

    def set(self, rules: List[UserRule], force=False) -> None:
        """
        Set rules to firewall
        :param rules: List of firewall rules to set
        :param force: Force set all rules ignoring any possible existing rules
        :return:
        """
        _, ipv4_rules_to_remove, ipv4_rules_to_add, \
        _, ipv6_rules_to_remove, ipv6_rules_to_add, \
        changes_needed = \
            self._sync_rules(rules, force)

        if not changes_needed:
            log.info("No changes needed")
            return

        def _exec_helper(rule_out: list) -> Tuple[subprocess.Popen, bytes, bytes]:
            rule_out_str = [str(out) for out in rule_out]
            # XXX Debug noise:
            # log.debug("Executing: '{}'".format(' '.join(rule_out_str)))
            p = subprocess.Popen(
                rule_out_str,
                stdout=subprocess.PIPE)
            output, err = p.communicate()

            return p, output, err

        if force:
            # Forced update
            # Flush the chains first
            rule_out = [self._iptables_cmd, "-F", self._chain]
            p, output, err = _exec_helper(rule_out)
            if p.returncode != 0:
                raise RuntimeError("Failed to flush IPtables IPv4 chain {}".format(self._chain))

            rule_out = [self._ip6tables_cmd, "-F", self._chain]
            p, output, err = _exec_helper(rule_out)
            if p.returncode != 0:
                raise RuntimeError("Failed to flush IPtables IPv6 chain {}".format(self._chain))

        # IPv4:
        # Apply deletion in reverse order. As we'll progress from highest number to lowest,
        # IPtables rule order won't change in the process.
        for rule in sorted(ipv4_rules_to_remove, key=lambda x: x.rule_number_in_chain, reverse=True):
            rule_out = self._rule_to_ipchain_delete(4, rule, with_command=True)
            if rule_out:
                p, output, err = _exec_helper(rule_out)
                if p.returncode != 0:
                    raise RuntimeError("Failed to delete IPtables IPv4 rule #{}".format(rule.rule_number_in_chain))

        # Rules will be appended to the end of the chain
        for rule in ipv4_rules_to_add:
            service_rules = self._rule_to_ipchain_append(4, rule, with_command=True)
            for rule_out in service_rules:
                p, output, err = _exec_helper(rule_out)
                if p.returncode != 0:
                    raise RuntimeError("Failed to add IPtables IPv4 rule: '{}'".format(str(rule)))

        # IPv6:
        # Exactly same processing as for IPv4-rules
        for rule in sorted(ipv6_rules_to_remove, key=lambda x: x.rule_number_in_chain, reverse=True):
            rule_out = self._rule_to_ipchain_delete(6, rule, with_command=True)
            if rule_out:
                p, output, err = _exec_helper(rule_out)
                if p.returncode != 0:
                    raise RuntimeError("Failed to delete IPtables IPv6 rule #{}".format(rule.rule_number_in_chain))

        # Exactly same processing as for IPv4-rules
        for rule in ipv6_rules_to_add:
            service_rules = self._rule_to_ipchain_append(6, rule, with_command=True)
            for rule_out in service_rules:
                p, output, err = _exec_helper(rule_out)
                if p.returncode != 0:
                    raise RuntimeError("Failed to add IPtables IPv6 rule: '{}'".format(str(rule)))

    def simulate(self, rules: List[UserRule], force=False) -> Union[bool, List[str]]:
        """
        Show what would happen if set rules to firewall
        :param rules: List of firewall rules to simulate
        :param force: Force simulate all rules ignoring any possible existing rules
        :return: list of strings, what firewall would need to do to make rules effective
        """
        _, ipv4_rules_to_remove, ipv4_rules_to_add, \
        _, ipv6_rules_to_remove, ipv6_rules_to_add, \
        changes_needed = \
            self._sync_rules(rules, force)

        log.debug("IPtables simulate(), changes_needed = {}".format(changes_needed))
        if not changes_needed:
            return False

        rules_out = []

        # IPv4:
        for rule in sorted(ipv4_rules_to_remove, key=lambda x: x.rule_number_in_chain, reverse=True):
            rule_out = self._rule_to_ipchain_delete(4, rule, with_command=True)
            if rule_out:
                rule_str = ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)
        for rule in ipv4_rules_to_add:
            service_rules = self._rule_to_ipchain_append(4, rule, with_command=True)
            for rule_out in service_rules:
                rule_str = ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)

        # IPv6:
        for rule in sorted(ipv6_rules_to_remove, key=lambda x: x.rule_number_in_chain, reverse=True):
            rule_out = self._rule_to_ipchain_delete(6, rule, with_command=True)
            if rule_out:
                rule_str = ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)
        for rule in ipv6_rules_to_add:
            service_rules = self._rule_to_ipchain_append(6, rule, with_command=True)
            for rule_out in service_rules:
                rule_str = ' '.join(str(r) for r in rule_out)
                rules_out.append(rule_str)

        return rules_out

    def needs_update(self, rules: List[UserRule]) -> bool:
        """
        Query if any rules requested by users are not in effect
        :param rules: list of user rules
        :return: bool, True = changes needed, False = all rules effective
        """
        _, _, _, _, _, _, changes_needed = self._sync_rules(rules, False)

        return changes_needed

    #
    # IPtables internal implementation below
    #

    def _sync_rules(self, user_rules: List[UserRule], force: bool) -> Tuple[
        List[MatchedIptablesRule], list, List[UserRule],
        List[MatchedIptablesRule], list, List[UserRule], bool
    ]:
        if not force:
            return self._do_sync_rules(user_rules)

        # Forced sync. No matching needed.
        ipv4_rules_matched = []
        ipv4_rules_to_add = []
        ipv4_rules_to_remove = []
        ipv6_rules_matched = []
        ipv6_rules_to_add = []
        ipv6_rules_to_remove = []

        for idx, rule in enumerate(user_rules):
            if rule.network_size_valid(False) is False:
                log.warning("Skipping IPv{} network {} of size /{}".format(
                    rule.source_address_family, rule.source, rule.source_address.prefixlen
                ))
                continue
            if rule.comment and len(rule.comment) > 256:
                raise ValueError("IPtables comment can only be 256 characters long. Got: {}".format(len(rule.comment)))
            if rule.source_address_family == 4:
                ipv4_rules_to_add.append(rule)
            elif rule.source_address_family == 6:
                ipv6_rules_to_add.append(rule)

        # Logging
        log.debug("Out of {} rules, forcing all to be added. All (possibly) active rules to remove.".format(
            len(user_rules)
        ))

        return ipv4_rules_matched, ipv4_rules_to_remove, ipv4_rules_to_add, \
               ipv6_rules_matched, ipv6_rules_to_remove, ipv6_rules_to_add, \
               True

    def _do_sync_rules(self, user_rules: List[UserRule]) -> Tuple[
        List[MatchedIptablesRule], list, List[UserRule],
        List[MatchedIptablesRule], list, List[UserRule], bool
    ]:
        """
        Match actual IPtables rules against a set of user's desired rules.
        :param user_rules:  List of user's rules
        :return: (list) IPv4 rules matched, (list) IPv4 rules to remove, (list) IPv4 rules to add,
            (list) IPv6 rules matched, (list) IPv6 rules to remove, (list) IPv6 rules to add,
            (bool) changes needed
        """
        # Prep:
        # Index for all of the rules
        matched_rules = {}
        for idx, rule in enumerate(user_rules):
            if rule.comment and len(rule.comment) > 256:
                raise ValueError("IPtables comment can only be 256 characters long. Got: {}".format(len(rule.comment)))

            if rule.has_expired():
                # Ah. Expired already. We won't be needing this rule in active ones.
                continue

            matched_rules[idx] = False

        # IPv4 matching:
        active_ipv4_rules = self._read_chain(4)
        ipv4_rules_matched = []
        ipv4_rules_to_add = []
        ipv4_rules_to_remove = []
        for active_rule in active_ipv4_rules:
            # Search for this active rule in set of user-rules
            found_it = False
            for idx, rule in enumerate(user_rules):
                # Match: 1) Service 2) Source address 3) Comment
                if rule == active_rule:
                    # Found match!
                    # Check if the rule hasn't expired and hasn't been matched already.
                    if idx in matched_rules and not matched_rules[idx]:
                        # A service can contain multiple protocols and ports.
                        # Append to list only if user rule not matched already.
                        matched_rule = MatchedIptablesRule(active_rule.rule_number_in_chain, rule)
                        ipv4_rules_matched.append(matched_rule)
                        # XXX Debug noise:
                        # log.debug("Matched IPv4 rule: '{}'!".format(matched_rule))
                        matched_rules[idx] = True
                    found_it = True
                    break

            if not found_it:
                log.debug("Active IPv4 rule '{}' not found in user rules".format(active_rule))
                ipv4_rules_to_remove.append(active_rule)

        # IPv6 matching:
        active_ipv6_rules = self._read_chain(6)
        ipv6_rules_matched = []
        ipv6_rules_to_add = []
        ipv6_rules_to_remove = []
        for active_rule in active_ipv6_rules:
            # Search for this active rule in set of user-rules
            found_it = False
            for idx, rule in enumerate(user_rules):
                # Match: 1) Service 2) Source address 3) Comment
                if rule == active_rule:
                    # Found match!
                    # Check if the rule hasn't expired and hasn't been matched already.
                    if idx in matched_rules and not matched_rules[idx]:
                        # A service can contain multiple protocols and ports.
                        # Append to list only if user rule not matched already.
                        matched_rule = MatchedIptablesRule(active_rule.rule_number_in_chain, rule)
                        ipv6_rules_matched.append(matched_rule)
                        # XXX Debug noise:
                        # log.debug("Matched IPv6 rule: '{}'!".format(matched_rule))
                        matched_rules[idx] = True
                    found_it = True
                    break

            if not found_it:
                log.debug("Active IPv6 rule '{}' not found in user rules".format(active_rule))
                ipv6_rules_to_remove.append(active_rule)

        # Un-matched rules:
        for idx, rule in enumerate(user_rules):
            # Check if the rule hasn't expired and hasn't been matched already.
            if idx in matched_rules and matched_rules[idx]:
                # This one is already matched
                continue

            if rule.source_address_family == 4:
                ipv4_rules_to_add.append(rule)
            elif rule.source_address_family == 6:
                ipv6_rules_to_add.append(rule)

        # Stats matched rules
        matches_found = len([True for match in matched_rules.values() if match is True])

        # Any changes in rules?
        changes = matches_found != len(matched_rules)
        if not changes:
            changes = len(ipv4_rules_to_remove) + len(ipv6_rules_to_remove) > 0

        # Logging
        log.debug("Out of {} rules, {} match, {} need to be added. {} active rules to remove.".format(
            len(matched_rules), matches_found,
            len(ipv4_rules_to_add) + len(ipv6_rules_to_add),
            len(ipv4_rules_to_remove) + len(ipv6_rules_to_remove)
        ))

        return ipv4_rules_matched, ipv4_rules_to_remove, ipv4_rules_to_add, \
               ipv6_rules_matched, ipv6_rules_to_remove, ipv6_rules_to_add, \
               changes

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
            raise RuntimeError("Failed to query for IPtables rules. "
                               "Exit code: {} Command: {} Stdout: {} Stderr: {}".format(
                p.returncode, command_to_run, output, err
            ))

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
            if proto not in Service.PROTOCOLS:
                raise ValueError("IPchain output error! Rule has unsupported proto '{}', "
                                 "rule: '{}'".format(proto, line.strip()))
            # Parse destination, it contains all possible options of iptables-rule
            # We'll expect to see:
            # 1: protocol
            # 2: dpt:<port number>
            # 3: [other options]
            # 4: /* [optional comment] */
            match = re.search(r'^(\w+)\s+dpt:(\d+)(\s+(.*))?$', destination)
            if not match:
                raise ValueError("IPchain output error! Rule destination failing to parse, "
                                 "rule: '{}'".format(line.strip()))
            port = int(match.group(2))
            comment = None
            if match.group(3):
                # Parse options/comment further.
                # Comment is always last
                options = match.group(4)
                match = re.search(r'/\*\s+(.+)\s+\*/', options)
                if match:
                    # Options do contain a comment
                    comment = match.group(1)
                # log.debug("Comment: '{}'".format(comment))

            # XXX Debug noise:
            # log.debug("Parsed rule {}: {}, {}, {}".format(rule_num, proto, port, source_addr))
            service = IptablesRule.find_service(proto, port, self.services)
            if service:
                rule_out = IptablesRule(rule_num, proto, port, service, source_addr, comment)
                rules_out.append(rule_out)

        return rules_out

    def _rule_to_ipchain_append(self, proto_ver: int, rule: Rule, with_command=False) -> List[list]:
        ipchain_rules = []

        # Sanity: IPv4 or IPv6 address
        if rule.source_address_family != proto_ver:
            return ipchain_rules

        # Output
        for service_def in rule.service.enumerate():
            proto = service_def[0]
            port = service_def[1]

            ipchain_rule = [
                "-A", self._chain, "-p", proto, "-m", proto, "--source", rule.source, "--dport", port
            ]
            if self.stateful:
                # Docs: https://ipset.netfilter.org/iptables-extensions.man.html#lbCC
                ipchain_rule.extend(["-m", "state", "--state", "NEW"])
            if rule.comment:
                # Docs: https://ipset.netfilter.org/iptables-extensions.man.html#lbAK
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

            ipchain_rules.append(ipchain_rule)

        return ipchain_rules

    def _rule_to_ipchain_delete(self, proto_ver: int, rule: IptablesRule, with_command=False) -> List[list]:
        # Sanity: IPv4 or IPv6 address
        if rule.source_address_family != proto_ver:
            return []

        # Output
        ipchain_rule = [
            "-D", self._chain, rule.rule_number_in_chain
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
