#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

# This file is part of Spammer Block library and tool.
# Spamer Block is free software: you can
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
import sys
from typing import Optional, Tuple
import argparse
from firewall_updater.rules import RuleReader, RuleWriter, ServiceReader, UserRule
from firewall_updater import FirewallBase, Iptables
import logging

log = logging.getLogger(__name__)


def _setup_logger(log_level_in: str) -> None:
    log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(log_formatter)
    console_handler.propagate = False
    log.addHandler(console_handler)

    if log_level_in.upper() not in logging._nameToLevel:
        raise ValueError("Unkown logging level '{}'!".format(log_level_in))
    log_level = logging._nameToLevel[log_level_in.upper()]
    log.setLevel(log_level)

    lib_log = logging.getLogger('firewall_updater')
    lib_log.setLevel(log_level)
    lib_log.addHandler(console_handler)


def read_rules_for_all_users(rule_engine: FirewallBase, rules_path: str) -> None:
    reader = RuleReader(rules_path)
    rules = reader.read_all_users()

    # Test the newly read rules
    log.info("Human-readable rules:")
    rules_str = rule_engine.query_readable(rules)
    from pprint import pprint
    pprint(rules_str)

    if False:
        # UserRules as strings
        for rule in rules:
            print(str(rule))


def read_active_rules_from_firewall(rule_engine: FirewallBase, rules_path: str) -> None:
    reader = RuleReader(rules_path)
    rules = reader.read_all_users()
    user_rules = rule_engine.query(rules)

    log.info("Requested rules ({}):".format(len(user_rules)))
    log.debug("Effective rules:")
    for rule in user_rules:
        if rule[1]:
            log.debug(rule[0])
    log.debug("Requested but non-effective rules:")
    for rule in user_rules:
        if not rule[1]:
            log.debug(rule[0])
    log.debug("Done listing rules")


def rules_need_update(rule_engine: FirewallBase, rules_path: str) -> None:
    reader = RuleReader(rules_path)
    rules = reader.read_all_users()

    # Test the newly read rules
    if rule_engine.needs_update(rules):
        log.info("Rules need updating!")
    else:
        log.info("All ok")


def rules_enforcement(rule_engine: FirewallBase, rules_path: str, simulation: bool, forced: bool) -> None:
    reader = RuleReader(rules_path)
    rules = reader.read_all_users()

    # Test the newly read rules
    log.info("Changes:")
    changes = rule_engine.simulate(rules, forced)

    if not changes:
        log.info("All ok, no changes")
    else:
        from pprint import pprint
        pprint(changes)

        if not simulation:
            log.warning("Proceed with changes:")
            rule_engine.set(rules, forced)
            log.info("Changes done!")
        else:
            log.info("Simulation. Won't proceed with changes:")


def add_rule(user: str, service_code: str, source: str, comment: str, rules_path: str) -> None:
    reader = RuleReader(rules_path)
    rules = reader.read(user)

    # Match user given service
    if not service_code in reader.all_services:
        raise ValueError("Unknown service '{}'!".format(service_code))
    service = reader.all_services[service_code]

    # Create the new rule to be appended
    new_rule = UserRule(user, service, source, comment=comment)

    # Go write!
    rules.append(new_rule)
    writer = RuleWriter(rules_path)
    writer.write(user, rules)


def main() -> None:
    parser = argparse.ArgumentParser(description='Firewall Updates daemon')
    parser.add_argument("rule_path", metavar="RULE-PATH",
                        help="User's firewall rules base directory")
    parser.add_argument("--user",
                        help="(optional) Update rules for single user")
    parser.add_argument('--log-level', default="WARNING",
                        help='Set logging level. Python default is: WARNING')
    parser.add_argument('--force', action='store_true',
                        default=False,
                        help="Force firewall update")
    parser.add_argument('--add-rule-user',
                        help="Add new firewall rule to user")
    parser.add_argument('--rule-service',
                        help="Service for a rule")
    parser.add_argument('--rule-source-address',
                        help="Source address for a rule")
    parser.add_argument('--rule-comment',
                        help="Comment for a rule")
    args = parser.parse_args()

    _setup_logger(args.log_level)

    log.info('Starting up ...')

    if args.add_rule_user:
        add_rule(args.add_rule_user, args.rule_service, args.rule_source_address, args.rule_comment,
                 args.rule_path)
        exit(0)

    reader = ServiceReader(args.rule_path)
    iptables_firewall = Iptables(reader.read_all(), "Friends-Firewall-INPUT")

    # read_rules_for_all_users(iptables_firewall, args.rule_path)
    # read_active_rules_from_firewall(iptables_firewall, args.rule_path)
    # rules_need_update(iptables_firewall, args.rule_path)
    rules_enforcement(iptables_firewall, args.rule_path, simulation=True, forced=args.force)


if __name__ == "__main__":
    main()
