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
from firewall_updater.rules import RuleReader
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


def read_active_rules_from_firewall(rule_engine: FirewallBase) -> None:
    rules = rule_engine.query()

    log.info("Active rules ({}):".format(len(rules)))
    from pprint import pprint
    pprint(rules)


def rules_need_update(rule_engine: FirewallBase, rules_path: str) -> None:
    reader = RuleReader(rules_path)
    rules = reader.read_all_users()

    # Test the newly read rules
    log.info("Rules need updating:")
    if rule_engine.needs_update(rules):
        log.info("Need updating")
    else:
        log.info("All ok")


def rules_simulation(rule_engine: FirewallBase, rules_path: str) -> None:
    reader = RuleReader(rules_path)
    rules = reader.read_all_users()

    # Test the newly read rules
    log.info("Changes:")
    changes = rule_engine.simulate(rules)
    if not changes:
        log.info("All ok")
    else:
        from pprint import pprint
        pprint(changes)

        log.info("Proceed with changes:")
        rule_engine.set(rules)


def main() -> None:
    parser = argparse.ArgumentParser(description='Firewall Updates daemon')
    parser.add_argument("rule_path", metavar="RULE-PATH",
                        help="User's firewall rules base directory")
    parser.add_argument("--user",
                        help="(optional) Update rules for single user")
    parser.add_argument('--log-level', default="WARNING",
                        help='Set logging level. Python default is: WARNING')
    args = parser.parse_args()

    _setup_logger(args.log_level)

    log.info('Starting up ...')

    iptables_firewall = Iptables("Friends-Firewall-INPUT")
    # read_rules_for_all_users(iptables_firewall, args.rule_path)
    # read_active_rules_from_firewall(iptables_firewall)
    # rules_need_update(iptables_firewall, args.rule_path)
    rules_simulation(iptables_firewall, args.rule_path)


if __name__ == "__main__":
    main()
