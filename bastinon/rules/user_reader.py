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
import sys
from typing import List, Tuple, Union, Dict
from lxml import etree
from pwd import getpwnam
from datetime import datetime
from .service_reader import ServiceReader
from .user_rule import UserRule, Service
from .shared_rule import SharedRule
import logging

log = logging.getLogger(__name__)


class RuleReader:
    USER_RULE_PATH = r"users"
    SHARED_RULE_PATH = r"shared"

    def __init__(self, rule_path: str,
                 max_ipv4_network_size: int = None, max_ipv6_network_size: int = None):
        user_rule_path = "{}/{}".format(rule_path, self.USER_RULE_PATH)
        if not os.path.exists(user_rule_path):
            raise ValueError("Rule path '{}' doesn't exist!".format(user_rule_path))
        if not os.path.isdir(user_rule_path):
            raise ValueError("Rule path '{}' is a file, not directory!".format(user_rule_path))

        self._path = rule_path
        self.all_services = None

        self._max_ipv4_network_size = max_ipv4_network_size
        self._max_ipv6_network_size = max_ipv6_network_size

    def _rule_filename(self, user: str) -> str:
        filename = "{}/{}/{}.xml".format(self._path, self.USER_RULE_PATH, user)

        return filename

    def has_rules_for(self, user: str) -> bool:
        filename = self._rule_filename(user)

        return os.path.exists(filename)

    def read_all_users(self, read_shared_rules: bool) -> List[UserRule]:
        if not self.all_services:
            reader = ServiceReader(self._path)
            self.all_services = reader.read_all()

        all_rules = []
        user_rules_path = "{}/{}".format(self._path, self.USER_RULE_PATH)
        shared_rules_path = "{}/{}".format(self._path, self.SHARED_RULE_PATH)

        # Iterate users
        for item in os.listdir(user_rules_path):
            if not item.endswith('.xml'):
                continue
            xml_file = os.path.join(user_rules_path, item)
            if os.path.isfile(xml_file):
                user_from_filename = item[:-4]
                try:
                    unix_user_passwd_record = getpwnam(user_from_filename)
                except KeyError:
                    log.warning("User '{}' has firewall-rule file, but doesn't exist in this system! "
                                "Ignoring.".format(user_from_filename))
                    continue
                user = unix_user_passwd_record.pw_name
                rules = self._user_rule_reader(user, xml_file, self.all_services)
                all_rules.extend(rules)

        # Iterate shared files (if any)
        if read_shared_rules:
            log.debug("Shared rules path: {}".format(shared_rules_path))
            if os.path.exists(shared_rules_path):
                for item in os.listdir(shared_rules_path):
                    if not item.endswith('.xml'):
                        continue
                    xml_file = os.path.join(shared_rules_path, item)
                    if os.path.isfile(xml_file):
                        rules = self._shared_rule_reader(xml_file, self.all_services)
                        all_rules.extend(rules)
            else:
                log.warning("Shared rules directory doesn't exist! Ignoring.")

        return all_rules

    def read(self, user: str) -> List[UserRule]:
        if not self.has_rules_for(user):
            raise ValueError("Cannot read rules for user {}! No rules found.".format(user))

        if not self.all_services:
            reader = ServiceReader(self._path)
            self.all_services = reader.read_all()

        filename = self._rule_filename(user)
        rules = self._user_rule_reader(user, filename, self.all_services)
        for rule in rules:
            if rule.source_address_family == 4 and self._max_ipv4_network_size:
                rule.max_ipv4_network_size = self._max_ipv4_network_size
            if rule.source_address_family == 6 and self._max_ipv6_network_size:
                rule.max_ipv6_network_size = self._max_ipv6_network_size

        return rules

    @staticmethod
    def _user_rule_reader(user: str, user_rules_filename: str, services: Dict[str, Service]) -> List[UserRule]:
        log.debug("For user {}, reading rule file: {}".format(user, user_rules_filename))
        return RuleReader._rule_reader(user_rules_filename, services, user=user)

    @staticmethod
    def _shared_rule_reader(shared_rules_filename: str, services: Dict[str, Service]) -> List[SharedRule]:
        log.debug("Reading shared rule file: {}".format(shared_rules_filename))
        shared_name = os.path.basename(shared_rules_filename)
        return RuleReader._rule_reader(shared_rules_filename, services, shared=shared_name)

    @staticmethod
    def _rule_reader(rules_filename: str, services: Dict[str, Service],
                     user: str = None, shared: str = None) -> List[Union[UserRule, SharedRule]]:
        # log.debug("Reading rule file: {}".format(rules_filename))
        root = etree.parse(rules_filename)
        schema_filename = "{}/xml-schemas/user_rule.xsd".format(sys.prefix)
        schema_doc = etree.parse(schema_filename)
        schema = etree.XMLSchema(schema_doc)
        if not schema.validate(root):
            raise ValueError("Rule-XML {} is not valid according to XSD file {}! Error: {}".format(
                rules_filename, schema_filename, schema.error_log))

        rules = []
        for zone_elem in root.iter(tag="zone"):
            service_elems = zone_elem.iter(tag="service")
            for service_elem in service_elems:
                if 'name' not in service_elem.attrib:
                    if user:
                        raise ValueError('Rule definition, service needs to have name! User: {}'.format(user))
                    if shared:
                        raise ValueError('Rule definition, service needs to have name! Shared: {}'.format(shared))
                    raise ValueError('Rule definition, service needs to have name!')

                service_name = service_elem.attrib['name']
                if service_name not in services:
                    if user:
                        raise ValueError(
                            "Rule definition, service is unknown '{}'! User: {}".format(service_name, user))
                    if shared:
                        raise ValueError(
                            "Rule definition, service is unknown '{}'! Shared: {}".format(service_name, shared))
                    raise ValueError("Rule definition, service is unknown '{}'!".format(service_name))

                service = services[service_name]
                source_elems = zone_elem.iter(tag="source")
                for source_elem in source_elems:
                    if 'address' not in source_elem.attrib:
                        if user:
                            raise ValueError('Rule definition, service needs to have name! User: {}'.format(user))
                        if shared:
                            raise ValueError('Rule definition, service needs to have name! Shared: {}'.format(shared))
                        raise ValueError('Rule definition, service needs to have name!')

                    # Source address:
                    source = source_elem.attrib['address']

                    # (optional) Expiry
                    if 'expires' in source_elem.attrib:
                        expiry = datetime.strptime(source_elem.attrib['expires'], "%Y-%m-%dT%H:%M:%S")
                        if False:
                            log.debug("Service '{}' source rule '{}' expiry: {}".format(
                                service_name,
                                etree.tostring(source_elem).decode('utf-8').rstrip(),
                                expiry
                            ))
                    else:
                        expiry = None

                    # (optional) Comment
                    if 'comment' in source_elem.attrib:
                        comment = source_elem.attrib['comment']
                    else:
                        comment = None

                    if user:
                        rule = UserRule(user, service, source, expiry, comment)
                    elif shared:
                        rule = SharedRule(service, source, expiry, comment)
                    else:
                        raise ValueError("Internal: What!?")

                    rules.append(rule)

        return rules
