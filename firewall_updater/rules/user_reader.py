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
from typing import List, Tuple, Union
from lxml import etree
from pwd import getpwnam
from datetime import datetime
from .service_reader import ServiceReader
from .rule import Rule
import logging

log = logging.getLogger(__name__)


class RuleReader:
    USERS_PATH = r"users"

    def __init__(self, rule_path: str):
        user_rule_path = "{}/{}".format(rule_path, self.USERS_PATH)
        if not os.path.exists(user_rule_path):
            raise ValueError("Rule path '{}' doesn't exist!".format(user_rule_path))
        if not os.path.isdir(user_rule_path):
            raise ValueError("Rule path '{}' is a file, not directory!".format(user_rule_path))

        self._path = rule_path

    def _rule_filename(self, user: str) -> str:
        filename = "{}/{}/{}.xml".format(self._path, self.USERS_PATH, user)

        return filename

    def has_rules_for(self, user: str) -> bool:
        filename = self._rule_filename(user)

        return os.path.exists(filename)

    def read_all_users(self) -> list:
        reader = ServiceReader(self._path)
        services = reader.read_all()

        all_rules = []
        user_rules_path = "{}/{}".format(self._path, self.USERS_PATH)
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
                rules = self._user_rule_reader(user, xml_file, services)
                all_rules.extend(rules)

        return all_rules

    def read(self, user: str) -> list:
        if not self.has_rules_for(user):
            raise ValueError("Cannot read rules for user {}! No rules found.".format(user))

        reader = ServiceReader(self._path)
        services = reader.read_all()
        filename = self._rule_filename(user)

        rules = self._user_rule_reader(user, filename, services)

        return rules

    @staticmethod
    def _user_rule_reader(user: str, user_rules_filename: str, services: dict) -> List[Rule]:
        log.debug("For user {}, reading rule file: {}".format(user, user_rules_filename))
        root = etree.parse(user_rules_filename)
        schema_filename = "{}/xml-schemas/user_rule.xsd".format(sys.prefix)
        schema_doc = etree.parse(schema_filename)
        schema = etree.XMLSchema(schema_doc)
        if not schema.validate(root):
            raise ValueError("Rule-XML {} is not valid according to XSD file {}! Error: {}".format(
                user_rules_filename, schema_filename, schema.error_log))

        rules = []
        for zone_elem in root.iter(tag="zone"):
            service_elems = zone_elem.iter(tag="service")
            for service_elem in service_elems:
                if 'name' not in service_elem.attrib:
                    raise ValueError('Rule definition, service needs to have name! User: {}'.format(user))
                service_name = service_elem.attrib['name']
                if service_name not in services:
                    raise ValueError("Rule definition, service is unknown '{}'! User: {}".format(service_name, user))
                service = services[service_name]
                source_elems = zone_elem.iter(tag="source")
                for source_elem in source_elems:
                    if 'address' not in source_elem.attrib:
                        raise ValueError('Rule definition, service needs to have name! User: {}'.format(user))
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

                    for service_def in service:
                        rule = Rule(service_def[0], service_def[1], source, expiry, comment)
                        rules.append(rule)

        return rules
