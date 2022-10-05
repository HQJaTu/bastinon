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
from .user_reader import RuleReader
from .service_reader import ServiceReader
from .user_rule import UserRule
from .service import Service
import logging

log = logging.getLogger(__name__)


class RuleWriter(RuleReader):
    XML_NS = r"https://raw.githubusercontent.com/HQJaTu/firewall-updater/master/xml/user_rule.xsd"

    def write(self, user: str, rules: List[UserRule]) -> List[UserRule]:
        """
        Write a set of user's rules into XML
        :param user: user whose rules these are
        :param rules: list of rules to write
        :return: new set of user's rules
        """
        # Sanity: Set of rules need to be for same user
        # Hint: Set of rules can be empty!
        for rule in rules:
            if rule.owner != user:
                raise ValueError("Rule '{}' isn't for user '{}'! Cannot continue.".format(rule, user))

        # Sanity: Already checked in Rule-class:
        # - Protocol needs to be a known one
        # - Port need to be in allowed range for that protocol
        # - Source address needs to be valid IPv4 or IPv6 address or network

        # Sanity:
        if not self.has_rules_for(user):
            raise ValueError("No existing rules for user '{}'. Refusing to create initial ones.".format(user))

        # Go writing!
        if not self.all_services:
            reader = ServiceReader(self._path)
            self.all_services = reader.read_all()

        filename = self._rule_filename(user)

        rules = self._user_rule_writer(user, filename, self.all_services, rules)

        return rules

    def _user_rule_writer(self, user: str, user_rules_filename: str, services: Dict[str, Service],
                          rules: List[UserRule]) -> List[UserRule]:
        # Prep: See which services are present in the rules
        services_in_rules = list(set([r.service.code for r in rules]))

        # Go XML!
        xml_schema_url = r"http://www.w3.org/2001/XMLSchema-instance"
        etree.register_namespace("xsi", xml_schema_url)
        location_attribute = '{{{}}}noNamespaceSchemaLocation'.format(xml_schema_url)

        user_elem = etree.Element('user', attrib={location_attribute: self.XML_NS})
        for service in services_in_rules:
            zone_elem = etree.Element('zone')
            user_elem.append(zone_elem)

            for rule in rules:
                if rule.service.code != service:
                    continue

                source_elem = etree.Element('source', address=rule.source)
                if rule.comment:
                    source_elem.attrib['comment'] = rule.comment
                if rule.expiry:
                    source_elem.attrib['expires'] = rule.expiry.isoformat()
                zone_elem.append(source_elem)

            service_elem = etree.Element('service', name=service)
            zone_elem.append(service_elem)

        # Output:
        if False:
            xml = etree.tostring(user_elem, xml_declaration=True, encoding='UTF-8', pretty_print=True).decode("utf-8")
            print(xml)
        et = etree.ElementTree(user_elem)
        et.write(user_rules_filename, xml_declaration=True, encoding='UTF-8', pretty_print=True)

        return self._user_rule_reader(user, user_rules_filename, services)
