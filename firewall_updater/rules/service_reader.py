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
from lxml import etree
import logging

log = logging.getLogger(__name__)


class ServiceReader:
    SERVICES_PATH = r"services"
    PROTOCOL_TCP = r'tcp'
    PROTOCOL_UDP = r'udp'
    PROTOCOLS = [PROTOCOL_TCP, PROTOCOL_UDP]

    def __init__(self, rule_path: str):
        services_path = "{}/{}".format(rule_path, self.SERVICES_PATH)
        if not os.path.exists(services_path):
            raise ValueError("Rule path '{}' doesn't exist!".format(services_path))
        if not os.path.isdir(services_path):
            raise ValueError("Rule path '{}' is a file, not directory!".format(services_path))

        self._path = rule_path

    def read_all(self) -> dict:
        services_out = {}
        services_path = "{}/{}".format(self._path, self.SERVICES_PATH)
        for item in os.listdir(services_path):
            if not item.endswith('.xml'):
                continue
            xml_file = os.path.join(services_path, item)
            if os.path.isfile(xml_file):
                service_definition = self._read_services(xml_file)
                service_name = item.replace('.xml', '')
                services_out[service_name] = service_definition

        return services_out

    def _read_services(self, filename: str) -> list:
        log.debug("Reading service file: {}".format(filename))
        root = etree.parse(filename)
        schema_filename = "{}/xml-schemas/service.xsd".format(sys.prefix)
        schema_doc = etree.parse(schema_filename)
        schema = etree.XMLSchema(schema_doc)
        if not schema.validate(root):
            raise ValueError("Service-XML {} is not valid! Error: {}".format(filename, schema.error_log))

        service_definition = []
        for elem in root.iter():
            if elem.tag == "service":
                continue
            if elem.tag != "port":
                continue

            if 'protocol' not in elem.attrib:
                raise ValueError("Need to have 'protocol' in service-definition! Service file: {}".format(filename))
            if 'port' not in elem.attrib:
                raise ValueError("Need to have 'port' in service-definition! Service file: {}".format(filename))
            if elem.attrib['protocol'] not in self.PROTOCOLS:
                raise ValueError("Unknown protocol '{}'! Service file: {}".format(elem.attrib['protocol'], filename))

            ip_protocol = elem.attrib['protocol']
            port = int(elem.attrib['port'])
            service = (ip_protocol, port)

            service_definition.append(service)

        return service_definition
