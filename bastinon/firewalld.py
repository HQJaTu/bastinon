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

from .base import FirewallBase
import logging

log = logging.getLogger(__name__)


class Firewalld(FirewallBase):

    def __init(self, chain_name: str):
        self._chain = chain_name

    def query(self) -> list:
        raise NotImplementedError("Get Firewalld rules not implemented yet!")

    def set(self) -> list:
        raise NotImplementedError("Setting Firewalld rules not implemented yet!")
