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

from abc import ABC, abstractmethod
from typing import Tuple, List, Union, Dict
from datetime import datetime
from ..rules import UserRule, Service
import logging

log = logging.getLogger(__name__)


class FirewallBase(ABC):

    def __init__(self, services: Dict[str, Service]):
        self.services = services

    @abstractmethod
    def query(self, rules: List[UserRule]) -> List[Tuple[UserRule, bool]]:
        """
        Query for currently active firewall rules.
        Match the rules against all users' rules.
        :param rules: Users' rules
        :param services: All servies
        :return: list of tuples, tuple: user rule object, rule in effect
        """
        pass

    @abstractmethod
    def query_readable(self, rules: List[UserRule]) -> List[str]:
        """
        Query for currently active firewall rules.
        Match the rules against all users' rules.
        :param rules: Users' rules
        :param services: All servies
        :return: list of strings
        """
        pass

    @abstractmethod
    def set(self, rules: List[UserRule], force=False) -> None:
        """
        Set rules to firewall
        :param rules: List of firewall rules to set
        :param force: Force set all rules
        :return:
        """
        pass

    @abstractmethod
    def simulate(self, rules: List[UserRule]) -> Union[bool, List[str]]:
        """
        Show what would happen if set rules to firewall
        :param rules:
        :return: list of strings, what firewall would need to do to make rules effective
        """
        pass

    @abstractmethod
    def needs_update(self, rules: List[UserRule]) -> bool:
        """
        Query if any rules requested by users are not in effect
        :param rules: list of user rules
        :return: bool, True = changes needed, False = all rules effective
        """
        pass
