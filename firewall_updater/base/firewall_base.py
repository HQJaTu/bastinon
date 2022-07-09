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
from typing import Tuple, List, Union
from datetime import datetime
import logging

log = logging.getLogger(__name__)


class FirewallBase(ABC):

    @abstractmethod
    def query(self) -> List[Tuple[str, int, str]]:
        pass

    @abstractmethod
    def set(self, rules: List[Tuple[str, int, str]]) -> list:
        pass

    @abstractmethod
    def simulate(self, rules: List[Tuple[str, int, str, Union[datetime, None]]], print_rules: bool) -> Tuple[
        List[str], List[str]
    ]:
        pass

    @abstractmethod
    def needs_update(self, rules: List[Tuple[str, int, str, Union[datetime, None]]]) -> bool:
        pass
