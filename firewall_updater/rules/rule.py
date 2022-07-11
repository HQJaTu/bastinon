from datetime import datetime
from typing import Tuple, Union
import ipaddress
from .service import Service


class Rule:

    def __init__(self, service: Service, source_address, expiry: datetime = None, comment: str = None):
        self.service = service
        self.source_address_family, self.source_address = self._parse_address(source_address)
        self.expiry = expiry
        self.comment = comment

    @property
    def source(self) -> str:
        return str(self.source_address)

    def has_expired(self) -> bool:
        if not self.expiry:
            return False

        now = datetime.utcnow()
        if now > self.expiry:
            return True

        return False

    def matches(self, service: Service, source_address, comment: str = None) -> bool:
        if self.service.name != service.name:
            return False

        address_family, source = self._parse_address(source_address)
        if self.source_address_family != address_family:
            return False

        if self.source_address != source:
            return False

        if comment:
            if not self.comment or self.comment != comment:
                # print("Rule comment won't match! me: '{}', other: '{}'".format(self.comment, comment))
                return False

        return True

    @staticmethod
    def _parse_address(address_in) -> Tuple[int, Union[
        ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv6Network
    ]]:
        if isinstance(address_in, str):
            # Only parse strings
            try:
                source_parsed = ipaddress.ip_address(address_in)
            except ValueError:
                try:
                    source_parsed = ipaddress.ip_network(address_in)
                except ValueError:
                    raise ValueError("Really weird IP-address definition '{}'!".format(address_in))
        else:
            # Assume ready-parsed object
            source_parsed = address_in

        if isinstance(source_parsed, ipaddress.IPv4Address) or isinstance(source_parsed, ipaddress.IPv4Network):
            return 4, source_parsed
        if isinstance(source_parsed, ipaddress.IPv6Address) or isinstance(source_parsed, ipaddress.IPv6Network):
            return 6, source_parsed

        raise ValueError("Failed to parse IP-address: '{}'".format(address_in))

    def __str__(self) -> str:
        return "IPv{} rule: {} allowed from {}".format(
            self.source_address_family, self.service, self.source
        )

    def __eq__(self, other: 'Rule'):
        return self.matches(other.service, other.source_address, comment=other.comment)
