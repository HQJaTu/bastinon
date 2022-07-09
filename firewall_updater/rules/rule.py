from datetime import datetime
from typing import Tuple, Union
import ipaddress


class Rule:
    PROTOCOL_TCP = r'tcp'
    PROTOCOL_UDP = r'udp'
    PROTOCOLS = [PROTOCOL_TCP, PROTOCOL_UDP]

    def __init__(self, proto: str, port: int, source_address, expiry: datetime = None, comment: str = None):
        if proto not in self.PROTOCOLS:
            raise ValueError("Proto '{}' not allowed! Known are: {}".format(proto, ', '.join(self.PROTOCOLS)))
        if port < 1:
            raise ValueError("Port {} not allowed! Must be between 1 and 65535!".format(port))
        self.proto = proto
        self.port = port
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

    def matches(self, proto: str, port: int, source_address, comment: str = None):
        if proto not in self.PROTOCOLS:
            raise ValueError("Proto '{}' not allowed! Known are: {}".format(proto, ', '.join(self.PROTOCOLS)))
        if port < 1:
            raise ValueError("Port {} not allowed! Must be between 1 and 65535!".format(port))

        if self.proto != proto:
            return False

        if self.port != port:
            return False

        address_family, source = self._parse_address(source_address)
        if self.source_address_family != address_family:
            return False

        if self.source_address != source:
            return False

        if comment:
            if not self.comment or self.comment == comment:
                return False

        return True

    @staticmethod
    def _parse_address(address_in) -> Tuple[int, Union[
        ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv6Network
    ]]:
        try:
            source_parsed = ipaddress.ip_address(address_in)
        except ValueError:
            try:
                source_parsed = ipaddress.ip_network(address_in)
            except ValueError:
                raise ValueError("Really weird IP-address definition '{}'!".format(address_in))

        if isinstance(source_parsed, ipaddress.IPv4Address) or isinstance(source_parsed, ipaddress.IPv4Network):
            return 4, source_parsed
        if isinstance(source_parsed, ipaddress.IPv6Address) or isinstance(source_parsed, ipaddress.IPv6Network):
            return 6, source_parsed

        raise ValueError("Failed to parse IP-address: '{}'".format(address_in))

    def __str__(self) -> str:
        return "IPv{} rule: {}/{} allowed from {}".format(
            self.source_address_family, self.proto.upper(), self.port, self.source
        )
