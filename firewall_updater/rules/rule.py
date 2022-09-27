from datetime import datetime
from typing import Tuple, Union
import ipaddress
from .service import Service


class Rule:
    DEFAULT_MAX_IPV4_NETWORK_SIZE = 16
    DEFAULT_MAX_IPV6_NETWORK_SIZE = 48

    def __init__(self, service: Service, source_address, expiry: datetime = None, comment: str = None):
        self.service = service
        self.source_address_family = None
        self.source_address = None
        self.source_is_network = None
        self.expiry = expiry
        self.comment = comment

        self._max_ipv4_network_size = self.DEFAULT_MAX_IPV4_NETWORK_SIZE
        self._max_ipv6_network_size = self.DEFAULT_MAX_IPV6_NETWORK_SIZE

        self.source = source_address

    @property
    def source(self) -> str:
        return str(self.source_address)

    @source.setter
    def source(self, source_address) -> None:
        address_family, source, is_network = self._parse_address(source_address)

        self.source_address_family = address_family
        self.source_address = source
        self.source_is_network = is_network

    @property
    def max_ipv4_network_size(self) -> int:
        return self._max_ipv4_network_size

    @max_ipv4_network_size.setter
    def max_ipv4_network_size(self, size: int) -> None:
        if size < 1 or size > 32:
            raise ValueError("Cannot set IPv4 network size policy of /{}!".format(size))

        self._max_ipv4_network_size = size

    @property
    def max_ipv6_network_size(self) -> int:
        return self._max_ipv6_network_size

    @max_ipv6_network_size.setter
    def max_ipv6_network_size(self, size: int) -> None:
        if size < 1 or size > 128:
            raise ValueError("Cannot set IPv6 network size policy of /{}!".format(size))

        self._max_ipv6_network_size = size

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

        address_family, source, _ = self._parse_address(source_address)
        if self.source_address_family != address_family:
            return False

        if self.source_address != source:
            return False

        if comment:
            if not self.comment or self.comment != comment:
                # print("Rule comment won't match! me: '{}', other: '{}'".format(self.comment, comment))
                return False

        return True

    def network_size_valid(self, raise_on_invalid: bool) -> Union[bool, None]:
        if not self.source_is_network:
            # Not applicable
            return None

        if self.source_address_family == 4:
            if self.source_address.prefixlen < self.max_ipv4_network_size:
                if raise_on_invalid:
                    raise ValueError("IPv4 network too big! Requested /{}, allowed /{}".format(
                        self.source_address.prefixlen, self.max_ipv4_network_size
                    ))
                else:
                    return False
            else:
                return True
        elif self.source_address_family == 6:
            if self.source_address.prefixlen < self.max_ipv6_network_size:
                if raise_on_invalid:
                    raise ValueError("IPv6 network too big! Requested /{}, allowed /{}".format(
                        self.source_address.prefixlen, self.max_ipv6_network_size
                    ))
                else:
                    return False
            else:
                return True
        else:
            raise RuntimeError("Internal: Unknown IP-address family.")

    @staticmethod
    def _parse_address(address_in) -> Tuple[int, Union[
        ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv6Network
    ], bool]:
        """
        Parse input address.
        :param address_in: Address to parse: If string, parse it into object. If object, sanity check only.
        :return: IP-address family (4 or 6), parsed object, True = is network False = single address
        """
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

        if isinstance(source_parsed, ipaddress.IPv4Address):
            return 4, source_parsed, False
        if isinstance(source_parsed, ipaddress.IPv4Network):
            return 4, source_parsed, True
        if isinstance(source_parsed, ipaddress.IPv6Address):
            return 6, source_parsed, False
        if isinstance(source_parsed, ipaddress.IPv6Network):
            return 6, source_parsed, True

        raise ValueError("Failed to parse IP-address: '{}'".format(address_in))

    def __str__(self) -> str:
        return "IPv{} rule: {} allowed from {}".format(
            self.source_address_family, self.service, self.source
        )

    def __eq__(self, other: 'Rule'):
        return self.matches(other.service, other.source_address, comment=other.comment)
