from typing import Tuple, Generator


class Service:
    PROTOCOL_TCP = r'tcp'
    PROTOCOL_UDP = r'udp'
    PROTOCOLS = [PROTOCOL_TCP, PROTOCOL_UDP]

    PORTS = {
        PROTOCOL_TCP: (1, 65535),
        PROTOCOL_UDP: (1, 65535),
    }

    def __init__(self, code: str, name: str, protocol_definition: dict):
        """
        Construct a firewall service
        :param protocol_definition: dict of known protocols, key is protocol, value is list of ports
        """
        self.code = code
        self.name = name
        if not protocol_definition:
            raise ValueError("Need a protocol definition with ports!")

        for proto in protocol_definition.keys():
            if proto not in self.PROTOCOLS:
                raise ValueError("Proto '{}' not allowed! Known are: {}".format(proto, ', '.join(self.PROTOCOLS)))
            if not isinstance(protocol_definition[proto], list):
                raise ValueError("Proto '{}' definition invalid! Need to have a list of ports".format(proto))
            for port in protocol_definition[proto]:
                if port < self.PORTS[proto][0] or port > self.PORTS[proto][1]:
                    raise ValueError("Port {} not allowed! Must be between {} and {}!".format(
                        port, self.PORTS[proto][0], self.PORTS[proto][1]
                    ))

        self.protocol_definition = protocol_definition

    def matches(self, proto: str, port: int) -> bool:
        """
        Match protocol/port-pair into a service
        :param proto: protocol to match
        :param port: port to match
        :return: boolean value if given proto/port-pair matches this service
        """
        if proto not in self.protocol_definition:
            return False

        matched_proto_definition = self.protocol_definition[proto]
        if port in matched_proto_definition:
            return True

        return False

    def __str__(self) -> str:
        out = ""
        for proto in self.protocol_definition.keys():
            if out:
                out += " and "
            out += "{}/{}".format(
                proto.upper(),
                ','.join([str(port) for port in self.protocol_definition[proto]])
            )

        return "{} [{}]".format(self.name, out)

    def enumerate(self) -> Generator[Tuple[str, int], None, None]:
        for proto in self.protocol_definition.keys():
            for port in self.protocol_definition[proto]:
                yield proto, port
