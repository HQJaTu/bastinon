from typing import List, Union, Dict
from .rule import Rule
from .service import Service


class FirewallRule(Rule):

    def __init__(self, proto: str, port: int, service: Service, source_address, comment: str = None):
        super().__init__(service, source_address, comment=comment)
        self.proto = proto
        self.port = port
        self.expiry = None

    def has_expired(self) -> bool:
        raise RuntimeError("IptablesRule has no expiry!")

    def __str__(self) -> str:
        return "Firewall IPv{} rule: {} allowed from {}".format(
            self.source_address_family,
            self.service, self.source
        )

    @staticmethod
    def find_service(proto: str, port: int, services: Dict[str, Service]) -> Union[Service, None]:
        for service_name, service in services.items():
            if service.matches(proto, port):
                return service

        return None
