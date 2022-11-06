from datetime import datetime
from .rule import Rule
from .service import Service


class SharedRule(Rule):

    def __init__(self, service: Service, source_address, expiry: datetime = None, comment: str = None):
        super().__init__(service, source_address, expiry=expiry, comment=comment)

    def __str__(self) -> str:
        return "Shared IPv{} rule: {} allowed from {}, Expiry: {}".format(
            self.source_address_family,
            self.service, self.source,
            self.expiry
        )

    def __hash__(self) -> int:
        return hash(self._hash_tuple())

    def _hash_tuple(self) -> tuple:
        return (
            1, self.service.code, self.source_address_family, self.source_address, self.expiry, self.comment
        )
