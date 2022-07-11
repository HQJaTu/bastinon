from datetime import datetime
from .rule import Rule
from .service import Service


class UserRule(Rule):

    def __init__(self, owner: str, service: Service, source_address, expiry: datetime = None, comment: str = None):
        super().__init__(service, source_address, expiry=expiry, comment=comment)
        self.owner = owner

    def __str__(self) -> str:
        return "User {} IPv{} rule: {} allowed from {}, Expiry: {}".format(
            self.owner,
            self.source_address_family,
            self.service, self.source,
            self.expiry
        )
