from datetime import datetime
from .rule import Rule


class UserRule(Rule):

    def __init__(self, owner: str, proto: str, port: int, source_address, expiry: datetime = None, comment: str = None):
        super().__init__(proto, port, source_address, expiry=expiry, comment=comment)
        self.owner = owner

    def __str__(self) -> str:
        return "User {} IPv{} rule: {}/{} allowed from {}, Expiry: {}".format(
            self.owner,
            self.source_address_family,
            self.proto.upper(), self.port, self.source,
            self.expiry
        )
