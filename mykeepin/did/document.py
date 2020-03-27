from mykeepin.crypto.signature import Signature


class DidDocument:
    def __init__(self, document: dict):
        self.public_key = document.get('publicKey')

    def get_public_key(self, key_id: str):
        for pub_key in self.public_key:
            if key_id == pub_key.get('id'):
                return pub_key
        return None

    def has_public_key_with_address(self, address: str) -> bool:
        if address.startswith("0x"):
            address = address[2:]

        for pub_key in self.public_key:
            if pub_key.get('id').endswith(address):
                if pub_key.get('publicKeyHash') and (pub_key.get('publicKeyHash') == address):
                    return True
                if pub_key.get('publicKeyHex'):
                    _address = Signature().to_address(pub_key['publicKeyHex'])
                    if _address == address:
                        return True
        return False
