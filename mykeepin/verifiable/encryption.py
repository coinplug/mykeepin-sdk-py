from jwcrypto import jwe
from jwcrypto.jwk import JWK


class VerifiableEncryptJWE:
    def __init__(self, key: JWK):
        self.key = key

    def encrypt(self, payload: str) -> str:
        header = {"alg": "RSA-OAEP-256", "enc": "A128CBC-HS256"}
        encrypted = jwe.JWE(
            payload.encode('utf-8'), recipient=self.key.public(), protected=header
        )
        return encrypted.serialize(True)

    def decrypt(self, enc: str) -> str:
        decrypted = jwe.JWE()
        decrypted.deserialize(enc, key=self.key)
        return decrypted.payload.decode('utf-8')
