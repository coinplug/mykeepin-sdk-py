from jwcrypto import jwt
from jwcrypto.jwk import JWK, InvalidJWKType

from mykeepin.verifiable import Verifiable
from mykeepin.verifiable.credential import VerifiableCredential
from mykeepin.verifiable.presentation import VerifiablePresentation


class VerifiableSignedJWT:
    @staticmethod
    def __sign(verifiable: Verifiable, algorithm: str, kid: str, nonce: str, key: JWK, is_serialize=False):
        if not isinstance(verifiable, (VerifiableCredential, VerifiablePresentation)):
            raise TypeError("'verifiable' must be Verifiable")
        claims = verifiable.to_jwt_claims(nonce=nonce)

        if not kid or not isinstance(kid, str):
            raise TypeError("'kid' must be string")

        if not algorithm or not isinstance(algorithm, str):
            raise TypeError("'algorithm' must be string")

        header = {"kid": kid, "typ": "JWT", "alg": algorithm}
        jwts = jwt.JWT(header=header, claims=claims, algs=[algorithm])
        jwts.make_signed_token(key)

        if is_serialize:
            return jwts.serialize()
        return jwts

    @staticmethod
    def __verify(token: str, algorithm: str, key: JWK, return_claims=False):
        if not isinstance(key, JWK):
            raise InvalidJWKType
        if not algorithm or not isinstance(algorithm, str):
            raise TypeError("'algorithm' must be string")

        verifier = jwt.JWT(algs=[algorithm])
        verifier.deserialize(jwt=token, key=key)

        if return_claims:
            return verifier.claims
        return verifier

    def sign(self, verifiable: Verifiable, kid, nonce, key: JWK):
        return self.__sign(verifiable, "ES256K", kid, nonce, key, True)

    def verify(self, token, key: JWK, return_claims=False):
        return self.__verify(token, "ES256K", key, return_claims)



