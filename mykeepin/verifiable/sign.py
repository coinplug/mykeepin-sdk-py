from jwcrypto import jwt
from jwcrypto.jwk import JWK, InvalidJWKType

from mykeepin.exceptions import ValidationError
from mykeepin.verifiable import Verifiable
from mykeepin.verifiable.credential import VerifiableCredential
from mykeepin.verifiable.presentation import VerifiablePresentation


class VerifiableSignedJWT:
    @staticmethod
    def __sign(verifiable: Verifiable, algorithm: str, kid: str, nonce: str, key: JWK, is_serialize=False):
        if not isinstance(verifiable, (VerifiableCredential, VerifiablePresentation)):
            raise ValidationError(param='verifiable', type_name=Verifiable)
        claims = verifiable.to_jwt_claims(nonce=nonce)

        if not kid or not isinstance(kid, str):
            raise ValidationError(param='kid', type_name=str)

        if not algorithm or not isinstance(algorithm, str):
            raise ValidationError(param='algorithm', type_name=str)

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
            raise ValidationError(param='algorithm', type_name=str)

        verifier = jwt.JWT(algs=[algorithm])
        verifier.deserialize(jwt=token, key=key)

        if return_claims:
            return verifier.claims
        return verifier

    @classmethod
    def sign(cls, verifiable: Verifiable, kid, nonce, key: JWK):
        return cls.__sign(verifiable, "ES256K", kid, nonce, key, True)

    @classmethod
    def verify(cls, token, key: JWK, return_claims=False):
        return cls.__verify(token, "ES256K", key, return_claims)



