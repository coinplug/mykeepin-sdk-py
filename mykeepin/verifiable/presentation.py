from mykeepin.utils import validate_did_format
from mykeepin.verifiable import Verifiable


class VerifiablePresentation(Verifiable):
    def __init__(self, id_=None, issuer=None, types=None, verifiable_credentials=None):
        self.issuer = issuer
        self.verifiable_credentials = verifiable_credentials
        super().__init__(id_=id_, types=["VerifiablePresentation"] + types)

    @property
    def issuer(self) -> str:
        return self._issuer

    @issuer.setter
    def issuer(self, i: str):
        if not isinstance(i, str):
            raise TypeError("'issuer' must be string")
        self._issuer = validate_did_format(i)

    @property
    def verifiable_credentials(self) -> [str]:
        return self._verifiable_credentials

    @verifiable_credentials.setter
    def verifiable_credentials(self, vcs: [str]):
        if not isinstance(vcs, list):
            raise TypeError("'verifiable_credentials' must be list")
        for vc in vcs:
            if not isinstance(vc, str):
                raise ValueError("'raw_vc' must be string")
            if not vc.count('.') == 2:
                raise ValueError("VC format unrecognized")
        self._verifiable_credentials = vcs

    def to_jwt_claims(self, nonce: str) -> dict:
        claims = {
            'iss': self.issuer,
            'vp': {
                '@context': ["https://w3id.org/credentials/v1"],
                'type': self.types,
                'verifiableCredential': self.verifiable_credentials,
            },
            'nonce': nonce,
        }
        if self.id_:
            claims['jti'] = self.id_

        return claims
