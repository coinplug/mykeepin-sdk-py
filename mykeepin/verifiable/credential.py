import copy
import datetime

from mykeepin.utils import validate_did_format
from mykeepin.verifiable import Verifiable


class VerifiableCredential(Verifiable):
    def __init__(self, id_=None, types=None, issuer=None, credential_subject=None,
                 issuance_date=None, expiration_date=None):

        self._issuance_date = None
        self._expiration_date = None

        self.issuer = issuer
        self.credential_subject = credential_subject
        self.issuance_date = issuance_date
        self.expiration_date = expiration_date

        super().__init__(id_=id_, types=["VerifiableCredential"] + types)

    @property
    def issuer(self):
        return self._issuer

    @issuer.setter
    def issuer(self, i: str):
        if not isinstance(i, str):
            raise TypeError("'issuer' must be string")
        self._issuer = validate_did_format(i)

    @property
    def issuance_date(self):
        return self._issuance_date

    @issuance_date.setter
    def issuance_date(self, i: datetime.datetime):
        if not isinstance(i, datetime.datetime):
            raise TypeError("'issuance_date' must be datetime")
        if self.expiration_date and (i > self.expiration_date):
            raise ValueError
        self._issuance_date = i

    @property
    def expiration_date(self):
        return self._expiration_date

    @expiration_date.setter
    def expiration_date(self, e: datetime.datetime):
        if e is not None:
            if not isinstance(e, datetime.datetime):
                raise TypeError("'expiration_date' must be datetime")
            if self.issuance_date and (e < self.issuance_date):
                raise ValueError
        self._expiration_date = e

    @property
    def credential_subject(self):
        return self._credential_subject

    @credential_subject.setter
    def credential_subject(self, c: dict):
        if not isinstance(c, dict):
            raise TypeError("'credential_subject' must be dict")
        self._credential_subject = c

    def to_jwt_claims(self, nonce: str):
        claims = {}
        _credential_subject = None
        if self.credential_subject.get('id'):
            _credential_subject = copy.deepcopy(self.credential_subject)
            _credential_subject.pop('id')
            claims['sub'] = self.credential_subject['id']

        claims.update({
            'iss': self.issuer,
            'nonce': nonce,
            'vc': {
                '@context': ["https://w3id.org/credentials/v1"],
                'type': self.types,
                'credentialSubject': _credential_subject
            },
        })
        if self.expiration_date:
            claims['exp'] = int(self._expiration_date.timestamp())
        if self.issuance_date:
            claims['iat'] = int(self._issuance_date.timestamp())
        if self.id_:
            claims['jti'] = self.id_

        return claims
