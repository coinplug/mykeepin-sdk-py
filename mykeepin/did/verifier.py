import json

from web3 import Web3
from jwcrypto import jwk
from jwcrypto.common import base64url_decode
from ecdsa.keys import VerifyingKey
from ecdsa.curves import SECP256k1

from mykeepin.crypto.signature import Signature
from mykeepin.did.document import DidDocument
from mykeepin.did.resolver import DIDResolver
from mykeepin.verifiable.sign import VerifiableSignedJWT


class DidVerifier:
    def __init__(self, did=None):
        self.document = self.__get_document(did)
        self.vc_list = []

    @staticmethod
    def __get_document(did: str) -> DidDocument:
        resolver = DIDResolver()
        return resolver.get_document(did, False)

    @staticmethod
    def __generate_nonce(service_id, state, code, type_=0, data='') -> str:
        if data.startswith('0x'):
            data = data[2:]
        nonce = Web3.soliditySha3(
            abi_types=['string', 'string', 'uint', 'string', 'string'],
            values=[code, service_id, type_, state, data]
        )
        return nonce.hex()

    def verify_signature_for_auth(self, service_id: str, state: str, code: str,
                                  type_: int, data_hash: str, signature: str) -> bool:
        nonce = self.__generate_nonce(service_id, state, code, type_, data_hash)
        address = self.verify_signature(nonce=nonce, signature=signature)
        return self.document.has_public_key_with_address(address)

    @staticmethod
    def verify_signature(nonce: str, signature: str) -> str:
        address = Signature().address_from_signature(nonce, signature)
        return address

    def verify_jws(self, raw_jws: str, did_document: DidDocument or None):
        c = raw_jws.split('.')
        data = {
            'protected': json.loads(base64url_decode(str(c[0])).decode('utf-8')),
            'payload': json.loads(base64url_decode(str(c[1])).decode('utf-8')),
            'signature': base64url_decode(str(c[2]))
        }
        key_id = data['protected']['kid']
        issuer = data['payload']['iss']

        if did_document is None:
            _cache_pub_key_of_issuer = self.document.get_public_key(key_id=key_id)
            if not _cache_pub_key_of_issuer:
                self.document = self.__get_document(issuer)

        pub_key_of_issuer = self.document.get_public_key(key_id=key_id)
        if not pub_key_of_issuer:
            raise Exception(f"Not Found KeyID in did document {issuer}")

        user_pub_key_hex = pub_key_of_issuer.get('publicKeyHex')
        if not user_pub_key_hex:
            return None

        user_pub_key = jwk.JWK().from_pem(
            VerifyingKey.from_string(
                bytes.fromhex(user_pub_key_hex), curve=SECP256k1
            ).to_pem()
        )
        return VerifiableSignedJWT().verify(token=raw_jws, key=user_pub_key)

    def extract_credentials_from_presentation(self, raw_vp: str):
        dict_vp = json.loads(raw_vp)
        for vc in dict_vp['vp'].get('verifiableCredential'):
            data = json.loads(self.verify_jws(vc, None).claims)
            self.vc_list.append(data)

    def find_verifiable_credential(self, issuer_did, credential_name):
        for vc in self.vc_list:
            if vc['iss'] == issuer_did and credential_name in vc['vc']['type']:
                return vc
        return None

