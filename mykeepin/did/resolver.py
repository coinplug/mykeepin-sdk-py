import requests

from mykeepin.constans import MAINNET_RESOLVER_URL, TESTNET_RESOLVER_URL
from mykeepin.exceptions import DidNotFoundException

from mykeepin.utils import validate_did_format
from mykeepin.did.document import DidDocument


class DIDResolver:
    def __init__(self):
        self.resolver_url = None

    def check_resolver_url(self, did: str):
        validate_did_format(did)
        resolver_url = TESTNET_RESOLVER_URL
        if not did.startswith("did:meta:testnet"):
            resolver_url = MAINNET_RESOLVER_URL
        self.resolver_url = resolver_url

    def get_document(self, did: str, no_cache: bool) -> DidDocument:
        self.check_resolver_url(did)
        try:
            r = requests.get(
                f'{self.resolver_url}identifiers/{did}',
                headers={'no-cache': 'true' if no_cache else 'false'}
            )
            data = r.json()
            if not data.get('didDocument'):
                raise DidNotFoundException(error_message=data.get('message'))

        except Exception as e:
            raise DidNotFoundException(error_message=e)

        did_document = DidDocument(document=data['didDocument'])
        _method_metadata = data.get('methodMetadata')
        _resolve_metadata = data.get('resolverMetadata')

        return did_document
