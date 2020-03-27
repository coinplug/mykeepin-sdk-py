import eth_keys

from web3 import Web3

from eth_utils import big_endian_to_int
from eth_keys.datatypes import PublicKey


class Signature:
    @staticmethod
    def __verify_precondition(condition, message):
        if not condition:
            raise Exception(message)

    @staticmethod
    def to_address(hexstr) -> str:
        hashed = Web3.sha3(hexstr=hexstr)
        address = Web3.toHex(hashed[-20:])
        return address

    def public_key_from_signature(self, message: str, signature: str) -> PublicKey:
        if signature.startswith("0x"):
            signature = signature[2:]
        bytes_sig = bytes.fromhex(signature)
        self.__verify_precondition(len(bytes_sig) == 65, "'signature' must be 65 bytes")

        vrs = (
            big_endian_to_int(bytes_sig[64:65]) - 27,
            big_endian_to_int(bytes_sig[0:32]),
            big_endian_to_int(bytes_sig[32:64]),
        )
        sig = eth_keys.keys.Signature(vrs=vrs)
        pub_key = eth_keys.keys.ecdsa_recover(Web3.keccak(text=message), sig)
        return pub_key

    def address_from_signature(self, message: str, signature: str) -> str:
        return self.public_key_from_signature(message, signature).to_address()


