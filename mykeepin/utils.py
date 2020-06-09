from mykeepin.exceptions import ValidationError


def validate_did_format(did: str) -> str:
    if not isinstance(did, str):
        raise ValidationError(param='did', type_name=str)
    if not did.startswith("did:meta"):
        raise ValueError("invalid did format")
    return did
