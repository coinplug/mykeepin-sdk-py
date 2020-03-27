def validate_did_format(did: str) -> str:
    if not isinstance(did, str):
        raise TypeError("'did' must be string")
    if not did.startswith("did:meta"):
        raise ValueError("invalid did format")
    return did
