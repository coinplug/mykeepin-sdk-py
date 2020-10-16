# MyKeepin SDK for Python 

## SDK 소개
- mykeepin-verify-sdk
- https://github.com/METADIUM/did-resolver-java-client
- https://github.com/METADIUM/verifiable-credential-java


## 주요 기능
### DID Document
- DID Document Resolver
- DID Document Verifier
- JWS secp256k1 sign/verify
- JWE encrypt/decrypt

### AA & SP
- MyKeepin 앱에서 전달받은 서명 또는 VP를 검증
- Mykeepin 앱에서 VC를 발급받기 위해 AA에게 전달한 VP 검증
- 검증된 VP에서 VC 목록을 반환
- 검증된 VP에서 issuer와 credential 이름으로 특정 VC를 조회


## SDK 설치
```
pip install mykeepin-sdk
```
