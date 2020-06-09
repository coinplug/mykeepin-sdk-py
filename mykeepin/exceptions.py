class DidException(Exception):
    """The base exception class for MyKeepinSDK exceptions."""
    fmt = 'An unspecified error occurred'

    def __init__(self, **kwargs):
        msg = self.fmt.format(**kwargs)
        Exception.__init__(self, msg)
        self.kwargs = kwargs


class ValidationError(DidException):
    fmt = "{param} must be {type_name}"


class RangeError(ValidationError):
    fmt = "Value out of range for param {param}: {range}"


class DidNotFoundException(DidException):
    """Resolver 호출 시 DID가 존재하지 않는 경우"""
    fmt = "{error_message}"


class NotIncludedVcException(DidException):
    """VP 내부에 VC가 누락된 경우"""
    fmt = "{vc_type} is not included in vp."


class NotRegisteredAAException(DidException):
    """VC의 iss가 인증서버에 등록된 AA가 아닐 경우"""
    fmt = "{iss} is not registered in authentication server."


class NotSupportedVcException(DidException):
    """검증하려는 VP 내부 VC의 type이 VC의 iss가 제공하는 타입이 아닐 경우"""
    fmt = "{vc_type} is not supported by {iss}."


class ExpiredVcException(DidException):
    """VC가 만료된 경우 (exp 필드)"""
    fmt = "{vc_type} is expired."


class VcOwnershipException(DidException):
    """VC의 sub 필드값이 사용자의 did와 다른 경우"""
    fmt = "{did} is not a subject of {vc_type}."


class JtiHttpRequestException(DidException):
    """JTI 요청 시 통신 에러가 발생하는 경우 (인터넷이 끊기는 등)"""
    fmt = "Can't request to JTI server: {jti_url}"


class InvalidJtiStatusException(DidException):
    """JTI 요청 시 응답받은 http status code가 200이 아닐 경우"""
    fmt = "JTI status of {vc_type} is invalid: {jti_url}"


class NotFoundJtiFieldException(DidException):
    """VC 에 JTI 필드가 없는 경우"""
    fmt = "Can't find a JTI field in {vc_type}"
