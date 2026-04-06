class VeilSecError(Exception):
    pass


class InvalidCredentialsError(VeilSecError):
    pass


class APIKeyRevokedError(VeilSecError):
    pass


class LGPDConsentRequiredError(VeilSecError):
    pass


class OwnershipProofNotFoundError(VeilSecError):
    pass


class OwnershipTokenExpiredError(VeilSecError):
    pass


class InsufficientOwnershipProofError(VeilSecError):
    pass


class DomainMismatchError(VeilSecError):
    pass


class ScanNotFoundError(VeilSecError):
    pass


class ScanAccessDeniedError(VeilSecError):
    pass


class InputTooLargeError(VeilSecError):
    pass


class UnsupportedLanguageError(VeilSecError):
    pass


class SecurityViolationError(VeilSecError):
    pass


class LLMOutputValidationError(VeilSecError):
    pass


class LLMUnavailableError(VeilSecError):
    pass


class TargetDegradationDetectedError(VeilSecError):
    pass


class ConsecutiveErrorsExceededError(VeilSecError):
    pass
