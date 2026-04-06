from enum import Enum


class ScanType(str, Enum):
    SAST = "SAST"
    DAST = "DAST"


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationMethod(str, Enum):
    DNS_TXT = "DNS_TXT"
    WELL_KNOWN = "WELL_KNOWN"
    HTTP_HEADER = "HTTP_HEADER"


class Plan(str, Enum):
    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"


class FindingCategory(str, Enum):
    PII_LEAK = "PII_LEAK"
    BROKEN_AUTH = "BROKEN_AUTH"
    INJECTION = "INJECTION"
    SENSITIVE_EXPOSURE = "SENSITIVE_EXPOSURE"
    MISSING_CONSENT = "MISSING_CONSENT"
    MISSING_RETENTION = "MISSING_RETENTION"
    MISSING_DELETION = "MISSING_DELETION"
    PROMPT_INJECTION = "PROMPT_INJECTION"


class SupportedLanguage(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
