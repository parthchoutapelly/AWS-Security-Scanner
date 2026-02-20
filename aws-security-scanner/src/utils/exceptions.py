"""Custom exceptions for AWS Security Scanner."""


class ScannerError(Exception):
    """Base exception for the scanner."""


class AWSAuthenticationError(ScannerError):
    """Raised when AWS authentication fails."""


class AWSPermissionError(ScannerError):
    """Raised when the scanner lacks required AWS permissions."""


class ConfigurationError(ScannerError):
    """Raised when configuration is invalid."""


class AuditorError(ScannerError):
    """Raised when an auditor encounters an unrecoverable error."""


class ReportGenerationError(ScannerError):
    """Raised when report generation fails."""
