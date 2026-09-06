class SecurityMiscError(Exception):
    """Base exception for SECURITY-MISC."""


class ValidationError(SecurityMiscError):
    """Raised when user input fails validation."""


class ToolExecutionError(SecurityMiscError):
    """Raised when a tool cannot complete its operation."""