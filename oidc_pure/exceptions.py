"""Custom exceptions for OIDC/OAuth2 operations."""


class OIDCError(Exception):
    """Base exception for all OIDC/OAuth2 errors."""

    def __init__(self, message: str, error_code: str | None = None):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class AuthorizationError(OIDCError):
    """Raised when authorization flow fails."""

    pass


class TokenError(OIDCError):
    """Raised when token operations fail."""

    pass


class ValidationError(OIDCError):
    """Raised when token or response validation fails."""

    pass


class DiscoveryError(OIDCError):
    """Raised when OIDC discovery fails."""

    pass


class NetworkError(OIDCError):
    """Raised when network operations fail."""

    pass
