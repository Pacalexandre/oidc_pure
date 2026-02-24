"""
Pure OAuth2/OIDC Implementation following RFC 6749.

This library provides a pure Python implementation of OAuth2 and OpenID Connect (OIDC)
protocols for authentication with Keycloak and other identity providers.

Main Components:
- OIDCClient: Main client for OAuth2/OIDC operations
- OAuth2Flow: Implementation of RFC 6749 flows
- TokenValidator: JWT token validation
- OIDCDiscovery: OIDC Discovery endpoint support
"""

from oidc_pure.client import OIDCClient
from oidc_pure.exceptions import (
    AuthorizationError,
    DiscoveryError,
    OIDCError,
    TokenError,
    ValidationError,
)
from oidc_pure.models import OIDCConfig, TokenResponse, UserInfo

__version__ = "1.1.3"
__all__ = [
    "OIDCClient",
    "OIDCError",
    "AuthorizationError",
    "TokenError",
    "ValidationError",
    "DiscoveryError",
    "TokenResponse",
    "UserInfo",
    "OIDCConfig",
]
