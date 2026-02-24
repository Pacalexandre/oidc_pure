"""Data models for OIDC/OAuth2 responses and configurations."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class OIDCConfig:
    """OIDC Provider configuration from discovery endpoint."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    end_session_endpoint: str | None = None
    scopes_supported: list[str] = field(default_factory=list)
    response_types_supported: list[str] = field(default_factory=list)
    grant_types_supported: list[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: list[str] = field(default_factory=list)
    claims_supported: list[str] = field(default_factory=list)
    code_challenge_methods_supported: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OIDCConfig":
        """Create OIDCConfig from discovery response."""
        return cls(
            issuer=data["issuer"],
            authorization_endpoint=data["authorization_endpoint"],
            token_endpoint=data["token_endpoint"],
            userinfo_endpoint=data["userinfo_endpoint"],
            jwks_uri=data["jwks_uri"],
            end_session_endpoint=data.get("end_session_endpoint"),
            scopes_supported=data.get("scopes_supported", []),
            response_types_supported=data.get("response_types_supported", []),
            grant_types_supported=data.get("grant_types_supported", []),
            token_endpoint_auth_methods_supported=data.get(
                "token_endpoint_auth_methods_supported", []
            ),
            claims_supported=data.get("claims_supported", []),
            code_challenge_methods_supported=data.get(
                "code_challenge_methods_supported", []
            ),
        )


@dataclass
class TokenResponse:
    """OAuth2 token response as per RFC 6749."""

    access_token: str
    token_type: str
    expires_in: int | None = None
    refresh_token: str | None = None
    scope: str | None = None
    id_token: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenResponse":
        """Create TokenResponse from token endpoint response."""
        return cls(
            access_token=data["access_token"],
            token_type=data["token_type"],
            expires_in=data.get("expires_in"),
            refresh_token=data.get("refresh_token"),
            scope=data.get("scope"),
            id_token=data.get("id_token"),
        )


@dataclass
class UserInfo:
    """User information from userinfo endpoint."""

    sub: str  # Subject identifier
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    email: str | None = None
    email_verified: bool | None = None
    preferred_username: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UserInfo":
        """
        Create UserInfo from userinfo endpoint response.
        
        Suporta tanto o formato OIDC padrão quanto providers OAuth2 puros
        como GitHub, que usam estruturas diferentes.
        
        Mapeamentos:
        - GitHub 'id' -> OIDC 'sub'
        - GitHub 'login' -> OIDC 'preferred_username'
        """
        # Extract known fields
        known_fields = {
            "sub",
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "preferred_username",
        }
        
        # Separate known and unknown claims
        known = {k: v for k, v in data.items() if k in known_fields}
        unknown = {k: v for k, v in data.items() if k not in known_fields}
        
        # Mapear campos de providers não-OIDC (GitHub, etc)
        # GitHub usa 'id' ao invés de 'sub'
        if "sub" not in known and "id" in data:
            known["sub"] = str(data["id"])
            unknown.pop("id", None)
        
        # GitHub usa 'login' ao invés de 'preferred_username'
        if "preferred_username" not in known and "login" in data:
            known["preferred_username"] = data["login"]
            unknown.pop("login", None)
        
        # Se ainda não tem 'sub', usar email ou login como fallback
        if "sub" not in known:
            known["sub"] = known.get("email") or known.get("preferred_username") or "unknown"
        
        return cls(
            sub=known["sub"],
            name=known.get("name"),
            given_name=known.get("given_name"),
            family_name=known.get("family_name"),
            email=known.get("email"),
            email_verified=known.get("email_verified"),
            preferred_username=known.get("preferred_username"),
            claims=unknown,
        )


@dataclass
class JWK:
    """JSON Web Key."""

    kty: str  # Key type
    use: str | None = None  # Public key use
    kid: str | None = None  # Key ID
    alg: str | None = None  # Algorithm
    n: str | None = None  # RSA modulus
    e: str | None = None  # RSA exponent
    x: str | None = None  # Elliptic curve X coordinate
    y: str | None = None  # Elliptic curve Y coordinate
    crv: str | None = None  # Elliptic curve

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "JWK":
        """Create JWK from dictionary."""
        return cls(
            kty=data["kty"],
            use=data.get("use"),
            kid=data.get("kid"),
            alg=data.get("alg"),
            n=data.get("n"),
            e=data.get("e"),
            x=data.get("x"),
            y=data.get("y"),
            crv=data.get("crv"),
        )


@dataclass
class JWKSet:
    """JSON Web Key Set."""

    keys: list[JWK]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "JWKSet":
        """Create JWKSet from JWKS endpoint response."""
        return cls(keys=[JWK.from_dict(k) for k in data.get("keys", [])])

    def get_key(self, kid: str) -> JWK | None:
        """Get key by ID."""
        for key in self.keys:
            if key.kid == kid:
                return key
        return None
