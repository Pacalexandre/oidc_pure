"""Tests for data models (OIDCConfig, TokenResponse, UserInfo, JWK, JWKSet)."""

from oidc_pure.models import JWK, JWKSet, OIDCConfig, TokenResponse, UserInfo


class TestOIDCConfig:
    """Tests for OIDCConfig model."""

    def test_from_dict_minimal(self):
        """Test OIDCConfig.from_dict with minimal required fields."""
        data = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "userinfo_endpoint": "https://example.com/userinfo",
            "jwks_uri": "https://example.com/jwks",
        }
        config = OIDCConfig.from_dict(data)

        assert config.issuer == "https://example.com"
        assert config.authorization_endpoint == "https://example.com/auth"
        assert config.token_endpoint == "https://example.com/token"
        assert config.userinfo_endpoint == "https://example.com/userinfo"
        assert config.jwks_uri == "https://example.com/jwks"
        assert config.end_session_endpoint is None
        assert config.scopes_supported == []
        assert config.response_types_supported == []
        assert config.grant_types_supported == []
        assert config.token_endpoint_auth_methods_supported == []
        assert config.claims_supported == []
        assert config.code_challenge_methods_supported == []

    def test_from_dict_complete(self):
        """Test OIDCConfig.from_dict with all optional fields."""
        data = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "userinfo_endpoint": "https://example.com/userinfo",
            "jwks_uri": "https://example.com/jwks",
            "end_session_endpoint": "https://example.com/logout",
            "scopes_supported": ["openid", "profile", "email"],
            "response_types_supported": ["code", "token"],
            "grant_types_supported": ["authorization_code", "client_credentials"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "claims_supported": ["sub", "name", "email"],
            "code_challenge_methods_supported": ["S256", "plain"],
        }
        config = OIDCConfig.from_dict(data)

        assert config.end_session_endpoint == "https://example.com/logout"
        assert config.scopes_supported == ["openid", "profile", "email"]
        assert config.response_types_supported == ["code", "token"]
        assert config.grant_types_supported == ["authorization_code", "client_credentials"]
        assert config.token_endpoint_auth_methods_supported == ["client_secret_basic"]
        assert config.claims_supported == ["sub", "name", "email"]
        assert config.code_challenge_methods_supported == ["S256", "plain"]


class TestTokenResponse:
    """Tests for TokenResponse model."""

    def test_from_dict_minimal(self):
        """Test TokenResponse.from_dict with minimal required fields."""
        data = {
            "access_token": "access123",
            "token_type": "Bearer",
        }
        token = TokenResponse.from_dict(data)

        assert token.access_token == "access123"
        assert token.token_type == "Bearer"
        assert token.expires_in is None
        assert token.refresh_token is None
        assert token.scope is None
        assert token.id_token is None

    def test_from_dict_complete(self):
        """Test TokenResponse.from_dict with all optional fields."""
        data = {
            "access_token": "access123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh456",
            "scope": "openid profile email",
            "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        }
        token = TokenResponse.from_dict(data)

        assert token.access_token == "access123"
        assert token.token_type == "Bearer"
        assert token.expires_in == 3600
        assert token.refresh_token == "refresh456"
        assert token.scope == "openid profile email"
        assert token.id_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."


class TestUserInfo:
    """Tests for UserInfo model."""

    def test_from_dict_oidc_standard(self):
        """Test UserInfo.from_dict with standard OIDC format."""
        data = {
            "sub": "user123",
            "name": "John Doe",
            "given_name": "John",
            "family_name": "Doe",
            "email": "john@example.com",
            "email_verified": True,
            "preferred_username": "johndoe",
        }
        user = UserInfo.from_dict(data)

        assert user.sub == "user123"
        assert user.name == "John Doe"
        assert user.given_name == "John"
        assert user.family_name == "Doe"
        assert user.email == "john@example.com"
        assert user.email_verified is True
        assert user.preferred_username == "johndoe"
        assert user.claims == {}

    def test_from_dict_github_format(self):
        """Test UserInfo.from_dict with GitHub OAuth format (id instead of sub)."""
        data = {
            "id": 12345,
            "login": "johndoe",
            "name": "John Doe",
            "email": "john@example.com",
        }
        user = UserInfo.from_dict(data)

        assert user.sub == "12345"  # GitHub 'id' mapped to 'sub'
        assert user.preferred_username == "johndoe"  # GitHub 'login' mapped
        assert user.name == "John Doe"
        assert user.email == "john@example.com"
        assert "id" not in user.claims  # Removed after mapping
        assert "login" not in user.claims  # Removed after mapping

    def test_from_dict_minimal_with_extra_claims(self):
        """Test UserInfo.from_dict with minimal fields and extra claims."""
        data = {
            "sub": "user123",
            "custom_field": "value123",
            "role": "admin",
            "organization": "ACME Corp",
        }
        user = UserInfo.from_dict(data)

        assert user.sub == "user123"
        assert user.name is None
        assert user.email is None
        assert user.claims == {
            "custom_field": "value123",
            "role": "admin",
            "organization": "ACME Corp",
        }

    def test_from_dict_fallback_sub_from_email(self):
        """Test UserInfo.from_dict fallback: use email as sub if missing."""
        data = {
            "email": "john@example.com",
            "name": "John Doe",
        }
        user = UserInfo.from_dict(data)

        assert user.sub == "john@example.com"  # Email used as fallback
        assert user.email == "john@example.com"
        assert user.name == "John Doe"

    def test_from_dict_fallback_sub_from_preferred_username(self):
        """Test UserInfo.from_dict fallback: use preferred_username as sub."""
        data = {
            "preferred_username": "johndoe",
            "name": "John Doe",
        }
        user = UserInfo.from_dict(data)

        assert user.sub == "johndoe"  # preferred_username used as fallback
        assert user.preferred_username == "johndoe"
        assert user.name == "John Doe"

    def test_from_dict_fallback_sub_unknown(self):
        """Test UserInfo.from_dict fallback: use 'unknown' if no identifier."""
        data = {
            "name": "John Doe",
        }
        user = UserInfo.from_dict(data)

        assert user.sub == "unknown"  # Fallback when no identifier available
        assert user.name == "John Doe"

    def test_from_dict_github_with_extra_claims(self):
        """Test UserInfo.from_dict with GitHub format and extra claims."""
        data = {
            "id": 99999,
            "login": "octocat",
            "name": "The Octocat",
            "email": "octocat@github.com",
            "avatar_url": "https://avatars.githubusercontent.com/u/99999",
            "bio": "GitHub mascot",
            "public_repos": 8,
        }
        user = UserInfo.from_dict(data)

        assert user.sub == "99999"
        assert user.preferred_username == "octocat"
        assert user.name == "The Octocat"
        assert user.email == "octocat@github.com"
        assert user.claims == {
            "avatar_url": "https://avatars.githubusercontent.com/u/99999",
            "bio": "GitHub mascot",
            "public_repos": 8,
        }

    def test_from_dict_partial_oidc(self):
        """Test UserInfo.from_dict with partial OIDC fields."""
        data = {
            "sub": "user456",
            "email": "user@example.com",
            "email_verified": False,
        }
        user = UserInfo.from_dict(data)

        assert user.sub == "user456"
        assert user.email == "user@example.com"
        assert user.email_verified is False
        assert user.name is None
        assert user.given_name is None
        assert user.family_name is None
        assert user.preferred_username is None


class TestJWK:
    """Tests for JWK (JSON Web Key) model."""

    def test_from_dict_rsa_key(self):
        """Test JWK.from_dict with RSA key."""
        data = {
            "kty": "RSA",
            "use": "sig",
            "kid": "key123",
            "alg": "RS256",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt",
            "e": "AQAB",
        }
        jwk = JWK.from_dict(data)

        assert jwk.kty == "RSA"
        assert jwk.use == "sig"
        assert jwk.kid == "key123"
        assert jwk.alg == "RS256"
        assert jwk.n == "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
        assert jwk.e == "AQAB"
        assert jwk.x is None
        assert jwk.y is None
        assert jwk.crv is None

    def test_from_dict_ec_key(self):
        """Test JWK.from_dict with Elliptic Curve key."""
        data = {
            "kty": "EC",
            "use": "sig",
            "kid": "ec-key-1",
            "alg": "ES256",
            "crv": "P-256",
            "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
        }
        jwk = JWK.from_dict(data)

        assert jwk.kty == "EC"
        assert jwk.use == "sig"
        assert jwk.kid == "ec-key-1"
        assert jwk.alg == "ES256"
        assert jwk.crv == "P-256"
        assert jwk.x == "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis"
        assert jwk.y == "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
        assert jwk.n is None
        assert jwk.e is None

    def test_from_dict_minimal(self):
        """Test JWK.from_dict with only required field (kty)."""
        data = {"kty": "oct"}
        jwk = JWK.from_dict(data)

        assert jwk.kty == "oct"
        assert jwk.use is None
        assert jwk.kid is None
        assert jwk.alg is None


class TestJWKSet:
    """Tests for JWKSet (JSON Web Key Set) model."""

    def test_from_dict_multiple_keys(self):
        """Test JWKSet.from_dict with multiple keys."""
        data = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "key1",
                    "alg": "RS256",
                    "n": "modulus1",
                    "e": "AQAB",
                },
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "key2",
                    "alg": "RS256",
                    "n": "modulus2",
                    "e": "AQAB",
                },
                {
                    "kty": "EC",
                    "use": "sig",
                    "kid": "key3",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "x-coord",
                    "y": "y-coord",
                },
            ]
        }
        jwks = JWKSet.from_dict(data)

        assert len(jwks.keys) == 3
        assert jwks.keys[0].kid == "key1"
        assert jwks.keys[1].kid == "key2"
        assert jwks.keys[2].kid == "key3"

    def test_from_dict_empty_keys(self):
        """Test JWKSet.from_dict with empty keys array."""
        data = {"keys": []}
        jwks = JWKSet.from_dict(data)

        assert jwks.keys == []

    def test_from_dict_no_keys_field(self):
        """Test JWKSet.from_dict without 'keys' field."""
        data = {}
        jwks = JWKSet.from_dict(data)

        assert jwks.keys == []

    def test_get_key_found(self):
        """Test JWKSet.get_key() when key exists."""
        data = {
            "keys": [
                {"kty": "RSA", "kid": "key1", "n": "mod1", "e": "AQAB"},
                {"kty": "RSA", "kid": "key2", "n": "mod2", "e": "AQAB"},
                {"kty": "RSA", "kid": "key3", "n": "mod3", "e": "AQAB"},
            ]
        }
        jwks = JWKSet.from_dict(data)

        key = jwks.get_key("key2")
        assert key is not None
        assert key.kid == "key2"
        assert key.n == "mod2"

    def test_get_key_not_found(self):
        """Test JWKSet.get_key() when key doesn't exist."""
        data = {
            "keys": [
                {"kty": "RSA", "kid": "key1", "n": "mod1", "e": "AQAB"},
            ]
        }
        jwks = JWKSet.from_dict(data)

        key = jwks.get_key("nonexistent")
        assert key is None

    def test_get_key_empty_set(self):
        """Test JWKSet.get_key() on empty key set."""
        jwks = JWKSet.from_dict({})

        key = jwks.get_key("any-key")
        assert key is None

    def test_get_key_first_match(self):
        """Test JWKSet.get_key() returns first matching key."""
        data = {
            "keys": [
                {"kty": "RSA", "kid": "duplicate", "n": "mod1", "e": "AQAB"},
                {"kty": "RSA", "kid": "duplicate", "n": "mod2", "e": "AQAB"},
            ]
        }
        jwks = JWKSet.from_dict(data)

        key = jwks.get_key("duplicate")
        assert key is not None
        assert key.n == "mod1"  # Returns first match
