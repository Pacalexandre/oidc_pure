"""Shared fixtures for tests."""

import os
from typing import Generator

import httpx
import pytest
import respx

from oidc_pure.models import OIDCConfig


@pytest.fixture
def mock_issuer_url() -> str:
    """Mock issuer URL for testing."""
    return "https://keycloak.example.com/realms/test"


@pytest.fixture
def mock_client_id() -> str:
    """Mock client ID for testing."""
    return "test-client"


@pytest.fixture
def mock_client_secret() -> str:
    """Mock client secret for testing."""
    return "test-secret"


@pytest.fixture
def mock_redirect_uri() -> str:
    """Mock redirect URI for testing."""
    return "http://localhost:8080/callback"


@pytest.fixture
def mock_oidc_config(mock_issuer_url: str) -> OIDCConfig:
    """Mock OIDC configuration for testing."""
    return OIDCConfig(
        issuer=mock_issuer_url,
        authorization_endpoint=f"{mock_issuer_url}/protocol/openid-connect/auth",
        token_endpoint=f"{mock_issuer_url}/protocol/openid-connect/token",
        userinfo_endpoint=f"{mock_issuer_url}/protocol/openid-connect/userinfo",
        jwks_uri=f"{mock_issuer_url}/protocol/openid-connect/certs",
        end_session_endpoint=f"{mock_issuer_url}/protocol/openid-connect/logout",
        scopes_supported=["openid", "profile", "email"],
        response_types_supported=["code", "token", "id_token"],
        grant_types_supported=["authorization_code", "refresh_token", "client_credentials"],
        token_endpoint_auth_methods_supported=["client_secret_basic", "client_secret_post"],
        claims_supported=["sub", "iss", "aud", "exp", "iat"],
        code_challenge_methods_supported=["S256"],
    )


@pytest.fixture
def mock_discovery_response(mock_issuer_url: str) -> dict:
    """Mock discovery endpoint response."""
    return {
        "issuer": mock_issuer_url,
        "authorization_endpoint": f"{mock_issuer_url}/protocol/openid-connect/auth",
        "token_endpoint": f"{mock_issuer_url}/protocol/openid-connect/token",
        "userinfo_endpoint": f"{mock_issuer_url}/protocol/openid-connect/userinfo",
        "jwks_uri": f"{mock_issuer_url}/protocol/openid-connect/certs",
        "end_session_endpoint": f"{mock_issuer_url}/protocol/openid-connect/logout",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code", "token", "id_token"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat"],
        "code_challenge_methods_supported": ["S256"],
    }


@pytest.fixture
def mock_token_response() -> dict:
    """Mock token endpoint response."""
    return {
        "access_token": "mock_access_token_12345",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "mock_refresh_token_12345",
        "scope": "openid profile email",
        "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    }


@pytest.fixture
def mock_user_info() -> dict:
    """Mock userinfo endpoint response."""
    return {
        "sub": "1234567890",
        "name": "John Doe",
        "given_name": "John",
        "family_name": "Doe",
        "email": "john.doe@example.com",
        "email_verified": True,
        "preferred_username": "johndoe",
    }


@pytest.fixture
def respx_mock() -> Generator[respx.MockRouter, None, None]:
    """Provide respx mock router."""
    with respx.mock:
        yield respx


@pytest.fixture
def http_client() -> Generator[httpx.Client, None, None]:
    """Provide HTTP client for testing."""
    client = httpx.Client(timeout=30.0)
    yield client
    client.close()


# Integration test fixtures (using environment variables)


@pytest.fixture
def integration_enabled() -> bool:
    """Check if integration tests should run."""
    return all(
        [
            os.getenv("KEYCLOAK_URL"),
            os.getenv("KEYCLOAK_REALM"),
            os.getenv("CLIENT_ID"),
            os.getenv("CLIENT_SECRET"),
        ]
    )


@pytest.fixture
def keycloak_url() -> str:
    """Get Keycloak URL from environment."""
    url = os.getenv("KEYCLOAK_URL")
    if not url:
        pytest.skip("KEYCLOAK_URL not set")
    return url.rstrip("/")


@pytest.fixture
def keycloak_realm() -> str:
    """Get Keycloak realm from environment."""
    realm = os.getenv("KEYCLOAK_REALM")
    if not realm:
        pytest.skip("KEYCLOAK_REALM not set")
    return realm


@pytest.fixture
def integration_client_id() -> str:
    """Get client ID from environment."""
    client_id = os.getenv("CLIENT_ID")
    if not client_id:
        pytest.skip("CLIENT_ID not set")
    return client_id


@pytest.fixture
def integration_client_secret() -> str:
    """Get client secret from environment."""
    secret = os.getenv("CLIENT_SECRET")
    if not secret:
        pytest.skip("CLIENT_SECRET not set")
    return secret


@pytest.fixture
def integration_issuer_url(keycloak_url: str, keycloak_realm: str) -> str:
    """Build issuer URL for integration tests."""
    return f"{keycloak_url}/realms/{keycloak_realm}"


@pytest.fixture
def integration_username() -> str:
    """Get test username from environment."""
    username = os.getenv("TEST_USERNAME")
    if not username:
        pytest.skip("TEST_USERNAME not set for integration tests")
    return username


@pytest.fixture
def integration_password() -> str:
    """Get test password from environment."""
    password = os.getenv("TEST_PASSWORD")
    if not password:
        pytest.skip("TEST_PASSWORD not set for integration tests")
    return password
