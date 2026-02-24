"""Tests for OIDC client."""

from urllib.parse import parse_qs, urlparse

import httpx
import respx

from oidc_pure.client import OIDCClient
from oidc_pure.models import TokenResponse, UserInfo


class TestOIDCClient:
    """Tests for OIDCClient class."""

    @respx.mock
    def test_client_initialization_with_discovery(
        self,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
        mock_redirect_uri: str,
        mock_discovery_response: dict,
    ):
        """Test client initialization with auto-discovery."""
        discovery_url = f"{mock_issuer_url}/.well-known/openid-configuration"
        respx.get(discovery_url).mock(
            return_value=httpx.Response(200, json=mock_discovery_response)
        )

        client = OIDCClient(
            issuer_url=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            redirect_uri=mock_redirect_uri,
        )

        assert client.config is not None
        assert client.config.issuer == mock_issuer_url
        assert client.client_id == mock_client_id

    def test_client_initialization_without_discovery(
        self,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
        mock_redirect_uri: str,
        mock_oidc_config,
    ):
        """Test client initialization without auto-discovery."""
        client = OIDCClient(
            issuer_url=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            redirect_uri=mock_redirect_uri,
            config=mock_oidc_config,
            auto_discover=False,
        )

        assert client.config == mock_oidc_config

    @respx.mock
    def test_get_authorization_url(
        self,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
        mock_redirect_uri: str,
        mock_oidc_config,
    ):
        """Test getting authorization URL."""
        client = OIDCClient(
            issuer_url=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            redirect_uri=mock_redirect_uri,
            config=mock_oidc_config,
            auto_discover=False,
        )

        auth_url, state, verifier = client.get_authorization_url()

        assert auth_url.startswith(mock_oidc_config.authorization_endpoint)
        assert state is not None
        assert verifier is not None

        parsed_url = urlparse(auth_url)
        query_params = parse_qs(parsed_url.query)
        assert query_params["client_id"][0] == mock_client_id

    @respx.mock
    def test_handle_authorization_response_success(
        self,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
        mock_redirect_uri: str,
        mock_oidc_config,
        mock_token_response: dict,
    ):
        """Test handling successful authorization response."""
        client = OIDCClient(
            issuer_url=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            redirect_uri=mock_redirect_uri,
            config=mock_oidc_config,
            auto_discover=False,
        )

        respx.post(mock_oidc_config.token_endpoint).mock(
            return_value=httpx.Response(200, json=mock_token_response)
        )

        response_url = f"{mock_redirect_uri}?code=test_code&state=test_state"

        token = client.handle_authorization_response(
            response_url=response_url,
            expected_state="test_state",
            code_verifier="test_verifier",
        )

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]

    @respx.mock
    def test_get_user_info_success(
        self,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
        mock_redirect_uri: str,
        mock_oidc_config,
        mock_user_info: dict,
    ):
        """Test getting user information."""
        client = OIDCClient(
            issuer_url=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            redirect_uri=mock_redirect_uri,
            config=mock_oidc_config,
            auto_discover=False,
        )

        respx.get(mock_oidc_config.userinfo_endpoint).mock(
            return_value=httpx.Response(200, json=mock_user_info)
        )

        user_info = client.get_user_info(access_token="test_access_token")

        assert isinstance(user_info, UserInfo)
        assert user_info.sub == mock_user_info["sub"]
        assert user_info.name == mock_user_info["name"]
        assert user_info.email == mock_user_info["email"]

    @respx.mock
    def test_refresh_access_token(
        self,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
        mock_redirect_uri: str,
        mock_oidc_config,
        mock_token_response: dict,
    ):
        """Test refreshing access token."""
        client = OIDCClient(
            issuer_url=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            redirect_uri=mock_redirect_uri,
            config=mock_oidc_config,
            auto_discover=False,
        )

        respx.post(mock_oidc_config.token_endpoint).mock(
            return_value=httpx.Response(200, json=mock_token_response)
        )

        new_token = client.refresh_token(refresh_token="test_refresh_token")

        assert isinstance(new_token, TokenResponse)
        assert new_token.access_token == mock_token_response["access_token"]

    @respx.mock
    def test_get_client_credentials_token(
        self,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
        mock_oidc_config,
        mock_token_response: dict,
    ):
        """Test getting token with client credentials."""
        client = OIDCClient(
            issuer_url=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            config=mock_oidc_config,
            auto_discover=False,
        )

        respx.post(mock_oidc_config.token_endpoint).mock(
            return_value=httpx.Response(200, json=mock_token_response)
        )

        token = client.client_credentials_grant(scope="api:read")

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]

    def test_context_manager(
        self,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
        mock_oidc_config,
    ):
        """Test client as context manager."""
        with OIDCClient(
            issuer_url=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            config=mock_oidc_config,
            auto_discover=False,
        ) as client:
            assert client._client is not None

    @respx.mock
    def test_validate_id_token(
        self,
        mock_issuer_url: str,
        mock_client_id: str,
        mock_client_secret: str,
        mock_oidc_config,
    ):
        """Test ID token validation."""
        import base64
        import json
        import time

        client = OIDCClient(
            issuer_url=mock_issuer_url,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            config=mock_oidc_config,
            auto_discover=False,
        )

        # Create a simple ID token
        current_time = int(time.time())
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "iss": mock_issuer_url,
            "aud": mock_client_id,
            "exp": current_time + 3600,
            "iat": current_time,
        }

        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signature = "fake_signature"

        id_token = f"{header_b64}.{payload_b64}.{signature}"

        # Validate without signature verification
        validated = client.validate_token(id_token, verify_signature=False)

        assert validated["sub"] == "1234567890"
        assert validated["iss"] == mock_issuer_url
