"""Tests for OAuth2 flows."""

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from oidc_pure.exceptions import AuthorizationError, TokenError
from oidc_pure.models import OIDCConfig, TokenResponse
from oidc_pure.oauth2 import OAuth2Flow


class TestOAuth2Flow:
    """Tests for OAuth2Flow class."""

    @pytest.fixture
    def oauth2_flow(
        self,
        mock_oidc_config: OIDCConfig,
        mock_client_id: str,
        mock_client_secret: str,
        mock_redirect_uri: str,
    ):
        """Create an OAuth2Flow instance."""
        return OAuth2Flow(
            config=mock_oidc_config,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            redirect_uri=mock_redirect_uri,
        )

    def test_context_manager(self, oauth2_flow: OAuth2Flow):
        """Test OAuth2Flow as context manager."""
        with oauth2_flow as flow:
            assert flow._client is not None

    def test_build_authorization_url_basic(self, oauth2_flow: OAuth2Flow):
        """Test building basic authorization URL."""
        auth_url, state, verifier = oauth2_flow.build_authorization_url()

        parsed_url = urlparse(auth_url)
        query_params = parse_qs(parsed_url.query)

        assert parsed_url.scheme == "https"
        assert "client_id" in query_params
        assert "redirect_uri" in query_params
        assert "response_type" in query_params
        assert "scope" in query_params
        assert "state" in query_params
        assert query_params["response_type"][0] == "code"
        assert state is not None
        assert verifier is not None

    def test_build_authorization_url_with_pkce(self, oauth2_flow: OAuth2Flow):
        """Test building authorization URL with PKCE."""
        auth_url, state, verifier = oauth2_flow.build_authorization_url(use_pkce=True)

        parsed_url = urlparse(auth_url)
        query_params = parse_qs(parsed_url.query)

        assert "code_challenge" in query_params
        assert "code_challenge_method" in query_params
        assert query_params["code_challenge_method"][0] == "S256"
        assert verifier is not None

    def test_build_authorization_url_without_pkce(self, oauth2_flow: OAuth2Flow):
        """Test building authorization URL without PKCE."""
        auth_url, state, verifier = oauth2_flow.build_authorization_url(use_pkce=False)

        parsed_url = urlparse(auth_url)
        query_params = parse_qs(parsed_url.query)

        assert "code_challenge" not in query_params
        assert "code_challenge_method" not in query_params
        assert verifier is None

    def test_build_authorization_url_custom_scope(self, oauth2_flow: OAuth2Flow):
        """Test building authorization URL with custom scope."""
        auth_url, _, _ = oauth2_flow.build_authorization_url(scope="openid profile")

        parsed_url = urlparse(auth_url)
        query_params = parse_qs(parsed_url.query)

        assert "openid" in query_params["scope"][0]
        assert "profile" in query_params["scope"][0]

    def test_build_authorization_url_list_scope(self, oauth2_flow: OAuth2Flow):
        """Test building authorization URL with list of scopes."""
        auth_url, _, _ = oauth2_flow.build_authorization_url(scope=["openid", "email"])

        parsed_url = urlparse(auth_url)
        query_params = parse_qs(parsed_url.query)

        assert "openid" in query_params["scope"][0]
        assert "email" in query_params["scope"][0]

    def test_build_authorization_url_extra_params(self, oauth2_flow: OAuth2Flow):
        """Test building authorization URL with extra parameters."""
        auth_url, _, _ = oauth2_flow.build_authorization_url(
            extra_params={"prompt": "consent", "ui_locales": "pt-BR"}
        )

        parsed_url = urlparse(auth_url)
        query_params = parse_qs(parsed_url.query)

        assert query_params["prompt"][0] == "consent"
        assert query_params["ui_locales"][0] == "pt-BR"

    def test_build_authorization_url_no_redirect_uri(
        self,
        mock_oidc_config: OIDCConfig,
        mock_client_id: str,
        mock_client_secret: str,
    ):
        """Test building authorization URL without redirect URI."""
        flow = OAuth2Flow(
            config=mock_oidc_config,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
        )

        with pytest.raises(AuthorizationError, match="redirect_uri is required"):
            flow.build_authorization_url()

    @respx.mock
    def test_exchange_code_for_token_success(
        self, oauth2_flow: OAuth2Flow, mock_token_response: dict
    ):
        """Test successful code exchange."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=mock_token_response)
        )

        token = oauth2_flow.exchange_code_for_token(
            code="test_auth_code",
            code_verifier="test_verifier",
        )

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]
        assert token.token_type == mock_token_response["token_type"]
        assert token.refresh_token == mock_token_response["refresh_token"]

    @respx.mock
    def test_exchange_code_for_token_error(self, oauth2_flow: OAuth2Flow):
        """Test code exchange with error response."""
        error_response = {"error": "invalid_grant", "error_description": "Invalid code"}
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(400, json=error_response)
        )

        with pytest.raises(TokenError, match="invalid_grant"):
            oauth2_flow.exchange_code_for_token(code="invalid_code")

    @respx.mock
    def test_refresh_token_success(self, oauth2_flow: OAuth2Flow, mock_token_response: dict):
        """Test successful token refresh."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=mock_token_response)
        )

        token = oauth2_flow.refresh_access_token(refresh_token="test_refresh_token")

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]

    @respx.mock
    def test_refresh_token_error(self, oauth2_flow: OAuth2Flow):
        """Test token refresh with error response."""
        error_response = {"error": "invalid_grant", "error_description": "Invalid refresh token"}
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(400, json=error_response)
        )

        with pytest.raises(TokenError, match="invalid_grant"):
            oauth2_flow.refresh_access_token(refresh_token="invalid_token")

    @respx.mock
    def test_client_credentials_flow_success(
        self, oauth2_flow: OAuth2Flow, mock_token_response: dict
    ):
        """Test successful client credentials flow."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=mock_token_response)
        )

        token = oauth2_flow.client_credentials_flow(scope="api:read api:write")

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]

    @respx.mock
    def test_client_credentials_flow_error(self, oauth2_flow: OAuth2Flow):
        """Test client credentials flow with error."""
        error_response = {"error": "invalid_client", "error_description": "Invalid credentials"}
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(401, json=error_response)
        )

        with pytest.raises(TokenError, match="invalid_client"):
            oauth2_flow.client_credentials_flow()

    def test_parse_authorization_response_success(self, oauth2_flow: OAuth2Flow):
        """Test parsing successful authorization response."""
        response_url = "http://localhost:8080/callback?code=test_auth_code&state=test_state"

        code = oauth2_flow.parse_authorization_response(
            response_url=response_url,
            expected_state="test_state",
        )

        assert code == "test_auth_code"

    def test_parse_authorization_response_state_mismatch(self, oauth2_flow: OAuth2Flow):
        """Test parsing response with state mismatch."""
        response_url = "http://localhost:8080/callback?code=test_auth_code&state=wrong_state"

        with pytest.raises(AuthorizationError, match="State mismatch"):
            oauth2_flow.parse_authorization_response(
                response_url=response_url,
                expected_state="expected_state",
            )

    def test_parse_authorization_response_missing_code(self, oauth2_flow: OAuth2Flow):
        """Test parsing response with missing code."""
        response_url = "http://localhost:8080/callback?state=test_state"

        with pytest.raises(AuthorizationError, match="Response missing authorization code"):
            oauth2_flow.parse_authorization_response(
                response_url=response_url,
                expected_state="test_state",
            )

    def test_parse_authorization_response_error(self, oauth2_flow: OAuth2Flow):
        """Test parsing response with error."""
        response_url = (
            "http://localhost:8080/callback?error=access_denied&error_description=User denied"
        )

        with pytest.raises(AuthorizationError, match="access_denied"):
            oauth2_flow.parse_authorization_response(
                response_url=response_url,
                expected_state="test_state",
            )
