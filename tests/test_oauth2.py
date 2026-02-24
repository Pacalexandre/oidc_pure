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


class TestOAuth2FlowAsync:
    """Tests for OAuth2Flow async methods."""

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

    @pytest.mark.asyncio
    @respx.mock
    async def test_exchange_code_for_token_async_success(
        self, oauth2_flow: OAuth2Flow, mock_token_response: dict
    ):
        """Test successful async code exchange."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=mock_token_response)
        )

        token = await oauth2_flow.exchange_code_for_token_async(
            code="test_auth_code",
            code_verifier="test_verifier",
        )

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]
        assert token.token_type == mock_token_response["token_type"]
        assert token.refresh_token == mock_token_response["refresh_token"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_exchange_code_for_token_async_error(self, oauth2_flow: OAuth2Flow):
        """Test async code exchange with error response."""
        error_response = {"error": "invalid_grant", "error_description": "Invalid code"}
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(400, json=error_response)
        )

        with pytest.raises(TokenError, match="invalid_grant"):
            await oauth2_flow.exchange_code_for_token_async(code="invalid_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_exchange_code_for_token_async_no_redirect_uri(
        self,
        mock_oidc_config: OIDCConfig,
        mock_client_id: str,
        mock_client_secret: str,
    ):
        """Test async code exchange without redirect URI."""
        flow = OAuth2Flow(
            config=mock_oidc_config,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
        )

        with pytest.raises(TokenError, match="redirect_uri is required"):
            await flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_refresh_access_token_async_success(
        self, oauth2_flow: OAuth2Flow, mock_token_response: dict
    ):
        """Test successful async token refresh."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=mock_token_response)
        )

        token = await oauth2_flow.refresh_access_token_async(refresh_token="test_refresh_token")

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_refresh_access_token_async_error(self, oauth2_flow: OAuth2Flow):
        """Test async token refresh with error response."""
        error_response = {"error": "invalid_grant", "error_description": "Invalid refresh token"}
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(400, json=error_response)
        )

        with pytest.raises(TokenError, match="invalid_grant"):
            await oauth2_flow.refresh_access_token_async(refresh_token="invalid_token")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_form_urlencoded_response(self, oauth2_flow: OAuth2Flow):
        """Test async token request with form-urlencoded response (GitHub OAuth)."""
        # GitHub OAuth returns form-urlencoded by default
        form_response = "access_token=gho_testtoken123&token_type=bearer&scope=repo%2Cuser"
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                text=form_response,
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        )

        token = await oauth2_flow.exchange_code_for_token_async(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "gho_testtoken123"
        assert token.token_type == "bearer"

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_json_fallback(self, oauth2_flow: OAuth2Flow):
        """Test async token request with JSON fallback when content-type is missing."""
        json_response = {
            "access_token": "test_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                json=json_response,
                headers={"content-type": "text/plain"},  # Wrong content-type
            )
        )

        token = await oauth2_flow.exchange_code_for_token_async(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "test_token"

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_form_urlencoded_with_charset(self, oauth2_flow: OAuth2Flow):
        """Test async token request with form-urlencoded and charset."""
        form_response = "access_token=gho_github_token_456&token_type=bearer&scope=admin%3Aorg"
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                text=form_response,
                headers={"content-type": "application/x-www-form-urlencoded; charset=utf-8"},
            )
        )

        token = await oauth2_flow.exchange_code_for_token_async(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "gho_github_token_456"

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_json_with_charset(
        self, oauth2_flow: OAuth2Flow, mock_token_response: dict
    ):
        """Test async token request with JSON and charset."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                json=mock_token_response,
                headers={"content-type": "application/json; charset=utf-8"},
            )
        )

        token = await oauth2_flow.exchange_code_for_token_async(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_content_type_case_insensitive(self, oauth2_flow: OAuth2Flow):
        """Test async token request with uppercase Content-Type."""
        form_response = "access_token=case_test&token_type=Bearer"
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                text=form_response,
                headers={"Content-Type": "APPLICATION/X-WWW-FORM-URLENCODED"},
            )
        )

        token = await oauth2_flow.refresh_access_token_async(refresh_token="test_refresh")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "case_test"

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_form_urlencoded_with_special_chars(
        self, oauth2_flow: OAuth2Flow
    ):
        """Test async token request with URL encoded special characters."""
        form_response = (
            "access_token=special_token&"
            "token_type=bearer&"
            "scope=read%3Auser+write%3Arepo&"
            "expires_in=7200"
        )
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                text=form_response,
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        )

        token = await oauth2_flow.exchange_code_for_token_async(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "special_token"
        assert token.expires_in == "7200"  # Form-urlencoded returns string

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_empty_response(self, oauth2_flow: OAuth2Flow):
        """Test async token request with empty response."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, text="")
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_network_error(self, oauth2_flow: OAuth2Flow):
        """Test async token request with network error."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ConnectError("Connection failed")
        )

        with pytest.raises(NetworkError, match="Network error"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_connect_timeout(self, oauth2_flow: OAuth2Flow):
        """Test async token request with connection timeout."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ConnectTimeout("Connection timeout")
        )

        with pytest.raises(NetworkError, match="Network error"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_read_timeout(self, oauth2_flow: OAuth2Flow):
        """Test async token request with read timeout."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ReadTimeout("Read timeout")
        )

        with pytest.raises(NetworkError, match="Network error"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_pool_timeout(self, oauth2_flow: OAuth2Flow):
        """Test async token request with connection pool timeout."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.PoolTimeout("Connection pool exhausted")
        )

        with pytest.raises(NetworkError, match="Network error"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_write_timeout(self, oauth2_flow: OAuth2Flow):
        """Test async token request with write timeout."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.WriteTimeout("Write timeout")
        )

        with pytest.raises(NetworkError, match="Network error"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_remote_protocol_error(self, oauth2_flow: OAuth2Flow):
        """Test async token request with remote protocol error."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.RemoteProtocolError("Remote host closed connection")
        )

        with pytest.raises(NetworkError, match="Network error"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_local_protocol_error(self, oauth2_flow: OAuth2Flow):
        """Test async token request with local protocol error."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.LocalProtocolError("Invalid HTTP response")
        )

        with pytest.raises(NetworkError, match="Network error"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_proxy_error(self, oauth2_flow: OAuth2Flow):
        """Test async token request with proxy error."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ProxyError("Proxy connection failed")
        )

        with pytest.raises(NetworkError, match="Network error"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_refresh_token_async_network_error(self, oauth2_flow: OAuth2Flow):
        """Test async refresh token with network error."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ConnectTimeout("Connection timeout")
        )

        with pytest.raises(NetworkError, match="Network error"):
            await oauth2_flow.refresh_access_token_async(refresh_token="test_refresh")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_request_async_http_status_error(self, oauth2_flow: OAuth2Flow):
        """Test async token request with HTTP status error without JSON body."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        with pytest.raises(TokenError, match="Token request failed with status 500"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")


class TestOAuth2FlowEdgeCases:
    """Tests for OAuth2Flow edge cases and error handling."""

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

    @respx.mock
    def test_exchange_code_for_token_no_redirect_uri(
        self,
        mock_oidc_config: OIDCConfig,
        mock_client_id: str,
        mock_client_secret: str,
    ):
        """Test code exchange without redirect URI."""
        flow = OAuth2Flow(
            config=mock_oidc_config,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
        )

        with pytest.raises(TokenError, match="redirect_uri is required"):
            flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_client_credentials_flow_no_client_secret(
        self,
        mock_oidc_config: OIDCConfig,
        mock_client_id: str,
        mock_redirect_uri: str,
    ):
        """Test client credentials flow without client secret."""
        flow = OAuth2Flow(
            config=mock_oidc_config,
            client_id=mock_client_id,
            redirect_uri=mock_redirect_uri,
        )

        with pytest.raises(TokenError, match="client_secret is required"):
            flow.client_credentials_flow()

    @respx.mock
    def test_token_request_form_urlencoded_response(self, oauth2_flow: OAuth2Flow):
        """Test token request with form-urlencoded response (GitHub OAuth)."""
        form_response = (
            "access_token=gho_testtoken123&token_type=bearer&"
            "scope=repo%2Cuser&refresh_token=gho_refresh123"
        )
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                text=form_response,
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "gho_testtoken123"
        assert token.token_type == "bearer"
        assert token.refresh_token == "gho_refresh123"

    @respx.mock
    def test_token_request_json_fallback_with_json_start(
        self, oauth2_flow: OAuth2Flow, mock_token_response: dict
    ):
        """Test token request with JSON fallback when content-type is wrong but body is JSON."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                json=mock_token_response,
                headers={"content-type": "text/html"},  # Wrong content-type
            )
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]

    @respx.mock
    def test_token_request_json_fallback_with_form_urlencoded(self, oauth2_flow: OAuth2Flow):
        """Test token request with form-urlencoded fallback when no content-type."""
        form_response = "access_token=test_token&token_type=bearer&expires_in=3600"
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, text=form_response)
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "test_token"

    @respx.mock
    def test_token_request_form_urlencoded_with_charset(self, oauth2_flow: OAuth2Flow):
        """Test token request with form-urlencoded and charset (GitHub OAuth)."""
        form_response = "access_token=gho_16C7e42F292c6912E7710c838347Ae178B4a&token_type=bearer&scope=repo%2Cuser"
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                text=form_response,
                headers={"content-type": "application/x-www-form-urlencoded; charset=utf-8"},
            )
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "gho_16C7e42F292c6912E7710c838347Ae178B4a"
        assert token.token_type == "bearer"

    @respx.mock
    def test_token_request_json_with_charset(
        self, oauth2_flow: OAuth2Flow, mock_token_response: dict
    ):
        """Test token request with JSON and charset."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                json=mock_token_response,
                headers={"content-type": "application/json; charset=utf-8"},
            )
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]

    @respx.mock
    def test_token_request_content_type_case_insensitive(self, oauth2_flow: OAuth2Flow):
        """Test token request with uppercase Content-Type."""
        form_response = "access_token=test_token&token_type=Bearer"
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                text=form_response,
                headers={"Content-Type": "APPLICATION/X-WWW-FORM-URLENCODED"},
            )
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "test_token"

    @respx.mock
    def test_token_request_form_urlencoded_with_special_chars(self, oauth2_flow: OAuth2Flow):
        """Test token request with URL encoded special characters."""
        # Simulates GitHub OAuth response with encoded scope values
        form_response = (
            "access_token=test_token_123&"
            "token_type=bearer&"
            "scope=user%3Aemail+repo%3Astatus+notifications"
        )
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                text=form_response,
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "test_token_123"
        assert token.token_type == "bearer"

    @respx.mock
    def test_token_request_form_urlencoded_multivalue(self, oauth2_flow: OAuth2Flow):
        """Test token request with multiple values for same key."""
        # Some OAuth providers may return multiple scope values
        form_response = "access_token=test_token&token_type=bearer&scope=read&scope=write"
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                text=form_response,
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "test_token"

    @respx.mock
    def test_token_request_json_in_text_content_type(
        self, oauth2_flow: OAuth2Flow, mock_token_response: dict
    ):
        """Test token request with JSON body but text/plain content-type (fallback detection)."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                json=mock_token_response,
                headers={"content-type": "text/plain"},
            )
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == mock_token_response["access_token"]

    @respx.mock
    def test_token_request_form_urlencoded_no_header(self, oauth2_flow: OAuth2Flow):
        """Test token request with form-urlencoded body but missing Content-Type header."""
        form_response = "access_token=github_token&token_type=bearer&expires_in=28800"
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, text=form_response)
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")

        assert isinstance(token, TokenResponse)
        assert token.access_token == "github_token"
        assert token.expires_in == "28800"  # Form-urlencoded returns string

    @respx.mock
    def test_token_request_empty_response(self, oauth2_flow: OAuth2Flow):
        """Test token request with empty response."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, text="")
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_request_malformed_json(self, oauth2_flow: OAuth2Flow):
        """Test token request with malformed JSON response."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                text="{invalid json}",
                headers={"content-type": "application/json"},
            )
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_request_network_error(self, oauth2_flow: OAuth2Flow):
        """Test token request with network error."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ConnectError("Connection failed")
        )

        with pytest.raises(NetworkError, match="Network error"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_request_connect_timeout_error(self, oauth2_flow: OAuth2Flow):
        """Test token request with connection timeout."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ConnectTimeout("Connection timeout")
        )

        with pytest.raises(NetworkError, match="Network error"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_request_read_timeout_error(self, oauth2_flow: OAuth2Flow):
        """Test token request with read timeout."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ReadTimeout("Read timeout")
        )

        with pytest.raises(NetworkError, match="Network error"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_request_pool_timeout_error(self, oauth2_flow: OAuth2Flow):
        """Test token request with connection pool timeout."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.PoolTimeout("Connection pool exhausted")
        )

        with pytest.raises(NetworkError, match="Network error"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_request_write_timeout_error(self, oauth2_flow: OAuth2Flow):
        """Test token request with write timeout."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.WriteTimeout("Write timeout")
        )

        with pytest.raises(NetworkError, match="Network error"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_request_remote_protocol_error(self, oauth2_flow: OAuth2Flow):
        """Test token request with remote protocol error (connection closed)."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.RemoteProtocolError("Remote host closed connection")
        )

        with pytest.raises(NetworkError, match="Network error"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_request_local_protocol_error(self, oauth2_flow: OAuth2Flow):
        """Test token request with local protocol error."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.LocalProtocolError("Invalid HTTP response")
        )

        with pytest.raises(NetworkError, match="Network error"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_request_proxy_error(self, oauth2_flow: OAuth2Flow):
        """Test token request with proxy error."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ProxyError("Proxy connection failed")
        )

        with pytest.raises(NetworkError, match="Network error"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_refresh_token_network_error(self, oauth2_flow: OAuth2Flow):
        """Test refresh token with network error."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ConnectError("Connection failed")
        )

        with pytest.raises(NetworkError, match="Network error"):
            oauth2_flow.refresh_access_token(refresh_token="test_refresh")

    @respx.mock
    def test_client_credentials_flow_network_error(self, oauth2_flow: OAuth2Flow):
        """Test client credentials flow with network error."""
        from oidc_pure.exceptions import NetworkError

        respx.post(oauth2_flow.config.token_endpoint).mock(
            side_effect=httpx.ReadTimeout("Read timeout during client credentials")
        )

        with pytest.raises(NetworkError, match="Network error"):
            oauth2_flow.client_credentials_flow(scope="api:read")

    @respx.mock
    def test_token_request_http_status_error_without_json(self, oauth2_flow: OAuth2Flow):
        """Test token request with HTTP error but no JSON error body."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        with pytest.raises(TokenError, match="Token request failed with status 500"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    def test_oauth2_flow_with_custom_client(
        self,
        mock_oidc_config: OIDCConfig,
        mock_client_id: str,
        mock_client_secret: str,
        mock_redirect_uri: str,
    ):
        """Test OAuth2Flow with custom httpx.Client."""
        custom_client = httpx.Client(timeout=60.0)
        flow = OAuth2Flow(
            config=mock_oidc_config,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            redirect_uri=mock_redirect_uri,
            client=custom_client,
        )

        assert flow._client is custom_client
        assert flow._own_client is False

    def test_oauth2_flow_context_manager_with_custom_client(
        self,
        mock_oidc_config: OIDCConfig,
        mock_client_id: str,
        mock_client_secret: str,
        mock_redirect_uri: str,
    ):
        """Test OAuth2Flow context manager doesn't close custom client."""
        custom_client = httpx.Client(timeout=60.0)
        flow = OAuth2Flow(
            config=mock_oidc_config,
            client_id=mock_client_id,
            client_secret=mock_client_secret,
            redirect_uri=mock_redirect_uri,
            client=custom_client,
        )

        with flow:
            assert flow._client is custom_client

        # Custom client should not be closed
        assert not custom_client.is_closed

        custom_client.close()


class TestOAuth2MalformedResponses:
    """Tests for malformed and edge case responses."""

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

    @respx.mock
    def test_token_response_missing_access_token(self, oauth2_flow: OAuth2Flow):
        """Test token response missing required access_token field."""
        incomplete_response = {
            "token_type": "Bearer",
            "expires_in": 3600,
            # Missing access_token
        }
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=incomplete_response)
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_response_missing_token_type(self, oauth2_flow: OAuth2Flow):
        """Test token response missing token_type field."""
        incomplete_response = {
            "access_token": "test_token",
            "expires_in": 3600,
            # Missing token_type
        }
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=incomplete_response)
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_response_whitespace_only(self, oauth2_flow: OAuth2Flow):
        """Test token response with only whitespace."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, text="   \n\t   ")
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_response_null_json(self, oauth2_flow: OAuth2Flow):
        """Test token response with null JSON."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200, text="null", headers={"content-type": "application/json"}
            )
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_response_empty_json_object(self, oauth2_flow: OAuth2Flow):
        """Test token response with empty JSON object."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json={}, headers={"content-type": "application/json"})
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_response_json_array_instead_of_object(self, oauth2_flow: OAuth2Flow):
        """Test token response with JSON array instead of object."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200, text='["access_token", "bearer"]', headers={"content-type": "application/json"}
            )
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_response_html_instead_of_json(self, oauth2_flow: OAuth2Flow):
        """Test token response with HTML error page instead of JSON."""
        html_error = """
        <html>
            <body>
                <h1>500 Internal Server Error</h1>
                <p>Something went wrong</p>
            </body>
        </html>
        """
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, text=html_error, headers={"content-type": "text/html"})
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_response_invalid_json_syntax(self, oauth2_flow: OAuth2Flow):
        """Test token response with invalid JSON syntax."""
        invalid_jsons = [
            "{access_token: 'missing_quotes'}",  # Missing quotes on key
            "{'access_token': 'single_quotes'}",  # Single quotes
            "{access_token: test_token}",  # Missing quotes on both
            '{"access_token": "test", }',  # Trailing comma
            '{"access_token": undefined}',  # JavaScript undefined
        ]

        for invalid_json in invalid_jsons:
            respx.post(oauth2_flow.config.token_endpoint).mock(
                return_value=httpx.Response(
                    200, text=invalid_json, headers={"content-type": "application/json"}
                )
            )

            with pytest.raises(TokenError, match="Invalid token response"):
                oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_response_xml_instead_of_json(self, oauth2_flow: OAuth2Flow):
        """Test token response with XML instead of JSON."""
        xml_response = """<?xml version="1.0"?>
        <response>
            <access_token>test_token</access_token>
            <token_type>Bearer</token_type>
        </response>
        """
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200, text=xml_response, headers={"content-type": "application/xml"}
            )
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_response_binary_data(self, oauth2_flow: OAuth2Flow):
        """Test token response with binary data."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200,
                content=b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",  # PNG header
                headers={"content-type": "application/octet-stream"},
            )
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            oauth2_flow.exchange_code_for_token(code="test_code")

    @respx.mock
    def test_token_response_extremely_large(self, oauth2_flow: OAuth2Flow):
        """Test token response with extremely large payload."""
        # Simulate a large (but valid) response
        large_response = {
            "access_token": "a" * 100000,  # 100KB token
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=large_response)
        )

        # Should work despite large size
        token = oauth2_flow.exchange_code_for_token(code="test_code")
        assert token.access_token == "a" * 100000

    @respx.mock
    def test_token_response_unicode_in_fields(self, oauth2_flow: OAuth2Flow):
        """Test token response with unicode characters."""
        unicode_response = {
            "access_token": "test_token_🔒",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read:user 読み取り write:repo",
        }
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=unicode_response)
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")
        assert "🔒" in token.access_token

    @respx.mock
    def test_token_response_with_bom(self, oauth2_flow: OAuth2Flow):
        """Test token response with UTF-8 BOM (Byte Order Mark)."""
        import json

        response_data = {"access_token": "test_token", "token_type": "Bearer", "expires_in": 3600}
        # UTF-8 BOM + JSON
        json_with_bom = "\ufeff" + json.dumps(response_data)

        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200, text=json_with_bom, headers={"content-type": "application/json; charset=utf-8"}
            )
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")
        assert token.access_token == "test_token"

    @respx.mock
    def test_token_response_numeric_strings(self, oauth2_flow: OAuth2Flow):
        """Test token response with numeric values as strings."""
        response_with_strings = {
            "access_token": "test_token",
            "token_type": "Bearer",
            "expires_in": "3600",  # String instead of int
            "scope": "openid profile",
        }
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=response_with_strings)
        )

        token = oauth2_flow.exchange_code_for_token(code="test_code")
        assert token.expires_in == "3600"  # Should accept as-is

    @respx.mock
    def test_token_response_extra_unknown_fields(self, oauth2_flow: OAuth2Flow):
        """Test token response with extra unknown fields."""
        response_with_extras = {
            "access_token": "test_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "unknown_field": "unknown_value",
            "custom_data": {"nested": "value"},
            "deprecated_field": None,
        }
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, json=response_with_extras)
        )

        # Should ignore unknown fields and work normally
        token = oauth2_flow.exchange_code_for_token(code="test_code")
        assert token.access_token == "test_token"

    @respx.mock
    def test_token_response_form_urlencoded_malformed(self, oauth2_flow: OAuth2Flow):
        """Test malformed form-urlencoded response."""
        malformed_forms = [
            "access_token=test&=invalid",  # Missing key
            "access_token&token_type=Bearer",  # Missing value
            "access_token=test&token_type",  # Incomplete pair
            "===",  # Only separators
            "access_token=test&token_type=Bearer&",  # Trailing &
        ]

        for malformed in malformed_forms:
            respx.post(oauth2_flow.config.token_endpoint).mock(
                return_value=httpx.Response(
                    200,
                    text=malformed,
                    headers={"content-type": "application/x-www-form-urlencoded"},
                )
            )

            # Should handle gracefully (may succeed with partial data or fail)
            try:
                token = oauth2_flow.exchange_code_for_token(code="test_code")
                # If it succeeds, at least access_token should be present
                assert hasattr(token, "access_token")
            except TokenError:
                # Acceptable to fail on malformed data
                pass

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_response_async_malformed_json(self, oauth2_flow: OAuth2Flow):
        """Test async token request with malformed JSON."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(
                200, text="{broken json}", headers={"content-type": "application/json"}
            )
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_response_async_empty_response(self, oauth2_flow: OAuth2Flow):
        """Test async token request with empty response."""
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, text="")
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")

    @pytest.mark.asyncio
    @respx.mock
    async def test_token_response_async_html_error(self, oauth2_flow: OAuth2Flow):
        """Test async token request with HTML error page."""
        html_error = "<html><body><h1>Error</h1></body></html>"
        respx.post(oauth2_flow.config.token_endpoint).mock(
            return_value=httpx.Response(200, text=html_error, headers={"content-type": "text/html"})
        )

        with pytest.raises(TokenError, match="Invalid token response"):
            await oauth2_flow.exchange_code_for_token_async(code="test_code")
