"""OAuth2 flows implementation following RFC 6749."""

import secrets
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from oidc_pure.exceptions import AuthorizationError, NetworkError, TokenError
from oidc_pure.models import OIDCConfig, TokenResponse
from oidc_pure.tokens import create_pkce_challenge, generate_code_verifier


class OAuth2Flow:
    """
    OAuth2 flow implementation following RFC 6749.

    Supports:
    - Authorization Code Flow (Section 4.1)
    - Authorization Code Flow with PKCE (RFC 7636)
    - Client Credentials Flow (Section 4.4)
    - Refresh Token Flow (Section 6)
    """

    def __init__(
        self,
        config: OIDCConfig,
        client_id: str,
        client_secret: str | None = None,
        redirect_uri: str | None = None,
        client: httpx.Client | None = None,
    ):
        """
        Initialize OAuth2 flow handler.

        Args:
            config: OIDC provider configuration
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret (optional for public clients)
            redirect_uri: Redirect URI for authorization code flow
            client: Optional httpx.Client for custom configuration
        """
        self.config = config
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._client = client
        self._own_client = client is None

    def __enter__(self):
        """Context manager entry."""
        if self._own_client:
            self._client = httpx.Client(timeout=30.0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._own_client and self._client:
            self._client.close()

    def build_authorization_url(
        self,
        scope: str | list[str] = "openid profile email",
        state: str | None = None,
        nonce: str | None = None,
        use_pkce: bool = True,
        extra_params: dict[str, str] | None = None,
    ) -> tuple[str, str, str | None]:
        """
        Build authorization URL for Authorization Code Flow (RFC 6749 Section 4.1).

        Args:
            scope: OAuth2 scopes (space-separated string or list)
            state: State parameter for CSRF protection (generated if not provided)
            nonce: Nonce for ID token validation (generated if not provided)
            use_pkce: Whether to use PKCE (RFC 7636)
            extra_params: Additional query parameters

        Returns:
            Tuple of (authorization_url, state, code_verifier)
            code_verifier is None if PKCE is not used

        Raises:
            AuthorizationError: If redirect_uri is not configured
        """
        if not self.redirect_uri:
            raise AuthorizationError("redirect_uri is required for authorization code flow")

        # Generate state if not provided
        if state is None:
            state = secrets.token_urlsafe(32)

        # Generate nonce if not provided and openid scope is requested
        if isinstance(scope, str):
            scopes_list = scope.split()
        else:
            scopes_list = scope
            scope = " ".join(scope)

        if nonce is None and "openid" in scopes_list:
            nonce = secrets.token_urlsafe(32)

        # Build base parameters
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": scope,
            "state": state,
        }

        if nonce:
            params["nonce"] = nonce

        # Add PKCE parameters
        code_verifier = None
        if use_pkce:
            code_verifier = generate_code_verifier()
            code_challenge, code_challenge_method = create_pkce_challenge(code_verifier)
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method

        # Add extra parameters
        if extra_params:
            params.update(extra_params)

        # Build URL
        auth_url = f"{self.config.authorization_endpoint}?{urlencode(params)}"

        return auth_url, state, code_verifier

    def parse_authorization_response(
        self,
        response_url: str,
        expected_state: str,
    ) -> str:
        """
        Parse authorization response and extract authorization code.

        Args:
            response_url: Full redirect URL with query parameters
            expected_state: Expected state value for validation

        Returns:
            Authorization code

        Raises:
            AuthorizationError: If response is invalid or contains error
        """
        parsed = urlparse(response_url)
        params = parse_qs(parsed.query)

        # Check for error response
        if "error" in params:
            error = params["error"][0]
            error_description = params.get("error_description", [""])[0]
            raise AuthorizationError(
                f"Authorization failed: {error} - {error_description}",
                error_code=error,
            )

        # Validate state
        if "state" not in params:
            raise AuthorizationError("Response missing state parameter")

        state = params["state"][0]
        if state != expected_state:
            raise AuthorizationError(
                "State mismatch: possible CSRF attack",
                error_code="state_mismatch",
            )

        # Extract code
        if "code" not in params:
            raise AuthorizationError("Response missing authorization code")

        return params["code"][0]

    def exchange_code_for_token(
        self,
        code: str,
        code_verifier: str | None = None,
    ) -> TokenResponse:
        """
        Exchange authorization code for tokens (RFC 6749 Section 4.1.3).

        Args:
            code: Authorization code
            code_verifier: PKCE code verifier (if PKCE was used)

        Returns:
            TokenResponse with access token and optional refresh token

        Raises:
            TokenError: If token exchange fails
        """
        if not self.redirect_uri:
            raise TokenError("redirect_uri is required for code exchange")

        # Build request payload
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }

        # Add PKCE verifier
        if code_verifier:
            data["code_verifier"] = code_verifier

        # Add client secret if available
        if self.client_secret:
            data["client_secret"] = self.client_secret

        return self._token_request(data)

    def refresh_access_token(self, refresh_token: str) -> TokenResponse:
        """
        Refresh access token using refresh token (RFC 6749 Section 6).

        Args:
            refresh_token: Refresh token

        Returns:
            TokenResponse with new access token

        Raises:
            TokenError: If refresh fails
        """
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }

        if self.client_secret:
            data["client_secret"] = self.client_secret

        return self._token_request(data)

    def client_credentials_flow(self, scope: str | None = None) -> TokenResponse:
        """
        Perform client credentials flow (RFC 6749 Section 4.4).

        Used for machine-to-machine authentication.

        Args:
            scope: Optional scope

        Returns:
            TokenResponse with access token

        Raises:
            TokenError: If authentication fails
        """
        if not self.client_secret:
            raise TokenError("client_secret is required for client credentials flow")

        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        if scope:
            data["scope"] = scope

        return self._token_request(data)

    def _token_request(self, data: dict[str, str]) -> TokenResponse:
        """
        Make token request to token endpoint.

        Args:
            data: Form data for token request

        Returns:
            TokenResponse

        Raises:
            TokenError: If request fails
            NetworkError: If network request fails
        """
        try:
            client = self._client or httpx.Client(timeout=30.0)

            response = client.post(
                self.config.token_endpoint,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",  # GitHub suporta JSON se pedirmos
                },
            )

            # Check for error response
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error = error_data.get("error", "unknown_error")
                    error_description = error_data.get("error_description", "")
                    raise TokenError(
                        f"Token request failed: {error} - {error_description}",
                        error_code=error,
                    )
                except (ValueError, KeyError):
                    raise TokenError(
                        f"Token request failed with status {response.status_code}",
                        error_code="http_error",
                    )

            response.raise_for_status()

            # Tentar parsear resposta - GitHub pode retornar JSON ou form-urlencoded
            content_type = response.headers.get("content-type", "").lower()
            response_data = None

            if "application/json" in content_type:
                response_data = response.json()
                # Validate response is a dict, not an array or other type
                if not isinstance(response_data, dict):
                    raise ValueError(f"Invalid token response type: {type(response_data).__name__}")
            elif "application/x-www-form-urlencoded" in content_type:
                # GitHub OAuth retorna em formato form-urlencoded por padrão
                from urllib.parse import parse_qs

                parsed = parse_qs(response.text)
                response_data = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
            else:
                # Fallback: tentar JSON primeiro, depois form-urlencoded
                if response.text.strip():
                    # Detectar pelo conteúdo
                    if response.text.strip().startswith("{"):
                        response_data = response.json()
                        # Validate response is a dict
                        if not isinstance(response_data, dict):
                            raise ValueError(
                                f"Invalid token response type: {type(response_data).__name__}"
                            )
                    else:
                        from urllib.parse import parse_qs

                        parsed = parse_qs(response.text)
                        response_data = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
                else:
                    raise ValueError("Empty response from token endpoint")

            if not response_data:
                raise ValueError("Failed to parse token response")

            return TokenResponse.from_dict(response_data)

        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"HTTP error during token request: {e.response.status_code}",
                error_code="http_error",
            ) from e
        except httpx.RequestError as e:
            raise NetworkError(
                f"Network error during token request: {e}",
                error_code="network_error",
            ) from e
        except (KeyError, ValueError) as e:
            raise TokenError(
                f"Invalid token response: {e}",
                error_code="invalid_response",
            ) from e
        finally:
            if self._own_client and not self._client:
                client.close()

    async def exchange_code_for_token_async(
        self,
        code: str,
        code_verifier: str | None = None,
    ) -> TokenResponse:
        """Exchange authorization code for tokens (async version)."""
        if not self.redirect_uri:
            raise TokenError("redirect_uri is required for code exchange")

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }

        if code_verifier:
            data["code_verifier"] = code_verifier

        if self.client_secret:
            data["client_secret"] = self.client_secret

        return await self._token_request_async(data)

    async def refresh_access_token_async(self, refresh_token: str) -> TokenResponse:
        """Refresh access token (async version)."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }

        if self.client_secret:
            data["client_secret"] = self.client_secret

        return await self._token_request_async(data)

    async def _token_request_async(self, data: dict[str, str]) -> TokenResponse:
        """Make async token request."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    self.config.token_endpoint,
                    data=data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json",  # GitHub suporta JSON se pedirmos
                    },
                )

                if response.status_code >= 400:
                    try:
                        error_data = response.json()
                        error = error_data.get("error", "unknown_error")
                        error_description = error_data.get("error_description", "")
                        raise TokenError(
                            f"Token request failed: {error} - {error_description}",
                            error_code=error,
                        )
                    except (ValueError, KeyError):
                        raise TokenError(
                            f"Token request failed with status {response.status_code}",
                            error_code="http_error",
                        )

                response.raise_for_status()

                # Tentar parsear resposta - GitHub pode retornar JSON ou form-urlencoded
                content_type = response.headers.get("content-type", "").lower()
                response_data = None

                if "application/json" in content_type:
                    response_data = response.json()
                    # Validate response is a dict, not an array or other type
                    if not isinstance(response_data, dict):
                        raise ValueError(
                            f"Invalid token response type: {type(response_data).__name__}"
                        )
                elif "application/x-www-form-urlencoded" in content_type:
                    # GitHub OAuth retorna em formato form-urlencoded por padrão
                    from urllib.parse import parse_qs

                    parsed = parse_qs(response.text)
                    response_data = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
                else:
                    # Fallback: tentar JSON primeiro, depois form-urlencoded
                    if response.text.strip():
                        # Detectar pelo conteúdo
                        if response.text.strip().startswith("{"):
                            response_data = response.json()
                            # Validate response is a dict
                            if not isinstance(response_data, dict):
                                raise ValueError(
                                    f"Invalid token response type: {type(response_data).__name__}"
                                )
                        else:
                            from urllib.parse import parse_qs

                            parsed = parse_qs(response.text)
                            response_data = {
                                k: v[0] if len(v) == 1 else v for k, v in parsed.items()
                            }
                    else:
                        raise ValueError("Empty response from token endpoint")

                if not response_data:
                    raise ValueError("Failed to parse token response")

                return TokenResponse.from_dict(response_data)

        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"HTTP error during token request: {e.response.status_code}",
                error_code="http_error",
            ) from e
        except httpx.RequestError as e:
            raise NetworkError(
                f"Network error during token request: {e}",
                error_code="network_error",
            ) from e
        except (KeyError, ValueError) as e:
            raise TokenError(
                f"Invalid token response: {e}",
                error_code="invalid_response",
            ) from e
