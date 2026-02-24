"""Main OIDC client for OAuth2/OIDC operations."""

from typing import Any

import httpx

from oidc_pure.discovery import OIDCDiscovery
from oidc_pure.exceptions import NetworkError
from oidc_pure.models import OIDCConfig, TokenResponse, UserInfo
from oidc_pure.oauth2 import OAuth2Flow
from oidc_pure.tokens import TokenValidator


class OIDCClient:
    """
    Main OIDC client for OAuth2/OpenID Connect operations.

    Provides a high-level interface for:
    - OIDC Discovery
    - Authorization Code Flow with PKCE
    - Token management and validation
    - User information retrieval
    - Token refresh

    Example:
        ```python
        from oidc_pure import OIDCClient

        # Initialize client
        client = OIDCClient(
            issuer_url="https://keycloak.example.com/realms/myrealm",
            client_id="my-client",
            client_secret="my-secret",
            redirect_uri="http://localhost:8080/callback"
        )

        # Start authorization flow
        auth_url, state, verifier = client.get_authorization_url()

        # After user authorization, exchange code for token
        token = client.handle_authorization_response(
            response_url="http://localhost:8080/callback?code=...",
            expected_state=state,
            code_verifier=verifier
        )

        # Get user information
        user_info = client.get_user_info(token.access_token)
        print(f"Hello, {user_info.name}!")
        ```
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        client_secret: str | None = None,
        redirect_uri: str | None = None,
        config: OIDCConfig | None = None,
        client: httpx.Client | None = None,
        auto_discover: bool = True,
    ):
        """
        Initialize OIDC client.

        Args:
            issuer_url: OIDC issuer URL (e.g., https://keycloak.example.com/realms/myrealm)
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret (optional for public clients)
            redirect_uri: Redirect URI for authorization code flow
            config: Pre-configured OIDCConfig (skip discovery if provided)
            client: Optional httpx.Client for custom configuration
            auto_discover: Automatically discover provider configuration

        Raises:
            DiscoveryError: If auto_discover is True and discovery fails
        """
        self.issuer_url = issuer_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self._client = client
        self._own_client = client is None

        # Store config or discover it
        if config:
            self.config = config
        elif auto_discover:
            self.config = self._discover_config()
        else:
            self.config = None  # type: ignore

        # Initialize OAuth2 flow handler
        if self.config:
            self._oauth2 = OAuth2Flow(
                config=self.config,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                client=self._get_client(),
            )

        # Initialize token validator
        self._validator = TokenValidator(
            issuer=self.issuer_url,
            client_id=client_id,
            client_secret=client_secret,
        )

    def __enter__(self):
        """Context manager entry."""
        if self._own_client:
            self._client = httpx.Client(timeout=30.0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._own_client and self._client:
            self._client.close()

    def _get_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if not self._client:
            self._client = httpx.Client(timeout=30.0)
        return self._client

    def _discover_config(self) -> OIDCConfig:
        """Discover OIDC provider configuration."""
        with OIDCDiscovery(client=self._get_client()) as discovery:
            return discovery.discover(self.issuer_url)

    def get_authorization_url(
        self,
        scope: str | list[str] = "openid profile email",
        state: str | None = None,
        nonce: str | None = None,
        use_pkce: bool = True,
        **extra_params,
    ) -> tuple[str, str, str | None]:
        """
        Generate authorization URL for user authentication.

        Args:
            scope: OAuth2 scopes (default: "openid profile email")
            state: State parameter for CSRF protection (auto-generated if not provided)
            nonce: Nonce for ID token validation (auto-generated if not provided)
            use_pkce: Use PKCE for enhanced security (recommended)
            **extra_params: Additional query parameters

        Returns:
            Tuple of (authorization_url, state, code_verifier)

        Example:
            ```python
            auth_url, state, verifier = client.get_authorization_url()
            print(f"Please visit: {auth_url}")
            ```
        """
        return self._oauth2.build_authorization_url(
            scope=scope,
            state=state,
            nonce=nonce,
            use_pkce=use_pkce,
            extra_params=extra_params or None,
        )

    def handle_authorization_response(
        self,
        response_url: str,
        expected_state: str,
        code_verifier: str | None = None,
    ) -> TokenResponse:
        """
        Handle authorization response and exchange code for tokens.

        Args:
            response_url: Full redirect URL with authorization code
            expected_state: Expected state value for CSRF validation
            code_verifier: PKCE code verifier (if PKCE was used)

        Returns:
            TokenResponse with access_token, refresh_token, and id_token

        Raises:
            AuthorizationError: If response is invalid
            TokenError: If token exchange fails

        Example:
            ```python
            token = client.handle_authorization_response(
                response_url="http://localhost:8080/callback?code=...",
                expected_state=state,
                code_verifier=verifier
            )
            ```
        """
        # Parse response and extract code
        code = self._oauth2.parse_authorization_response(response_url, expected_state)

        # Exchange code for tokens
        return self._oauth2.exchange_code_for_token(code, code_verifier)

    def get_user_info(self, access_token: str) -> UserInfo:
        """
        Retrieve user information from userinfo endpoint.

        Args:
            access_token: Valid access token

        Returns:
            UserInfo with user claims

        Raises:
            NetworkError: If request fails

        Example:
            ```python
            user_info = client.get_user_info(token.access_token)
            print(f"User: {user_info.name} ({user_info.email})")
            ```
        """
        try:
            client = self._get_client()
            response = client.get(
                self.config.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()

            data = response.json()
            return UserInfo.from_dict(data)

        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"HTTP error fetching user info: {e.response.status_code}",
                error_code="http_error",
            ) from e
        except httpx.RequestError as e:
            raise NetworkError(
                f"Network error fetching user info: {e}",
                error_code="network_error",
            ) from e

    def refresh_token(self, refresh_token: str) -> TokenResponse:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            TokenResponse with new access token

        Raises:
            TokenError: If refresh fails

        Example:
            ```python
            new_token = client.refresh_token(token.refresh_token)
            ```
        """
        return self._oauth2.refresh_access_token(refresh_token)

    def validate_token(
        self,
        token: str,
        verify_signature: bool = False,
        leeway: int = 60,
    ) -> dict[str, Any]:
        """
        Validate JWT token.

        Args:
            token: JWT token to validate
            verify_signature: Verify token signature (requires client_secret for HMAC)
            leeway: Time leeway in seconds for exp/nbf validation

        Returns:
            Validated token claims

        Raises:
            ValidationError: If validation fails

        Note:
            Signature verification only supports HMAC (HS256/HS384/HS512) algorithms
            in this pure implementation. For RSA/ECDSA, use verify_signature=False
            and validate through other means.

        Example:
            ```python
            claims = client.validate_token(token.access_token)
            print(f"Token subject: {claims['sub']}")
            ```
        """
        return self._validator.validate_token(
            token=token,
            verify_signature=verify_signature,
            leeway=leeway,
        )

    def decode_token(self, token: str) -> dict[str, Any]:
        """
        Decode JWT token without validation.

        Useful for inspecting token claims without full validation.

        Args:
            token: JWT token to decode

        Returns:
            Token payload (claims)

        Example:
            ```python
            claims = client.decode_token(token.id_token)
            print(f"Token expires at: {claims['exp']}")
            ```
        """
        return self._validator.extract_claims(token)

    def client_credentials_grant(self, scope: str | None = None) -> TokenResponse:
        """
        Perform client credentials grant for machine-to-machine authentication.

        Args:
            scope: Optional scope

        Returns:
            TokenResponse with access token

        Raises:
            TokenError: If grant fails

        Note:
            Requires client_secret to be configured.

        Example:
            ```python
            token = client.client_credentials_grant(scope="api:read")
            ```
        """
        return self._oauth2.client_credentials_flow(scope)

    def logout_url(
        self,
        id_token_hint: str | None = None,
        post_logout_redirect_uri: str | None = None,
    ) -> str | None:
        """
        Generate logout URL for ending user session.

        Args:
            id_token_hint: ID token to hint which user to logout
            post_logout_redirect_uri: Where to redirect after logout

        Returns:
            Logout URL or None if end_session_endpoint not available

        Example:
            ```python
            logout_url = client.logout_url(
                id_token_hint=token.id_token,
                post_logout_redirect_uri="http://localhost:8080"
            )
            if logout_url:
                print(f"Logout at: {logout_url}")
            ```
        """
        if not self.config.end_session_endpoint:
            return None

        params = []
        if id_token_hint:
            params.append(f"id_token_hint={id_token_hint}")
        if post_logout_redirect_uri:
            params.append(f"post_logout_redirect_uri={post_logout_redirect_uri}")

        if params:
            return f"{self.config.end_session_endpoint}?{'&'.join(params)}"
        return self.config.end_session_endpoint

    async def get_user_info_async(self, access_token: str) -> UserInfo:
        """Retrieve user information (async version)."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.config.userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                response.raise_for_status()

                data = response.json()
                return UserInfo.from_dict(data)

        except httpx.HTTPStatusError as e:
            raise NetworkError(
                f"HTTP error fetching user info: {e.response.status_code}",
                error_code="http_error",
            ) from e
        except httpx.RequestError as e:
            raise NetworkError(
                f"Network error fetching user info: {e}",
                error_code="network_error",
            ) from e

    async def handle_authorization_response_async(
        self,
        response_url: str,
        expected_state: str,
        code_verifier: str | None = None,
    ) -> TokenResponse:
        """Handle authorization response and exchange code (async version)."""
        code = self._oauth2.parse_authorization_response(response_url, expected_state)
        return await self._oauth2.exchange_code_for_token_async(code, code_verifier)

    async def refresh_token_async(self, refresh_token: str) -> TokenResponse:
        """Refresh access token (async version)."""
        return await self._oauth2.refresh_access_token_async(refresh_token)
