"""
Simple example: Basic OIDC authentication flow.
"""

from oidc_pure import OIDCClient

# Configure your Keycloak instance
ISSUER_URL = "https://keycloak.example.com/realms/myrealm"
CLIENT_ID = "my-app"
CLIENT_SECRET = "your-secret"  # Optional for public clients
REDIRECT_URI = "http://localhost:8080/callback"


def main():
    """Simple authentication example."""

    # Initialize client with automatic discovery
    client = OIDCClient(
        issuer_url=ISSUER_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
    )

    # Step 1: Get authorization URL
    auth_url, state, code_verifier = client.get_authorization_url(
        scope="openid profile email",
        use_pkce=True,  # Use PKCE for enhanced security
    )

    print(f"Please visit: {auth_url}")

    # Step 2: After user authorizes, get the callback URL
    # In a real app, this would come from your web server
    callback_url = input("Enter callback URL: ")

    # Step 3: Exchange authorization code for tokens
    token = client.handle_authorization_response(
        response_url=callback_url,
        expected_state=state,
        code_verifier=code_verifier,
    )

    print(f"\nAccess Token: {token.access_token[:50]}...")
    print(f"Token Type: {token.token_type}")
    print(f"Expires In: {token.expires_in} seconds")

    # Step 4: Get user information
    user_info = client.get_user_info(token.access_token)

    print("\nUser Information:")
    print(f"  Name: {user_info.name}")
    print(f"  Email: {user_info.email}")
    print(f"  Username: {user_info.preferred_username}")

    # Step 5: Validate token
    claims = client.validate_token(token.access_token, verify_signature=False)
    print("\nToken Claims:")
    print(f"  Subject: {claims.get('sub')}")
    print(f"  Issued At: {claims.get('iat')}")
    print(f"  Expires At: {claims.get('exp')}")

    # Step 6: Refresh token (if needed)
    if token.refresh_token:
        new_token = client.refresh_token(token.refresh_token)
        print(f"\nRefreshed Access Token: {new_token.access_token[:50]}...")


if __name__ == "__main__":
    main()
