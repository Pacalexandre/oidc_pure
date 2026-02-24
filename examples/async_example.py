"""
Async example: Using async/await for OIDC operations.
"""

import asyncio

from oidc_pure import OIDCClient

ISSUER_URL = "https://keycloak.example.com/realms/myrealm"
CLIENT_ID = "my-app"
CLIENT_SECRET = "your-secret"
REDIRECT_URI = "http://localhost:8080/callback"


async def main():
    """Async authentication example."""

    # Initialize client
    client = OIDCClient(
        issuer_url=ISSUER_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
    )

    # Get authorization URL (synchronous)
    auth_url, state, code_verifier = client.get_authorization_url()

    print(f"Visit: {auth_url}")
    callback_url = input("Enter callback URL: ")

    # Exchange code for tokens (async)
    token = await client.handle_authorization_response_async(
        response_url=callback_url,
        expected_state=state,
        code_verifier=code_verifier,
    )

    print(f"\nAccess Token: {token.access_token[:50]}...")

    # Get user info (async)
    user_info = await client.get_user_info_async(token.access_token)

    print(f"\nUser: {user_info.name} ({user_info.email})")

    # Refresh token (async)
    if token.refresh_token:
        new_token = await client.refresh_token_async(token.refresh_token)
        print(f"\nNew Token: {new_token.access_token[:50]}...")


if __name__ == "__main__":
    asyncio.run(main())
