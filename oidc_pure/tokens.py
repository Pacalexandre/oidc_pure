"""JWT token validation and manipulation."""

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from oidc_pure.exceptions import ValidationError


class TokenValidator:
    """
    JWT token validator for OIDC tokens.

    Implements basic JWT validation without external crypto libraries,
    supporting HS256, HS384, HS512 (HMAC) algorithms.

    Note: For production use with RSA/ECDSA, consider using cryptography library.
    """

    def __init__(self, issuer: str, client_id: str, client_secret: str | None = None):
        """
        Initialize token validator.

        Args:
            issuer: Expected token issuer
            client_id: OAuth2 client ID (expected audience)
            client_secret: Client secret for HMAC validation
        """
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret

    def decode_token(self, token: str) -> dict[str, Any]:
        """
        Decode JWT token without validation.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            ValidationError: If token format is invalid
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValidationError("Invalid JWT format: must have 3 parts")

            # Decode header and payload
            header = self._base64url_decode(parts[0])
            payload = self._base64url_decode(parts[1])

            return {
                "header": json.loads(header),
                "payload": json.loads(payload),
                "signature": parts[2],
            }
        except (ValueError, json.JSONDecodeError) as e:
            raise ValidationError(f"Failed to decode token: {e}") from e

    def validate_token(
        self,
        token: str,
        verify_signature: bool = True,
        leeway: int = 60,
    ) -> dict[str, Any]:
        """
        Validate JWT token.

        Args:
            token: JWT token string
            verify_signature: Whether to verify signature (requires client_secret for HS*)
            leeway: Time leeway in seconds for exp/nbf validation

        Returns:
            Validated token payload

        Raises:
            ValidationError: If validation fails
        """
        decoded = self.decode_token(token)
        header = decoded["header"]
        payload = decoded["payload"]

        # Validate signature if requested
        if verify_signature:
            alg = header.get("alg")
            if not alg:
                raise ValidationError("Token header missing 'alg' field")

            if alg.startswith("HS"):
                if not self.client_secret:
                    raise ValidationError("Client secret required for HMAC signature verification")
                self._verify_hmac_signature(token, alg)
            elif alg == "none":
                raise ValidationError("Algorithm 'none' not allowed")
            else:
                # For RS256, ES256, etc., we would need JWK validation
                # This is a simplified implementation
                raise ValidationError(
                    f"Algorithm {alg} not supported in pure implementation. "
                    "Use client_secret with HS256/HS384/HS512 or disable signature verification."
                )

        # Validate claims
        current_time = int(time.time())

        # Check issuer
        if "iss" in payload and payload["iss"] != self.issuer:
            raise ValidationError(f"Invalid issuer: expected {self.issuer}, got {payload['iss']}")

        # Check audience
        if "aud" in payload:
            aud = payload["aud"]
            audiences = [aud] if isinstance(aud, str) else aud
            if self.client_id not in audiences:
                raise ValidationError(f"Invalid audience: {self.client_id} not in {audiences}")

        # Check expiration
        if "exp" in payload:
            exp = payload["exp"]
            if current_time > exp + leeway:
                raise ValidationError("Token has expired")

        # Check not before
        if "nbf" in payload:
            nbf = payload["nbf"]
            if current_time < nbf - leeway:
                raise ValidationError("Token not yet valid")

        # Check issued at
        if "iat" in payload:
            iat = payload["iat"]
            if current_time < iat - leeway:
                raise ValidationError("Token issued in the future")

        return payload

    def _verify_hmac_signature(self, token: str, alg: str) -> None:
        """Verify HMAC signature."""
        if not self.client_secret:
            raise ValidationError("Client secret required for HMAC validation")

        parts = token.rsplit(".", 1)
        message = parts[0].encode("utf-8")
        signature = parts[1]

        # Select hash algorithm
        hash_alg = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg)

        if not hash_alg:
            raise ValidationError(f"Unsupported HMAC algorithm: {alg}")

        # Compute expected signature
        expected_sig = hmac.new(
            self.client_secret.encode("utf-8"),
            message,
            hash_alg,
        ).digest()

        expected_sig_b64 = self._base64url_encode(expected_sig)

        # Compare signatures (constant time)
        if not hmac.compare_digest(signature, expected_sig_b64):
            raise ValidationError("Invalid token signature")

    def extract_claims(self, token: str) -> dict[str, Any]:
        """
        Extract claims from token without full validation.
        Useful for debugging or when validation is done elsewhere.

        Args:
            token: JWT token string

        Returns:
            Token claims (payload)
        """
        decoded = self.decode_token(token)
        return decoded["payload"]

    @staticmethod
    def _base64url_decode(data: str) -> bytes:
        """Decode base64url encoded data."""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding

        # Replace URL-safe characters
        data = data.replace("-", "+").replace("_", "/")

        return base64.b64decode(data)

    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        """Encode data as base64url."""
        encoded = base64.b64encode(data).decode("utf-8")
        # Remove padding and make URL-safe
        return encoded.rstrip("=").replace("+", "-").replace("/", "_")


def create_pkce_challenge(code_verifier: str) -> tuple[str, str]:
    """
    Create PKCE code challenge from verifier.

    Implements RFC 7636: Proof Key for Code Exchange.

    Args:
        code_verifier: Random string (43-128 characters)

    Returns:
        Tuple of (code_challenge, code_challenge_method)
    """
    if not (43 <= len(code_verifier) <= 128):
        raise ValueError("Code verifier must be 43-128 characters")

    # Use S256 method
    challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    challenge_b64 = base64.urlsafe_b64encode(challenge).decode("utf-8").rstrip("=")

    return challenge_b64, "S256"


def generate_code_verifier(length: int = 64) -> str:
    """
    Generate random code verifier for PKCE.

    Args:
        length: Length of verifier (43-128)

    Returns:
        Random code verifier string
    """
    import secrets
    import string

    if not (43 <= length <= 128):
        raise ValueError("Length must be between 43 and 128")

    alphabet = string.ascii_letters + string.digits + "-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))
