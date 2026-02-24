"""
Sistema de configuração multi-provider para OIDC.

Carrega configurações de forma genérica, permitindo trocar de provedor
facilmente através da variável OIDC_PROVIDER.

Uso:
    from oidc_config import get_oidc_config, create_oidc_client

    # Carrega automaticamente do .env
    config = get_oidc_config()

    # Cria cliente OIDC
    client = create_oidc_client()

    # Ou especifica provedor
    client = create_oidc_client(provider='google')
"""

import os
from dataclasses import dataclass
from typing import Dict, Optional


def _get_github_config(issuer_url: str):
    """Retorna configuração pré-definida para GitHub OAuth (não suporta OIDC Discovery)."""
    from oidc_pure.models import OIDCConfig

    return OIDCConfig(
        issuer=issuer_url,
        authorization_endpoint="https://github.com/login/oauth/authorize",
        token_endpoint="https://github.com/login/oauth/access_token",
        userinfo_endpoint="https://api.github.com/user",
        jwks_uri="https://github.com/.well-known/jwks.json",  # Não existe, mas obrigatório
        scopes_supported=["user", "user:email", "read:user", "repo"],
        response_types_supported=["code"],
        grant_types_supported=["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported=["client_secret_post"],
        code_challenge_methods_supported=["S256"],
    )


@dataclass
class OIDCProviderConfig:
    """Configuração de um provedor OIDC."""

    issuer_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: str = "openid profile email"
    use_pkce: bool = True
    verify_ssl: bool = True
    token_leeway: int = 60


# =============================================================================
# FUNÇÕES PRINCIPAIS
# =============================================================================


def get_oidc_config(provider: Optional[str] = None) -> OIDCProviderConfig:
    """
    Obtém configuração OIDC do provedor especificado.

    Args:
        provider: Nome do provedor (keycloak, google, microsoft, etc.)
                 Se None, usa OIDC_PROVIDER do .env

    Returns:
        OIDCProviderConfig com as configurações

    Raises:
        ValueError: Se configuração estiver incompleta

    Examples:
        # Usa provedor ativo do .env
        config = get_oidc_config()

        # Força Google
        config = get_oidc_config('google')

        # Força Keycloak
        config = get_oidc_config('keycloak')
    """
    # Determinar provedor
    if provider is None:
        provider = os.getenv("OIDC_PROVIDER", "keycloak").lower()
    else:
        provider = provider.lower()

    # Tentar carregar configuração específica do provedor
    prefix = provider.upper()

    issuer_url = os.getenv(f"{prefix}_ISSUER_URL")
    client_id = os.getenv(f"{prefix}_CLIENT_ID")
    client_secret = os.getenv(f"{prefix}_CLIENT_SECRET")
    redirect_uri = os.getenv(f"{prefix}_REDIRECT_URI")
    scopes = os.getenv(f"{prefix}_SCOPES", "openid profile email")

    # Fallback para variáveis genéricas se não encontrar específicas
    if not issuer_url:
        issuer_url = os.getenv("OIDC_ISSUER_URL")
    if not client_id:
        client_id = os.getenv("OIDC_CLIENT_ID")
    if not client_secret:
        client_secret = os.getenv("OIDC_CLIENT_SECRET")
    if not redirect_uri:
        redirect_uri = os.getenv("OIDC_REDIRECT_URI")
    if scopes == "openid profile email":
        scopes = os.getenv("OIDC_SCOPES", "openid profile email")

    # Validar configuração obrigatória
    if not issuer_url:
        raise ValueError(
            f"Issuer URL não configurado para provedor '{provider}'. "
            f"Configure {prefix}_ISSUER_URL ou OIDC_ISSUER_URL"
        )
    if not client_id:
        raise ValueError(
            f"Client ID não configurado para provedor '{provider}'. "
            f"Configure {prefix}_CLIENT_ID ou OIDC_CLIENT_ID"
        )
    if not client_secret:
        raise ValueError(
            f"Client Secret não configurado para provedor '{provider}'. "
            f"Configure {prefix}_CLIENT_SECRET ou OIDC_CLIENT_SECRET"
        )

    # Configurações adicionais
    use_pkce = os.getenv("OIDC_USE_PKCE", "true").lower() == "true"
    verify_ssl = os.getenv("OIDC_VERIFY_SSL", "true").lower() == "true"
    token_leeway = int(os.getenv("OIDC_TOKEN_LEEWAY", "60"))

    return OIDCProviderConfig(
        issuer_url=issuer_url,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri or "http://localhost:8080/callback",
        scopes=scopes,
        use_pkce=use_pkce,
        verify_ssl=verify_ssl,
        token_leeway=token_leeway,
    )


def create_oidc_client(provider: Optional[str] = None):
    """
    Cria um cliente OIDC configurado com o provedor especificado.

    Args:
        provider: Nome do provedor (keycloak, google, github, microsoft, etc.)
                 Se None, usa OIDC_PROVIDER do .env

    Returns:
        OIDCClient configurado e pronto para uso

    Examples:
        # Cliente com provedor ativo
        client = create_oidc_client()

        # Cliente com Google
        client = create_oidc_client('google')
        token = client.client_credentials_grant()

        # Cliente com GitHub (OAuth2 puro, sem OIDC Discovery)
        client = create_oidc_client('github')
        auth_url, state, verifier = client.get_authorization_url()

        # Cliente com Keycloak
        client = create_oidc_client('keycloak')
        auth_url, state, verifier = client.get_authorization_url()
    """
    from oidc_pure import OIDCClient

    config = get_oidc_config(provider)

    # Determinar provedor para configurações especiais
    if provider is None:
        provider = os.getenv("OIDC_PROVIDER", "keycloak").lower()
    else:
        provider = provider.lower()

    # GitHub OAuth não suporta OIDC Discovery - usar config manual
    if provider == "github":
        oidc_config = _get_github_config(config.issuer_url)
        return OIDCClient(
            issuer_url=config.issuer_url,
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=config.redirect_uri,
            config=oidc_config,
            auto_discover=False,
        )

    # Outros provedores: usar OIDC Discovery automático
    return OIDCClient(
        issuer_url=config.issuer_url,
        client_id=config.client_id,
        client_secret=config.client_secret,
        redirect_uri=config.redirect_uri,
    )


def list_available_providers() -> Dict[str, bool]:
    """
    Lista provedores disponíveis (configurados no .env).

    Returns:
        Dict com nome do provedor e se está configurado

    Example:
        providers = list_available_providers()
        for name, configured in providers.items():
            if configured:
                print(f"✅ {name}")
    """
    providers = {}

    for name in ["keycloak", "google", "github", "microsoft", "okta", "auth0"]:
        prefix = name.upper()
        issuer = os.getenv(f"{prefix}_ISSUER_URL")
        client_id = os.getenv(f"{prefix}_CLIENT_ID")
        client_secret = os.getenv(f"{prefix}_CLIENT_SECRET")

        providers[name] = all([issuer, client_id, client_secret])

    return providers


def get_active_provider() -> str:
    """
    Retorna o nome do provedor ativo.

    Returns:
        Nome do provedor (ex: 'keycloak', 'google')
    """
    return os.getenv("OIDC_PROVIDER", "keycloak").lower()


def print_config_info(provider: Optional[str] = None):
    """
    Imprime informações sobre a configuração atual.

    Args:
        provider: Nome do provedor ou None para ativo
    """
    try:
        config = get_oidc_config(provider)
        provider_name = provider or get_active_provider()

        print("=" * 70)
        print(f"  Configuração OIDC: {provider_name.upper()}")
        print("=" * 70)
        print(f"Issuer URL:    {config.issuer_url}")
        print(f"Client ID:     {config.client_id}")
        print(f"Client Secret: {'*' * 8}{config.client_secret[-4:]}")
        print(f"Redirect URI:  {config.redirect_uri}")
        print(f"Scopes:        {config.scopes}")
        print(f"Use PKCE:      {config.use_pkce}")
        print(f"Verify SSL:    {config.verify_ssl}")
        print("=" * 70)

    except ValueError as e:
        print(f"❌ Erro: {e}")


# =============================================================================
# AUTO LOAD .env
# =============================================================================


def load_env():
    """Carrega variáveis do arquivo .env automaticamente."""
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        # python-dotenv não instalado, ok
        pass


# Carregar .env automaticamente ao importar
load_env()


# =============================================================================
# EXEMPLO DE USO
# =============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  Sistema de Configuração Multi-Provider OIDC")
    print("=" * 70)

    # Mostrar provedor ativo
    active = get_active_provider()
    print(f"\nProvedor ativo: {active.upper()}")

    # Listar provedores disponíveis
    print("\nProvedores configurados:")
    providers = list_available_providers()
    for name, configured in providers.items():
        status = "✅" if configured else "❌"
        print(f"  {status} {name}")

    # Mostrar configuração do provedor ativo
    print("\nConfiguração do provedor ativo:")
    print_config_info()

    # Testar criação de cliente
    print("\nTestando criação de cliente...")
    try:
        client = create_oidc_client()
        print("✅ Cliente criado com sucesso!")
        print(f"   Issuer: {client.config.issuer}")
        print(f"   Authorization endpoint: {client.config.authorization_endpoint}")
    except Exception as e:
        print(f"❌ Erro ao criar cliente: {e}")

    # Mostrar exemplo de troca de provedor
    print("\n" + "=" * 70)
    print("  Como trocar de provedor:")
    print("=" * 70)
    print("""
# No .env, mude apenas uma linha:
OIDC_PROVIDER=google  # ou keycloak, microsoft, okta, etc.

# No código Python:
from oidc_config import create_oidc_client

# Usa provedor ativo do .env
client = create_oidc_client()

# Ou força um provedor específico
client = create_oidc_client('google')
client = create_oidc_client('keycloak')

# O resto do código permanece igual!
token = client.client_credentials_grant()
    """)
