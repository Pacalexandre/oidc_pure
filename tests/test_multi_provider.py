"""
Testes para sistema multi-provider OIDC.

Testa o módulo oidc_config.py com múltiplos provedores (Keycloak, Google).
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from oidc_config import (
    OIDCProviderConfig,
    create_oidc_client,
    get_oidc_config,
    list_available_providers,
)


class TestMultiProviderConfig:
    """Testes para configuração multi-provider."""

    def test_get_config_keycloak_specific(self):
        """Testa carregamento de configuração específica do Keycloak."""
        env_vars = {
            "KEYCLOAK_ISSUER_URL": "https://sso.apps.alcoal.net.br/auth/realms/SUDES",
            "KEYCLOAK_CLIENT_ID": "cartorio",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REDIRECT_URI": "http://localhost:5400/callback",
            "KEYCLOAK_SCOPES": "openid profile email tjdft_profile",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = get_oidc_config("keycloak")

            assert config.issuer_url == "https://sso.apps.alcoal.net.br/auth/realms/SUDES"
            assert config.client_id == "cartorio"
            assert config.client_secret == "test-secret"
            assert config.redirect_uri == "http://localhost:5400/callback"
            assert config.scopes == "openid profile email tjdft_profile"
            assert config.use_pkce is True
            assert config.verify_ssl is True

    def test_get_config_google_specific(self):
        """Testa carregamento de configuração específica do Google."""
        env_vars = {
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            "GOOGLE_CLIENT_ID": "615084797912-test.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "GOCSPX-test",
            "GOOGLE_REDIRECT_URI": "http://localhost:5400/callback",
            "GOOGLE_SCOPES": "openid profile email",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = get_oidc_config("google")

            assert config.issuer_url == "https://accounts.google.com"
            assert config.client_id == "615084797912-test.apps.googleusercontent.com"
            assert config.client_secret == "GOCSPX-test"
            assert config.redirect_uri == "http://localhost:5400/callback"
            assert config.scopes == "openid profile email"

    def test_get_config_fallback_to_generic(self):
        """Testa fallback para variáveis genéricas OIDC_*."""
        env_vars = {
            "OIDC_ISSUER_URL": "https://generic.provider.com",
            "OIDC_CLIENT_ID": "generic-client",
            "OIDC_CLIENT_SECRET": "generic-secret",
            "OIDC_REDIRECT_URI": "http://localhost:5400/callback",
            "OIDC_SCOPES": "openid profile",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = get_oidc_config("custom")

            assert config.issuer_url == "https://generic.provider.com"
            assert config.client_id == "generic-client"
            assert config.client_secret == "generic-secret"
            assert config.redirect_uri == "http://localhost:5400/callback"
            assert config.scopes == "openid profile"

    def test_get_config_mixed_specific_and_generic(self):
        """Testa configuração com mix de variáveis específicas e genéricas."""
        env_vars = {
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            "GOOGLE_CLIENT_ID": "615084797912-test.apps.googleusercontent.com",
            "OIDC_CLIENT_SECRET": "generic-secret",  # Fallback
            "OIDC_REDIRECT_URI": "http://localhost:5400/callback",  # Fallback
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = get_oidc_config("google")

            assert config.issuer_url == "https://accounts.google.com"
            assert config.client_id == "615084797912-test.apps.googleusercontent.com"
            assert config.client_secret == "generic-secret"
            assert config.redirect_uri == "http://localhost:5400/callback"

    def test_get_config_missing_issuer_url(self):
        """Testa erro quando issuer URL não está configurado."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="Issuer URL não configurado"):
                get_oidc_config("keycloak")

    def test_get_config_missing_client_id(self):
        """Testa erro quando client ID não está configurado."""
        env_vars = {
            "OIDC_ISSUER_URL": "https://provider.com",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ValueError, match="Client ID não configurado"):
                get_oidc_config("test")

    def test_get_config_missing_client_secret(self):
        """Testa erro quando client secret não está configurado."""
        env_vars = {
            "OIDC_ISSUER_URL": "https://provider.com",
            "OIDC_CLIENT_ID": "test-client",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            with pytest.raises(ValueError, match="Client Secret não configurado"):
                get_oidc_config("test")

    def test_get_config_default_redirect_uri(self):
        """Testa que redirect URI tem valor default se não configurado."""
        env_vars = {
            "OIDC_ISSUER_URL": "https://provider.com",
            "OIDC_CLIENT_ID": "test-client",
            "OIDC_CLIENT_SECRET": "test-secret",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = get_oidc_config("test")
            # Deve ter um default
            assert config.redirect_uri is not None
            assert "localhost" in config.redirect_uri

    def test_get_config_default_provider_from_env(self):
        """Testa uso do provedor padrão da variável OIDC_PROVIDER."""
        env_vars = {
            "OIDC_PROVIDER": "google",
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            "GOOGLE_CLIENT_ID": "test-client",
            "GOOGLE_CLIENT_SECRET": "test-secret",
            "GOOGLE_REDIRECT_URI": "http://localhost:5400/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = get_oidc_config()  # Sem especificar provedor

            assert config.issuer_url == "https://accounts.google.com"

    def test_get_config_optional_parameters(self):
        """Testa parâmetros opcionais (use_pkce, verify_ssl, token_leeway)."""
        env_vars = {
            "OIDC_ISSUER_URL": "https://provider.com",
            "OIDC_CLIENT_ID": "test-client",
            "OIDC_CLIENT_SECRET": "test-secret",
            "OIDC_REDIRECT_URI": "http://localhost:5400/callback",
            "OIDC_USE_PKCE": "false",
            "OIDC_VERIFY_SSL": "false",
            "OIDC_TOKEN_LEEWAY": "120",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = get_oidc_config("test")

            assert config.use_pkce is False
            assert config.verify_ssl is False
            assert config.token_leeway == 120

    def test_get_config_case_insensitive_provider(self):
        """Testa que nome do provedor é case-insensitive."""
        env_vars = {
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            "GOOGLE_CLIENT_ID": "test-client",
            "GOOGLE_CLIENT_SECRET": "test-secret",
            "GOOGLE_REDIRECT_URI": "http://localhost:5400/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config_lower = get_oidc_config("google")
            config_upper = get_oidc_config("GOOGLE")
            config_mixed = get_oidc_config("GoOgLe")

            assert config_lower.issuer_url == config_upper.issuer_url == config_mixed.issuer_url


class TestCreateOIDCClient:
    """Testes para criação de cliente OIDC."""

    @patch("oidc_pure.OIDCClient")
    def test_create_client_keycloak(self, mock_client_class):
        """Testa criação de cliente para Keycloak."""
        env_vars = {
            "KEYCLOAK_ISSUER_URL": "https://sso.apps.alcoal.net.br/auth/realms/SUDES",
            "KEYCLOAK_CLIENT_ID": "cartorio",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REDIRECT_URI": "http://localhost:5400/callback",
        }

        mock_instance = MagicMock()
        mock_client_class.return_value = mock_instance

        with patch.dict(os.environ, env_vars, clear=True):
            client = create_oidc_client("keycloak")

            # Verificar que foi chamado com os parâmetros corretos
            mock_client_class.assert_called_once()
            call_args = mock_client_class.call_args

            assert call_args[1]["issuer_url"] == "https://sso.apps.alcoal.net.br/auth/realms/SUDES"
            assert call_args[1]["client_id"] == "cartorio"
            assert call_args[1]["client_secret"] == "test-secret"
            assert call_args[1]["redirect_uri"] == "http://localhost:5400/callback"
            assert client == mock_instance

    @patch("oidc_pure.OIDCClient")
    def test_create_client_google(self, mock_client_class):
        """Testa criação de cliente para Google."""
        env_vars = {
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            "GOOGLE_CLIENT_ID": "615084797912-test.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "GOCSPX-test",
            "GOOGLE_REDIRECT_URI": "http://localhost:5400/callback",
            "GOOGLE_SCOPES": "openid profile email",
        }

        mock_instance = MagicMock()
        mock_client_class.return_value = mock_instance

        with patch.dict(os.environ, env_vars, clear=True):
            create_oidc_client("google")

            call_args = mock_client_class.call_args

            assert call_args[1]["issuer_url"] == "https://accounts.google.com"
            assert call_args[1]["client_id"] == "615084797912-test.apps.googleusercontent.com"

    @patch("oidc_pure.OIDCClient")
    def test_create_client_default_provider(self, mock_client_class):
        """Testa criação de cliente com provedor padrão."""
        env_vars = {
            "OIDC_PROVIDER": "keycloak",
            "KEYCLOAK_ISSUER_URL": "https://sso.apps.alcoal.net.br/auth/realms/SUDES",
            "KEYCLOAK_CLIENT_ID": "cartorio",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REDIRECT_URI": "http://localhost:5400/callback",
        }

        mock_instance = MagicMock()
        mock_client_class.return_value = mock_instance

        with patch.dict(os.environ, env_vars, clear=True):
            create_oidc_client()  # Sem especificar provedor

            assert mock_client_class.called


class TestListAvailableProviders:
    """Testes para listagem de provedores disponíveis."""

    def test_list_providers_keycloak_only(self):
        """Testa listagem quando só Keycloak está configurado."""
        env_vars = {
            "KEYCLOAK_ISSUER_URL": "https://sso.apps.alcoal.net.br/auth/realms/SUDES",
            "KEYCLOAK_CLIENT_ID": "cartorio",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REDIRECT_URI": "http://localhost:5400/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            providers = list_available_providers()

            assert providers["keycloak"] is True
            assert providers["google"] is False

    def test_list_providers_google_only(self):
        """Testa listagem quando só Google está configurado."""
        env_vars = {
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            "GOOGLE_CLIENT_ID": "test-client",
            "GOOGLE_CLIENT_SECRET": "test-secret",
            "GOOGLE_REDIRECT_URI": "http://localhost:5400/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            providers = list_available_providers()

            assert providers["google"] is True
            assert providers["keycloak"] is False

    def test_list_providers_multiple(self):
        """Testa listagem com múltiplos provedores configurados."""
        env_vars = {
            "KEYCLOAK_ISSUER_URL": "https://sso.apps.alcoal.net.br/auth/realms/SUDES",
            "KEYCLOAK_CLIENT_ID": "cartorio",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REDIRECT_URI": "http://localhost:5400/callback",
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            "GOOGLE_CLIENT_ID": "test-client",
            "GOOGLE_CLIENT_SECRET": "test-secret",
            "GOOGLE_REDIRECT_URI": "http://localhost:5400/callback",
            "MICROSOFT_ISSUER_URL": "https://login.microsoftonline.com/common/v2.0",
            "MICROSOFT_CLIENT_ID": "test-client",
            "MICROSOFT_CLIENT_SECRET": "test-secret",
            "MICROSOFT_REDIRECT_URI": "http://localhost:5400/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            providers = list_available_providers()

            assert providers["keycloak"] is True
            assert providers["google"] is True
            assert providers["microsoft"] is True

    def test_list_providers_generic_only(self):
        """Testa listagem com apenas configuração genérica."""
        env_vars = {
            "OIDC_ISSUER_URL": "https://provider.com",
            "OIDC_CLIENT_ID": "test-client",
            "OIDC_CLIENT_SECRET": "test-secret",
            "OIDC_REDIRECT_URI": "http://localhost:5400/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            providers = list_available_providers()

            # Configuração genérica não aparece em providers específicos
            assert all(not configured for configured in providers.values())

    def test_list_providers_partial_config(self):
        """Testa que provedores incompletos não aparecem como configurados."""
        env_vars = {
            "KEYCLOAK_ISSUER_URL": "https://sso.apps.alcoal.net.br/auth/realms/SUDES",
            "KEYCLOAK_CLIENT_ID": "cartorio",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REDIRECT_URI": "http://localhost:5400/callback",
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            # Google incompleto: falta CLIENT_ID, CLIENT_SECRET, REDIRECT_URI
        }

        with patch.dict(os.environ, env_vars, clear=True):
            providers = list_available_providers()

            assert providers["keycloak"] is True
            assert providers["google"] is False

    def test_list_providers_empty(self):
        """Testa listagem quando nenhum provedor está configurado."""
        with patch.dict(os.environ, {}, clear=True):
            providers = list_available_providers()

            # Retorna dict com provedores conhecidos mas todos False
            assert all(not configured for configured in providers.values())


class TestOIDCProviderConfigDataclass:
    """Testes para o dataclass OIDCProviderConfig."""

    def test_config_creation_minimal(self):
        """Testa criação de config com parâmetros mínimos."""
        config = OIDCProviderConfig(
            issuer_url="https://provider.com",
            client_id="test-client",
            client_secret="test-secret",
            redirect_uri="http://localhost:5400/callback",
        )

        assert config.issuer_url == "https://provider.com"
        assert config.client_id == "test-client"
        assert config.client_secret == "test-secret"
        assert config.redirect_uri == "http://localhost:5400/callback"
        assert config.scopes == "openid profile email"  # Default
        assert config.use_pkce is True  # Default
        assert config.verify_ssl is True  # Default
        assert config.token_leeway == 60  # Default

    def test_config_creation_full(self):
        """Testa criação de config com todos os parâmetros."""
        config = OIDCProviderConfig(
            issuer_url="https://provider.com",
            client_id="test-client",
            client_secret="test-secret",
            redirect_uri="http://localhost:5400/callback",
            scopes="openid custom",
            use_pkce=False,
            verify_ssl=False,
            token_leeway=120,
        )

        assert config.scopes == "openid custom"
        assert config.use_pkce is False
        assert config.verify_ssl is False
        assert config.token_leeway == 120


class TestRealWorldScenarios:
    """Testes de cenários reais de uso."""

    @patch("oidc_pure.OIDCClient")
    def test_switch_provider_at_runtime(self, mock_client_class):
        """Testa trocar de provedor em tempo de execução."""
        env_vars = {
            "KEYCLOAK_ISSUER_URL": "https://sso.apps.alcoal.net.br/auth/realms/SUDES",
            "KEYCLOAK_CLIENT_ID": "cartorio",
            "KEYCLOAK_CLIENT_SECRET": "keycloak-secret",
            "KEYCLOAK_REDIRECT_URI": "http://localhost:5400/callback",
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            "GOOGLE_CLIENT_ID": "google-client",
            "GOOGLE_CLIENT_SECRET": "google-secret",
            "GOOGLE_REDIRECT_URI": "http://localhost:5400/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            # Cliente Keycloak
            create_oidc_client("keycloak")
            call_kc = mock_client_class.call_args[1]
            assert call_kc["client_id"] == "cartorio"

            # Cliente Google
            create_oidc_client("google")
            call_g = mock_client_class.call_args[1]
            assert call_g["client_id"] == "google-client"

    def test_keycloak_with_custom_scope(self):
        """Testa Keycloak com scope customizado (tjdft_profile)."""
        env_vars = {
            "KEYCLOAK_ISSUER_URL": "https://sso.apps.alcoal.net.br/auth/realms/SUDES",
            "KEYCLOAK_CLIENT_ID": "cartorio",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "KEYCLOAK_REDIRECT_URI": "http://localhost:5400/callback",
            "KEYCLOAK_SCOPES": "openid profile email tjdft_profile",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = get_oidc_config("keycloak")

            assert "tjdft_profile" in config.scopes

    def test_google_without_custom_scope(self):
        """Testa Google com scopes padrão (sem tjdft_profile)."""
        env_vars = {
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            "GOOGLE_CLIENT_ID": "test-client",
            "GOOGLE_CLIENT_SECRET": "test-secret",
            "GOOGLE_REDIRECT_URI": "http://localhost:5400/callback",
            "GOOGLE_SCOPES": "openid profile email",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            config = get_oidc_config("google")

            assert "tjdft_profile" not in config.scopes
            assert "openid" in config.scopes

    def test_unified_port_configuration(self):
        """Testa que todos os provedores usam a mesma porta (5400)."""
        env_vars = {
            "KEYCLOAK_REDIRECT_URI": "http://localhost:5400/callback",
            "KEYCLOAK_ISSUER_URL": "https://sso.apps.alcoal.net.br/auth/realms/SUDES",
            "KEYCLOAK_CLIENT_ID": "cartorio",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
            "GOOGLE_REDIRECT_URI": "http://localhost:5400/callback",
            "GOOGLE_ISSUER_URL": "https://accounts.google.com",
            "GOOGLE_CLIENT_ID": "test-client",
            "GOOGLE_CLIENT_SECRET": "test-secret",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            kc_config = get_oidc_config("keycloak")
            g_config = get_oidc_config("google")

            # Ambos devem usar porta 5400
            assert ":5400/" in kc_config.redirect_uri
            assert ":5400/" in g_config.redirect_uri
            assert kc_config.redirect_uri == g_config.redirect_uri
