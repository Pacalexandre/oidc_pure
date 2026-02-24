#!/usr/bin/env python3
"""
🔐 Teste Manual Completo - Biblioteca OIDC Python
=================================================
Script interativo para testar autenticação:
- Keycloak e Google OAuth
- Validação de tokens (ID Token e Access Token)
- Informações do usuário
- Porta unificada: 5400
"""

import asyncio
import json
import time
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from dataclasses import asdict
from datetime import datetime
from typing import Optional

from oidc_config import create_oidc_client, get_oidc_config, list_available_providers


# ──────────────────────────────────────────────────────────────────────────
# CALLBACK SERVER
# ──────────────────────────────────────────────────────────────────────────

callback_data = {
    "code": None,
    "state": None,
    "error": None,
    "error_description": None,
    "received": False,
    "full_path": None,
}


class CallbackHandler(BaseHTTPRequestHandler):
    """Handler para processar callback OAuth2/OIDC."""

    def log_message(self, format, *args):
        """Suprimir logs padrão do servidor HTTP."""
        pass

    def do_GET(self):
        """Processa requisição GET do callback."""
        global callback_data

        # Ignorar requisições para favicon, assets, etc
        if self.path.startswith("/favicon") or self.path.startswith("/static"):
            self.send_response(404)
            self.end_headers()
            return

        # Parse da URL e query string
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # DEBUG: Mostrar o que foi recebido
        print(f"\n🔍 DEBUG - Callback recebido:")
        print(f"   Path completo: {self.path}")
        print(f"   Query params: {dict(params)}")

        # Extrair parâmetros do callback
        callback_data["code"] = params.get("code", [None])[0]
        callback_data["state"] = params.get("state", [None])[0]
        callback_data["error"] = params.get("error", [None])[0]
        callback_data["error_description"] = params.get("error_description", [None])[0]
        callback_data["full_path"] = self.path
        callback_data["received"] = True

        # DEBUG: Mostrar o que foi extraído
        print(
            f"   Code extraído: {callback_data['code'][:30] if callback_data['code'] else 'None'}..."
        )
        print(
            f"   State extraído: {callback_data['state'][:30] if callback_data['state'] else 'None'}..."
        )
        print(f"   Error: {callback_data['error']}")
        print()

        # Preparar resposta HTML
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        if callback_data["error"]:
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Erro de Autenticação</title>
                <style>
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
                        max-width: 600px;
                        margin: 50px auto;
                        padding: 20px;
                        background: #ffebee;
                    }}
                    .error {{
                        background: #c62828;
                        color: white;
                        padding: 30px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }}
                    h1 {{margin-top: 0;}}
                </style>
            </head>
            <body>
                <div class="error">
                    <h1>❌ Erro na Autenticação</h1>
                    <p><strong>Erro:</strong> {callback_data["error"]}</p>
                    <p><strong>Descrição:</strong> {callback_data.get("error_description", "N/A")}</p>
                </div>
            </body>
            </html>
            """
        else:
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Autenticação Concluída</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
                        max-width: 600px;
                        margin: 50px auto;
                        padding: 20px;
                        background: #e8f5e9;
                    }
                    .success {
                        background: #2e7d32;
                        color: white;
                        padding: 30px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }
                    h1 {margin-top: 0;}
                </style>
            </head>
            <body>
                <div class="success">
                    <h1>✅ Autenticação Concluída com Sucesso!</h1>
                    <p>O token de acesso foi recebido.</p>
                    <p><strong>Você pode fechar esta janela e retornar ao terminal.</strong></p>
                </div>
            </body>
            </html>
            """

        self.wfile.write(html.encode("utf-8"))


def reset_callback_data():
    """Reseta os dados do callback para novo uso."""
    callback_data["code"] = None
    callback_data["state"] = None
    callback_data["error"] = None
    callback_data["error_description"] = None
    callback_data["received"] = False
    callback_data["full_path"] = None


# ──────────────────────────────────────────────────────────────────────────
# VALIDAÇÃO E DECODIFICAÇÃO DE TOKENS
# ──────────────────────────────────────────────────────────────────────────


def decode_and_display_token(client, token_string: str, token_type: str = "Token"):
    """
    Decodifica e exibe informações de um token JWT.

    Args:
        client: Cliente OIDC
        token_string: String do token JWT
        token_type: Tipo do token ("ID Token" ou "Access Token")
    """
    print(f"\n   📋 Decodificando {token_type}...")

    try:
        claims = client.decode_token(token_string)

        print(f"   ✅ {token_type} válido!")
        print(f"\n   CLAIMS DO {token_type.upper()}:")
        print("   " + "─" * 66)

        # Claims importantes para exibir
        important_claims = [
            "sub",
            "iss",
            "aud",
            "azp",
            "exp",
            "iat",
            "email",
            "email_verified",
            "name",
            "preferred_username",
            "scope",
            "given_name",
            "family_name",
        ]

        for claim in important_claims:
            if claim in claims:
                value = claims[claim]

                # Formatar timestamps
                if claim in ["exp", "iat"]:
                    try:
                        dt = datetime.fromtimestamp(value)
                        value_str = f"{value} ({dt.strftime('%Y-%m-%d %H:%M:%S')})"
                    except:
                        value_str = str(value)
                else:
                    value_str = str(value)
                    if len(value_str) > 60:
                        value_str = value_str[:60] + "..."

                print(f"   {claim:20s}: {value_str}")

        # Mostrar outros claims (até 5)
        other_claims = {k: v for k, v in claims.items() if k not in important_claims}
        if other_claims:
            print(f"\n   Outros claims:")
            for claim, value in list(other_claims.items())[:5]:
                value_str = str(value)
                if len(value_str) > 60:
                    value_str = value_str[:60] + "..."
                print(f"   {claim:20s}: {value_str}")

        print("   " + "─" * 66)

    except Exception as e:
        print(f"   ⚠️  Erro ao decodificar: {e}")


def validate_and_display_tokens(client, token, provider: str):
    """
    Valida e exibe informações completas dos tokens.

    Args:
        client: Cliente OIDC
        token: Objeto TokenResponse com tokens
        provider: Nome do provedor
    """
    print(f"\n🔍 VALIDAÇÃO DOS TOKENS ({provider.upper()}):")
    print("   " + "─" * 66)

    # Validar ID Token
    if token.id_token:
        decode_and_display_token(client, token.id_token, "ID Token")

    # Validar Access Token (se for JWT)
    if token.access_token:
        parts = token.access_token.split(".")
        if len(parts) == 3:  # É um JWT
            decode_and_display_token(client, token.access_token, "Access Token")
        else:
            print(f"\n   ℹ️  Access Token é opaco (não é JWT)")
            print(f"   Token: {token.access_token[:50]}...")


# ──────────────────────────────────────────────────────────────────────────
# FUNÇÕES DE TESTE
# ──────────────────────────────────────────────────────────────────────────


def test_keycloak():
    """Testa autenticação com Keycloak."""
    return test_provider("keycloak")


def test_google():
    """Testa autenticação com Google OAuth."""
    return test_provider("google")


def test_github():
    """Testa autenticação com GitHub OAuth."""
    return test_provider("github")


def test_provider(provider: str) -> bool:
    """
    Testa autenticação com um provedor específico.

    Args:
        provider: Nome do provedor ('keycloak', 'google', etc.)

    Returns:
        bool: True se autenticação foi bem sucedida
    """
    print("\n" + "=" * 70)
    print(f"  🔐 TESTE: {provider.upper()}")
    print("=" * 70)

    try:
        # Obter configuração
        print("\n📋 Configuração:")
        config = get_oidc_config(provider)
        print(f"   Issuer URL:    {config.issuer_url}")
        print(f"   Client ID:     {config.client_id[:30]}...")
        print(f"   Redirect URI:  {config.redirect_uri}")
        print(f"   Scopes:        {config.scopes}")

        # Verificar porta
        parsed_uri = urlparse(config.redirect_uri)
        port = parsed_uri.port or 5400
        print(f"\n🔍 Porta configurada: {port}")
        print(f"   ⚠️  IMPORTANTE: O redirect URI '{config.redirect_uri}'")
        print(f"      deve estar registrado exatamente assim no provedor!")

        # Criar cliente OIDC
        print(f"\n🔧 Criando cliente OIDC...")
        client = create_oidc_client(provider)
        print(f"   ✅ Cliente criado")

        # Iniciar servidor de callback
        print(f"\n🌐 Iniciando servidor de callback na porta {port}...")
        try:
            server = HTTPServer(("localhost", port), CallbackHandler)
            print(f"   ✅ Servidor iniciado")
        except OSError as e:
            print(f"   ❌ Erro: Porta {port} já está em uso")
            print(f"\n💡 Solução: Execute o comando abaixo para liberar a porta:")
            print(f"   kill -9 $(lsof -ti:{port})")
            return False

        # Iniciar servidor em thread separada
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        # Gerar URL de autorização
        print(f"\n🔑 Gerando URL de autorização...")
        auth_url, state, verifier = client.get_authorization_url()
        print(f"   ✅ URL gerada")
        print(f"   State: {state[:30]}...")
        if verifier:
            print(f"   Code Verifier: {verifier[:30]}...")

        # DEBUG: Mostrar URL completa (primeiros 150 caracteres)
        print(f"\n🔍 DEBUG - URL de autorização:")
        print(f"   {auth_url[:150]}...")

        # Abrir navegador
        print(f"\n🌐 Abrindo navegador para autenticação...")
        print("\n" + "━" * 70)
        print("👉 FAÇA LOGIN NO NAVEGADOR QUE SERÁ ABERTO")
        print("   (Se o navegador não abrir, copie a URL acima)")
        print("━" * 70)

        webbrowser.open(auth_url)

        # Aguardar callback (timeout de 120 segundos)
        print(f"\n⏳ Aguardando autenticação...")

        for i in range(120):
            if callback_data["received"]:
                break
            time.sleep(1)
            if i > 0 and i % 10 == 0:
                print(f"   ... aguardando ({i}s)")

        # Encerrar servidor
        server.shutdown()

        # DEBUG: Mostrar estado do callback após espera
        print(f"\n🔍 DEBUG - Estado do callback:")
        print(f"   Received: {callback_data['received']}")
        print(f"   Code: {callback_data['code'][:30] if callback_data['code'] else 'None'}...")
        print(f"   State: {callback_data['state'][:30] if callback_data['state'] else 'None'}...")
        print(f"   Error: {callback_data['error']}")
        print(f"   Full path: {callback_data['full_path']}")

        # Verificar se recebeu callback
        if not callback_data["received"]:
            print("\n❌ Timeout - callback não foi recebido após 120s")
            print("\n💡 Verifique:")
            print(f"   - O Redirect URI '{config.redirect_uri}' está registrado no provedor")
            print(f"   - Você completou o login no navegador")
            return False

        # Verificar erros
        if callback_data["error"]:
            print(f"\n❌ Erro: {callback_data['error']}")
            if callback_data.get("error_description"):
                print(f"   Descrição: {callback_data['error_description']}")
            return False

        # Verificar código de autorização
        if not callback_data["code"]:
            print("\n❌ Código de autorização não foi recebido")
            print("\n💡 POSSÍVEIS CAUSAS:")
            print(f"   1. O Redirect URI não está registrado corretamente no provedor")
            print(f"      Esperado: {config.redirect_uri}")
            print(f"   2. Você negou a autorização no navegador")
            print(f"   3. O provedor está retornando erro (verifique navegador)")
            print(f"   4. Problema de rede ou firewall")
            print(f"\n   Full path recebido: {callback_data.get('full_path', 'N/A')}")
            return False

        print(f"\n✅ Callback recebido!")
        print(f"   Code: {callback_data['code'][:30]}...")

        # Trocar código por tokens
        print(f"\n🎫 Trocando código de autorização por tokens...")
        callback_url = f"http://localhost:{port}{callback_data['full_path']}"

        token = client.handle_authorization_response(
            callback_url, expected_state=state, code_verifier=verifier
        )

        print(f"   ✅ Tokens obtidos!")

        # Exibir informações dos tokens
        print(f"\n   📊 INFORMAÇÕES DOS TOKENS:")
        print("   " + "─" * 66)
        print(f"   Access Token:  {token.access_token[:50]}...")
        print(f"   Token Type:    {token.token_type}")

        if token.expires_in:
            print(f"   Expires In:    {token.expires_in}s ({token.expires_in // 60} minutos)")
        else:
            print(f"   Expires In:    N/A (provedor não informou)")

        if token.id_token:
            print(f"   ID Token:      {token.id_token[:50]}...")
        if token.refresh_token:
            print(f"   Refresh Token: {token.refresh_token[:50]}...")
        if token.scope:
            print(f"   Scope:         {token.scope}")

        print("   " + "─" * 66)

        # Validar e decodificar tokens
        validate_and_display_tokens(client, token, provider)

        # Obter informações do usuário
        print(f"\n👤 Obtendo informações do usuário...")
        user_info = client.get_user_info(token.access_token)
        print(f"   ✅ Informações obtidas!")

        # Exibir dados do usuário
        print(f"\n   📋 DADOS DO USUÁRIO AUTENTICADO:")
        print("   " + "─" * 66)

        # Converter UserInfo para dicionário
        user_dict = asdict(user_info)
        claims_extra = user_dict.pop("claims", {})
        user_dict.update(claims_extra)

        # Campos importantes
        user_fields = [
            "sub",
            "name",
            "given_name",
            "family_name",
            "email",
            "email_verified",
            "preferred_username",
            "picture",
            "locale",
        ]

        for field in user_fields:
            if field in user_dict and user_dict[field] is not None:
                value = user_dict[field]
                if field == "picture" and len(str(value)) > 50:
                    value = str(value)[:50] + "..."
                print(f"   {field:20s}: {value}")

        # Outros campos adicionais
        other_fields = {
            k: v for k, v in user_dict.items() if k not in user_fields and v is not None
        }
        if other_fields:
            print(f"\n   Campos adicionais:")
            for field, value in list(other_fields.items())[:5]:
                value_str = str(value)
                if len(value_str) > 50:
                    value_str = value_str[:50] + "..."
                print(f"   {field:20s}: {value_str}")

        print("   " + "─" * 66)

        # Resumo final
        print("\n" + "=" * 70)
        print(f"  ✅ SUCESSO - {provider.upper()} AUTENTICADO!")
        print("=" * 70)
        print(f"\n📊 Resumo:")
        user_id = (
            user_dict.get("email")
            or user_dict.get("preferred_username")
            or user_dict.get("sub", "N/A")
        )
        print(f"   ✅ Usuário: {user_id}")
        if token.expires_in:
            print(f"   ✅ Token válido por: {token.expires_in}s ({token.expires_in // 60} min)")
        print(f"   ✅ Tokens validados e decodificados com sucesso")
        print(f"   ✅ Provedor: {provider.upper()}")

        return True

    except Exception as e:
        print(f"\n❌ Erro: {e}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        reset_callback_data()


def list_providers():
    """Lista todos os provedores disponíveis."""
    print("\n" + "=" * 70)
    print("  📋 PROVEDORES DISPONÍVEIS")
    print("=" * 70)

    try:
        providers = list_available_providers()

        if not providers:
            print("\n⚠️  Nenhum provedor configurado no .env")
            print("\n💡 Configure ao menos um provedor no arquivo .env:")
            print("   - {PROVIDER}_ISSUER_URL")
            print("   - {PROVIDER}_CLIENT_ID")
            print("   - {PROVIDER}_REDIRECT_URI")
            return

        print(f"\n✅ {len(providers)} provedor(es) configurado(s):\n")

        for provider in sorted(providers):
            try:
                config = get_oidc_config(provider)
                print(f"   🔹 {provider.upper()}")
                print(f"      Issuer: {config.issuer_url}")
                print(f"      Client ID: {config.client_id[:30]}...")
                print(f"      Redirect: {config.redirect_uri}")
                print(f"      Scopes: {config.scopes}")
                print()
            except Exception as e:
                print(f"   ⚠️  {provider.upper()}: Erro ao carregar ({e})")
                print()

    except Exception as e:
        print(f"\n❌ Erro: {e}")


def show_env_guide():
    """Mostra guia de como configurar provedores no .env."""
    print("\n" + "=" * 70)
    print("  📖 GUIA: CONFIGURAR PROVEDORES NO .ENV")
    print("=" * 70)

    print("""
Para adicionar um provedor OIDC, adicione ao arquivo .env:

{PROVIDER}_ISSUER_URL=https://issuer.exemplo.com
{PROVIDER}_CLIENT_ID=seu-client-id
{PROVIDER}_CLIENT_SECRET=seu-client-secret  # Opcional
{PROVIDER}_REDIRECT_URI=http://localhost:5400/callback
{PROVIDER}_SCOPES=openid profile email  # Opcional

Onde {PROVIDER} pode ser: KEYCLOAK, GOOGLE, MICROSOFT, OKTA, etc.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXEMPLO - Google OAuth:

GOOGLE_ISSUER_URL=https://accounts.google.com
GOOGLE_CLIENT_ID=123456789.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-abcdef123456
GOOGLE_REDIRECT_URI=http://localhost:5400/callback
GOOGLE_SCOPES=openid profile email

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXEMPLO - GitHub OAuth (GRATUITO):

GITHUB_ISSUER_URL=https://github.com
GITHUB_CLIENT_ID=Iv1.a1b2c3d4e5f6g7h8
GITHUB_CLIENT_SECRET=abc123def456ghi789jkl012mno345pqr678
GITHUB_REDIRECT_URI=http://localhost:5400/callback
GITHUB_SCOPES=user:email read:user

⚠️  Configure em: https://github.com/settings/developers

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EXEMPLO - Keycloak:

KEYCLOAK_ISSUER_URL=https://sso.exemplo.com/auth/realms/meu-realm
KEYCLOAK_CLIENT_ID=minha-app
KEYCLOAK_CLIENT_SECRET=1234-5678-abcd-efgh
KEYCLOAK_REDIRECT_URI=http://localhost:5400/callback
KEYCLOAK_SCOPES=openid profile email

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  IMPORTANTE:
   • Todos os Redirect URIs devem estar registrados no provedor
   • Use porta 5400 (ou ajuste conforme necessário)
   • O client_secret é opcional para fluxos públicos (PKCE)

📚 Mais informações: consulte README.md ou arquivo .env.example
    """)


# ──────────────────────────────────────────────────────────────────────────
# MENU PRINCIPAL
# ──────────────────────────────────────────────────────────────────────────


def show_menu():
    """Exibe o menu principal."""
    print("\n" + "=" * 70)
    print("  🔐 TESTE MANUAL - BIBLIOTECA OIDC PYTHON")
    print("=" * 70)
    print("""
Este script permite testar autenticação OIDC/OAuth2 de forma interativa.

TESTES DE AUTENTICAÇÃO:
   [1] 🔑 Testar Keycloak
   [2] 🌐 Testar Google OAuth
   [3] � Testar GitHub OAuth
   [4] 🔄 Testar múltiplos provedores

GERENCIAMENTO:
   [5] 📋 Listar provedores disponíveis
   [6] 📖 Guia para configurar provedores no .env

SAIR:
   [0] ❌ Sair

⚠️  IMPORTANTE:
   • Os Redirect URIs devem estar registrados nos provedores
   • Porta padrão: 5400 (http://localhost:5400/callback)
   • Se necessário, libere a porta: kill -9 $(lsof -ti:5400)
    """)


def main_menu():
    """Loop principal do menu."""
    choice = input("Escolha uma opção: ").strip()

    if choice == "0":
        print("\n👋 Até logo!")
        return False

    elif choice == "1":
        success = test_keycloak()
        print(f"\n{'✅ Sucesso' if success else '❌ Falhou'}")

    elif choice == "2":
        success = test_google()
        print(f"\n{'✅ Sucesso' if success else '❌ Falhou'}")

    elif choice == "3":
        success = test_github()
        print(f"\n{'✅ Sucesso' if success else '❌ Falhou'}")

    elif choice == "4":
        print("\n📋 Testando múltiplos provedores...\n")

        # Descobrir quais provedores estão configurados
        available = list_available_providers()
        configured = [p for p, ok in available.items() if ok]

        if not configured:
            print("❌ Nenhum provedor configurado!")
            return True

        print(f"Provedores configurados: {', '.join(p.upper() for p in configured)}\n")

        results = {}
        for i, provider in enumerate(configured, 1):
            print("━" * 70)
            print(f"TESTE {i}/{len(configured)}: {provider.upper()}")
            print("━" * 70)
            results[provider] = test_provider(provider)

            if i < len(configured):
                print("\n")
                input(f"Pressione ENTER para continuar com {configured[i].upper()}...")

        print("\n" + "=" * 70)
        print("  📊 RESUMO FINAL")
        print("=" * 70)
        for provider, success in results.items():
            status = "✅ Sucesso" if success else "❌ Falhou"
            print(f"   {provider.capitalize():12s}: {status}")

    elif choice == "5":
        list_providers()

    elif choice == "6":
        show_env_guide()

    else:
        print("\n❌ Opção inválida. Tente novamente.")

    return True


# ──────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        # Carregar variáveis de ambiente
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    try:
        # Loop do menu
        while True:
            show_menu()
            if not main_menu():
                break

    except KeyboardInterrupt:
        print("\n\n👋 Cancelado pelo usuário")

    except Exception as e:
        print(f"\n❌ Erro inesperado: {e}")
        import traceback

        traceback.print_exc()
