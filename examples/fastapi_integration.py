#!/usr/bin/env python3
"""
🚀 Exemplo: Integração da biblioteca OIDC com FastAPI
=====================================================

Este exemplo demonstra como usar a biblioteca OIDC para proteger
rotas FastAPI com autenticação OAuth2/OIDC.

Recursos:
- Login via OAuth2 (Keycloak, Google, GitHub, etc.)
- Middleware para validação de tokens
- Proteção de rotas
- Obtenção de dados do usuário autenticado

Instalação:
    pip install fastapi uvicorn python-jose[cryptography]

    Ou adicione ao pyproject.toml:
    [project.optional-dependencies]
    fastapi = ["fastapi>=0.104.0", "uvicorn[standard]>=0.24.0"]

Uso:
    python examples/fastapi_integration.py
    # Acesse: http://localhost:8000/docs
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# Importar biblioteca OIDC
from oidc_config import create_oidc_client, get_oidc_config

# =============================================================================
# CONFIGURAÇÃO
# =============================================================================

app = FastAPI(
    title="API com OIDC Authentication",
    description="Exemplo de API protegida com OAuth2/OIDC",
    version="1.0.0",
)

# Armazenamento temporário de sessões (use Redis/DB em produção)
sessions = {}
tokens = {}

# Security scheme
security = HTTPBearer()

# =============================================================================
# MODELOS
# =============================================================================


class UserSession:
    """Modelo de sessão do usuário."""

    def __init__(self, access_token: str, refresh_token: Optional[str], user_info: dict):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.user_info = user_info
        self.expires_at = datetime.now() + timedelta(hours=1)


# =============================================================================
# DEPENDÊNCIAS DE AUTENTICAÇÃO
# =============================================================================


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Dependência para obter o usuário autenticado a partir do token.

    Use esta dependência em rotas protegidas:
        @app.get("/protected")
        def protected_route(user: dict = Depends(get_current_user)):
            return {"user": user["email"]}
    """
    token = credentials.credentials

    # Verificar se o token está em cache
    if token in tokens:
        session = tokens[token]

        # Verificar se não expirou
        if session.expires_at > datetime.now():
            return session.user_info

    # Token inválido ou expirado
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido ou expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )


def optional_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[dict]:
    """
    Dependência para autenticação opcional.

    Retorna dados do usuário se autenticado, None caso contrário.
    Útil para rotas que podem ser acessadas por usuários anônimos e autenticados.
    """
    if not credentials:
        return None

    try:
        return get_current_user(credentials)
    except HTTPException:
        return None


# =============================================================================
# ROTAS DE AUTENTICAÇÃO
# =============================================================================


@app.get("/")
def home():
    """Página inicial."""
    return {
        "message": "API com OIDC Authentication",
        "endpoints": {
            "login": "/auth/login",
            "callback": "/auth/callback",
            "me": "/auth/me",
            "logout": "/auth/logout",
            "protected": "/api/protected",
            "docs": "/docs",
        },
    }


@app.get("/auth/login")
def login(provider: str = "keycloak"):
    """
    Inicia o fluxo de autenticação OAuth2.

    Parâmetros:
    - provider: keycloak, google, github, etc.

    Redireciona para a página de login do provedor.
    """
    try:
        # Criar cliente OIDC
        client = create_oidc_client(provider)

        # Gerar URL de autorização
        state = secrets.token_urlsafe(32)
        auth_url, _, code_verifier = client.get_authorization_url(
            scope="openid profile email", state=state, use_pkce=True
        )

        # Armazenar state e verifier na sessão (simplificado)
        sessions[state] = {
            "code_verifier": code_verifier,
            "provider": provider,
            "created_at": datetime.now(),
        }

        # Redirecionar para o provedor
        return RedirectResponse(url=auth_url)

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao iniciar autenticação: {str(e)}",
        )


@app.get("/auth/callback")
def callback(code: str, state: str):
    """
    Callback OAuth2 - recebe o código de autorização.

    Troca o código por tokens e cria a sessão do usuário.
    """
    try:
        # Verificar state (proteção CSRF)
        if state not in sessions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="State inválido ou expirado"
            )

        session_data = sessions.pop(state)
        provider = session_data["provider"]
        code_verifier = session_data["code_verifier"]

        # Criar cliente OIDC
        client = create_oidc_client(provider)

        # Trocar código por tokens
        config = get_oidc_config(provider)
        callback_url = f"{config.redirect_uri}?code={code}&state={state}"

        token = client.handle_authorization_response(
            callback_url, expected_state=state, code_verifier=code_verifier
        )

        # Obter informações do usuário
        user_info = client.get_user_info(token.access_token)

        # Criar sessão
        user_session = UserSession(
            access_token=token.access_token,
            refresh_token=token.refresh_token,
            user_info={
                "sub": user_info.sub,
                "name": user_info.name,
                "email": user_info.email,
                "preferred_username": user_info.preferred_username,
                "provider": provider,
            },
        )

        # Armazenar token (use Redis/DB em produção)
        tokens[token.access_token] = user_session

        # Retornar token para o cliente
        return {
            "access_token": token.access_token,
            "token_type": "Bearer",
            "user": user_session.user_info,
            "message": "Autenticação realizada com sucesso! Use o access_token no header Authorization",
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro no callback: {str(e)}"
        )


@app.get("/auth/me")
def me(user: dict = Depends(get_current_user)):
    """
    Retorna informações do usuário autenticado.

    Requer autenticação (Bearer token no header).
    """
    return {"user": user}


@app.post("/auth/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Faz logout (invalida o token).
    """
    token = credentials.credentials

    if token in tokens:
        tokens.pop(token)

    return {"message": "Logout realizado com sucesso"}


# =============================================================================
# ROTAS PROTEGIDAS (EXEMPLOS)
# =============================================================================


@app.get("/api/protected")
def protected_route(user: dict = Depends(get_current_user)):
    """
    Exemplo de rota protegida - requer autenticação.
    """
    return {
        "message": f"Olá, {user.get('name') or user.get('email')}!",
        "user": user,
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/admin")
def admin_route(user: dict = Depends(get_current_user)):
    """
    Exemplo de rota administrativa.

    Em produção, adicione verificação de roles/permissions aqui.
    """
    # Exemplo: verificar se o usuário é admin
    # if "admin" not in user.get("roles", []):
    #     raise HTTPException(status_code=403, detail="Acesso negado")

    return {"message": "Área administrativa", "user": user}


@app.get("/api/public")
def public_route(user: Optional[dict] = Depends(optional_auth)):
    """
    Exemplo de rota pública com autenticação opcional.
    """
    if user:
        return {"message": f"Olá, {user.get('name')}!", "authenticated": True, "user": user}
    else:
        return {"message": "Olá, visitante!", "authenticated": False}


# =============================================================================
# MIDDLEWARE (OPCIONAL)
# =============================================================================


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Middleware para logging de requisições (opcional).
    """
    start_time = datetime.now()

    # Processar requisição
    response = await call_next(request)

    # Log
    duration = (datetime.now() - start_time).total_seconds()
    print(f"{request.method} {request.url.path} - {response.status_code} - {duration:.3f}s")

    return response


# =============================================================================
# INICIALIZAÇÃO
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    print("\n" + "=" * 70)
    print("  🚀 FastAPI com OIDC Authentication")
    print("=" * 70)
    print("\nConfiguração:")
    print("  1. Configure o .env com suas credenciais OIDC")
    print("  2. Registre http://localhost:8000/auth/callback como redirect_uri")
    print("\nEndpoints:")
    print("  📖 Documentação: http://localhost:8000/docs")
    print("  🔐 Login:        http://localhost:8000/auth/login?provider=keycloak")
    print("  👤 Usuário:      http://localhost:8000/auth/me")
    print("  🔒 Protegida:    http://localhost:8000/api/protected")
    print("\nFluxo de autenticação:")
    print("  1. Acesse /auth/login?provider=keycloak")
    print("  2. Faça login no provedor")
    print("  3. Será redirecionado para /auth/callback")
    print("  4. Use o access_token recebido no header: Authorization: Bearer <token>")
    print("=" * 70 + "\n")

    uvicorn.run("fastapi_integration:app", host="0.0.0.0", port=8000, reload=True)
