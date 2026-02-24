# OIDC Pure - Manual Completo

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![RFC 6749](https://img.shields.io/badge/RFC-6749-green.svg)](https://datatracker.ietf.org/doc/html/rfc6749)
[![OIDC](https://img.shields.io/badge/OpenID-Connect-orange.svg)](https://openid.net/connect/)
[![Coverage](https://img.shields.io/badge/coverage-78%25-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/security-audited-brightgreen.svg)](SECURITY.md)
[![Dependencies](https://img.shields.io/badge/dependencies-0_CVEs-brightgreen.svg)]()

Implementação pura em Python de OAuth2 (RFC 6749) e OpenID Connect para Keycloak e outros provedores de identidade. Sistema multi-provider genérico com suporte a Google, GitHub, Microsoft, Okta, Auth0 e qualquer provedor OIDC compatível.

---

## 📑 Índice

1. [Visão Geral](#1-visão-geral)
2. [Instalação](#2-instalação)
3. [Configuração Multi-Provider](#3-configuração-multi-provider)
4. [Guia de Uso Rápido](#4-guia-de-uso-rápido)
5. [Exemplos Práticos](#5-exemplos-práticos)
6. [Arquitetura](#6-arquitetura)
7. [Configuração Keycloak](#7-configuração-keycloak)
8. [Testes](#8-testes)
9. [Referência da API](#9-referência-da-api)
10. [Auditoria de Segurança](#10-auditoria-de-segurança)
11. [Segurança](#11-segurança)

---

## 1. Visão Geral

### 1.1 Features

- ✅ **OAuth2 RFC 6749 Completo**: Implementação pura seguindo a especificação
- ✅ **OIDC Discovery**: Descoberta automática de endpoints
- ✅ **PKCE (RFC 7636)**: Proof Key for Code Exchange para segurança
- ✅ **Multi-Provider**: Sistema genérico para qualquer provedor OIDC
- ✅ **Authorization Code Flow**: Fluxo completo com suporte a PKCE
- ✅ **Client Credentials Flow**: Para autenticação machine-to-machine
- ✅ **Refresh Token Flow**: Renovação de tokens
- ✅ **JWT Validation**: Validação de tokens (claims, expiração)
- ✅ **UserInfo Endpoint**: Obtenção de perfil do usuário
- ✅ **httpx**: Cliente HTTP moderno (sync e async)
- ✅ **Type Hints**: Completamente tipado para melhor suporte IDE
- ✅ **Sem Banco de Dados**: Operação stateless

### 1.2 Provedores Suportados

| Provedor | Status | Porta | Scopes | Notas |
|----------|--------|-------|--------|-------|
| **Keycloak** | ✅ Testado | 5400 | `openid profile email tjdft_profile` | OIDC completo |
| **Google OAuth** | ✅ Testado | 5400 | `openid profile email` | OIDC completo |
| **GitHub OAuth** | ✅ Testado | 5400 | `user:email read:user` | OAuth2 puro* |
| **Microsoft Azure AD** | 🔧 Pronto | 5400 | `openid profile email User.Read` | OIDC completo |
| **Okta** | 🔧 Pronto | 5400 | `openid profile email` | OIDC completo |
| **Auth0** | 🔧 Pronto | 5400 | `openid profile email` | OIDC completo |
| **Genérico** | ✅ Qualquer OIDC | 5400 | Configurável | - |

*GitHub usa OAuth2 puro (não implementa OIDC Discovery). Endpoints são pré-configurados.

### 1.3 Estrutura do Projeto

```
oidc-pure/
├── oidc/                          # 📦 Biblioteca Principal
│   ├── __init__.py                # API pública
│   ├── client.py                  # OIDCClient (interface principal)
│   ├── oauth2.py                  # Fluxos OAuth2 (RFC 6749)
│   ├── discovery.py               # OIDC Discovery
│   ├── tokens.py                  # JWT validation e PKCE
│   ├── models.py                  # Modelos de dados
│   └── exceptions.py              # Exceções customizadas
│
├── oidc_config.py                 # 🔧 Sistema Multi-Provider
├── .env                           # 🔒 Configurações (não versionado)
├── .env.example                   # 📝 Template de configuração
│
├── examples/                      # 📚 Exemplos de Uso
│   ├── simple_example.py          # Exemplo básico
│   ├── async_example.py           # Exemplo assíncrono
│   ├── keycloak_example.py        # Exemplo Keycloak completo
│   ├── flask_integration.py       # Integração Flask
│   ├── fastapi_integration.py     # Integração FastAPI (completo)
│   ├── django_integration.py      # Integração Django 4.x/5.x (500+ linhas)
│   └── django_drf_integration.py  # Integração DRF (700+ linhas)
│
├── tests/                         # 🧪 Testes (78% cobertura)
│   ├── test_client.py             # Testes do cliente
│   ├── test_oauth2.py             # Testes OAuth2
│   ├── test_discovery.py          # Testes discovery
│   ├── test_tokens.py             # Testes JWT/PKCE
│   ├── test_integration.py        # Testes integração
│   └── test_multi_provider.py     # Testes multi-provider (26 testes)
│
└── README.md                      # Este arquivo
```

---

## 2. Instalação

### 2.1 Requisitos

- Python 3.12+
- httpx >= 0.27.0
- python-dotenv >= 1.2.1 (para multi-provider)

### 2.2 Instalação via uv (Recomendado)

```bash
# Clonar repositório
git clone https://github.com/seu-usuario/oidc-pure.git
cd oidc-pure

# Instalar dependências
uv sync

# Ativar ambiente virtual
source .venv/bin/activate  # Linux/Mac
# ou
.venv\Scripts\activate     # Windows
```

### 2.3 Instalação via pip

```bash
# Do diretório local
pip install -e .

# Do Git
pip install git+https://github.com/seu-usuario/oidc-pure.git
```

### 2.4 Instalação em Modo Desenvolvimento

```bash
# Para desenvolvimento ativo
cd /caminho/para/oidc-pure
pip install -e .
```

### 2.5 Componentes Opcionais

#### 📦 **Biblioteca Core (Obrigatório)**

O diretório `oidc/` contém a biblioteca principal e é **obrigatório** para uso em produção:

```python
from oidc import OIDCClient

# Uso direto da biblioteca core
client = OIDCClient(
    issuer_url="https://accounts.google.com",
    client_id="seu-client-id",
    client_secret="seu-secret",
    redirect_uri="http://localhost:5400/callback"
)
```

#### 🔧 **oidc_config.py (Opcional)**

O arquivo `oidc_config.py` é um **helper opcional** que simplifica o uso multi-provider através de variáveis de ambiente:

```python
from oidc_config import create_oidc_client

# Lê automaticamente do .env
client = create_oidc_client('google')  # Muito mais simples!
```

**Em produção**: Se você não precisa gerenciar múltiplos provedores dinamicamente, pode **remover** o `oidc_config.py` e usar apenas o core `oidc/`.

**⚠️ Impacto da remoção:**
- ❌ `test_manual.py` - Parará de funcionar (usa `oidc_config`)
- ❌ `tests/test_multi_provider.py` - 26 testes falharão
- ❌ `examples/fastapi_integration.py` - Precisará refatoração
- ❌ `examples/django_integration.py` - Pode usar core diretamente (exemplo inclui ambas abordagens)
- ❌ `examples/django_drf_integration.py` - Pode usar core diretamente (exemplo inclui ambas abordagens)
- ✅ Biblioteca core `oidc/` - Continua funcionando normalmente
- ✅ Exemplos `simple_example.py`, `async_example.py` - Não são afetados

**Recomendação**: Mantenha o `oidc_config.py` se você precisa trocar entre provedores (Keycloak, Google, GitHub) facilmente. Remova apenas se vai usar um único provedor configurado diretamente no código.

---

## 3. Configuração Multi-Provider

### 3.1 Visão Geral do Sistema

O sistema multi-provider permite usar **qualquer provedor OIDC** sem mudar código, apenas alterando variáveis de ambiente.

**Princípios:**
1. **Provedor Ativo**: `OIDC_PROVIDER` define qual usar
2. **Busca Específica**: Procura `{PROVIDER}_*` primeiro
3. **Fallback Genérico**: Se não encontrar, usa `OIDC_*`

### 3.2 Configuração Inicial

```bash
# 1. Copiar template
cp .env.example .env

# 2. Gerar secret key
python -c "import secrets; print(secrets.token_hex(32))"

# 3. Editar .env com suas credenciais
```

### 3.3 Estrutura do .env

```ini
# =============================================================================
# PROVEDOR ATIVO
# =============================================================================
OIDC_PROVIDER=keycloak     # keycloak, google, github, microsoft, okta, auth0

# =============================================================================
# CONFIGURAÇÃO GENÉRICA (Fallback)
# =============================================================================
OIDC_ISSUER_URL=https://seu-provedor.com/auth/realms/SEU_REALM
OIDC_CLIENT_ID=seu-client-id
OIDC_CLIENT_SECRET=seu-client-secret
OIDC_REDIRECT_URI=http://localhost:5400/callback
OIDC_SCOPES=openid profile email

# Configurações adicionais
OIDC_USE_PKCE=true
OIDC_VERIFY_SSL=true
OIDC_TOKEN_LEEWAY=60

# =============================================================================
# KEYCLOAK (TJDFT)
# =============================================================================
KEYCLOAK_ISSUER_URL=https://sso.apps.tjdft.jus.br/auth/realms/SUDES
KEYCLOAK_CLIENT_ID=seu-client-id
KEYCLOAK_CLIENT_SECRET=seu-client-secret
KEYCLOAK_REDIRECT_URI=http://localhost:5400/callback
KEYCLOAK_SCOPES=openid profile email tjdft_profile

# =============================================================================
# GOOGLE OAUTH
# =============================================================================
# Console: https://console.cloud.google.com/apis/credentials
GOOGLE_ISSUER_URL=https://accounts.google.com
GOOGLE_CLIENT_ID=seu-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-seu-secret
GOOGLE_REDIRECT_URI=http://localhost:5400/callback
GOOGLE_SCOPES=openid profile email

# =============================================================================
# GITHUB OAUTH (GRATUITO) - OAuth2 puro, não OIDC
# =============================================================================
# Console: https://github.com/settings/developers
# 1. Acesse GitHub → Settings → Developer settings → OAuth Apps
# 2. Clique em "New OAuth App"
# 3. Configure Authorization callback URL: http://localhost:5400/callback
# NOTA: GitHub usa OAuth2 puro (não OIDC), endpoints são pré-configurados
GITHUB_ISSUER_URL=https://github.com
GITHUB_CLIENT_ID=seu-client-id
GITHUB_CLIENT_SECRET=seu-client-secret
GITHUB_REDIRECT_URI=http://localhost:5400/callback
GITHUB_SCOPES=user:email read:user

# =============================================================================
# MICROSOFT AZURE AD
# =============================================================================
# Portal: https://portal.azure.com/
# MICROSOFT_ISSUER_URL=https://login.microsoftonline.com/common/v2.0
# MICROSOFT_CLIENT_ID=seu-application-id
# MICROSOFT_CLIENT_SECRET=seu-client-secret
# MICROSOFT_REDIRECT_URI=http://localhost:5400/callback
# MICROSOFT_SCOPES=openid profile email User.Read

# =============================================================================
# APPLICATION CONFIGURATION
# =============================================================================
APP_HOST=localhost
APP_PORT=5400
APP_SECRET_KEY=gere-uma-chave-secreta-aleatoria
```

### 3.4 Como Funciona

```python
# Sistema busca nesta ordem:
OIDC_PROVIDER=google

# 1. GOOGLE_ISSUER_URL (específico) ✅
# 2. OIDC_ISSUER_URL (fallback) se não encontrar

# Permite misturar:
GOOGLE_ISSUER_URL=...    # Específico
OIDC_CLIENT_SECRET=...   # Genérico (usado se GOOGLE_CLIENT_SECRET não existir)
```

### 3.5 Uso do Sistema Multi-Provider

```python
from oidc_config import create_oidc_client, get_oidc_config

# 1. Usar provedor ativo do .env (OIDC_PROVIDER)
client = create_oidc_client()

# 2. Forçar provedor específico
client = create_oidc_client('google')
client = create_oidc_client('keycloak')

# 3. Obter configuração apenas
config = get_oidc_config('google')
print(f"Issuer: {config.issuer_url}")
print(f"Client ID: {config.client_id}")

# 4. Listar provedores disponíveis
from oidc_config import list_available_providers
providers = list_available_providers()
# {'keycloak': True, 'google': True, 'github': True, 'microsoft': False, ...}

# 5. Trocar de provedor em runtime
for provider in ['keycloak', 'google', 'github']:
    client = create_oidc_client(provider)
    # ... usar cliente
```

---

## 4. Guia de Uso Rápido

### 4.1 Exemplo Mínimo

```python
from oidc import OIDCClient

# 1. Inicializar cliente (discovery automático)
client = OIDCClient(
    issuer_url="https://keycloak.example.com/realms/myrealm",
    client_id="my-app",
    client_secret="secret",  # Opcional para clientes públicos
    redirect_uri="http://localhost:5400/callback"
)

# 2. Obter URL de autorização
auth_url, state, code_verifier = client.get_authorization_url(
    scope="openid profile email",
    use_pkce=True
)
print(f"Visite: {auth_url}")

# 3. Após autorização, trocar código por token
token = client.handle_authorization_response(
    response_url="http://localhost:5400/callback?code=...",
    expected_state=state,
    code_verifier=code_verifier
)

# 4. Obter informações do usuário
user_info = client.get_user_info(token.access_token)
print(f"Usuário: {user_info.name}")
print(f"Email: {user_info.email}")
```

### 4.2 Client Credentials Flow

```python
from oidc import OIDCClient

# Para autenticação machine-to-machine
client = OIDCClient(
    issuer_url="https://keycloak.example.com/realms/myrealm",
    client_id="service-account",
    client_secret="secret"
)

# Obter token diretamente
token = client.client_credentials_grant(scope="api:read api:write")
print(f"Access Token: {token.access_token}")
print(f"Expira em: {token.expires_in}s")
```

### 4.3 Refresh Token

```python
# Renovar access token expirado
new_token = client.refresh_token(token.refresh_token)
print(f"Novo Access Token: {new_token.access_token}")
```

### 4.4 Validação de Token

```python
# Decodificar e validar JWT
claims = client.decode_token(token.id_token)
print(f"Subject: {claims['sub']}")
print(f"Issuer: {claims['iss']}")
print(f"Expira em: {claims['exp']}")

# Validar com verificação de assinatura (HMAC)
claims = client.validate_token(
    token.access_token,
    verify_signature=True
)
```

### 4.5 Uso Assíncrono

```python
import asyncio
from oidc import OIDCClient

async def main():
    client = OIDCClient(
        issuer_url="https://keycloak.example.com/realms/myrealm",
        client_id="my-app",
        redirect_uri="http://localhost:5400/callback"
    )
    
    # Operações assíncronas
    token = await client.handle_authorization_response_async(
        response_url=callback_url,
        expected_state=state,
        code_verifier=code_verifier
    )
    
    user_info = await client.get_user_info_async(token.access_token)
    print(f"User: {user_info.name}")

asyncio.run(main())
```

---

## 5. Exemplos Práticos

📁 **Todos os exemplos estão disponíveis em:** [`examples/`](examples/)

**Nota:** Alguns exemplos podem requerer dependências adicionais:
- Flask: `pip install flask`
- FastAPI: `pip install fastapi uvicorn`
- Django: `pip install django`
- Django REST Framework: `pip install djangorestframework drf-spectacular`

### 5.1 Aplicação Web Simples

```python
"""Exemplo: Servidor web com callback OAuth"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import webbrowser
from oidc import OIDCClient

# Configuração
CLIENT = OIDCClient(
    issuer_url="https://keycloak.example.com/realms/myrealm",
    client_id="my-app",
    client_secret="secret",
    redirect_uri="http://localhost:5400/callback"
)

auth_data = {'code': None}

class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/callback'):
            auth_data['code'] = f"http://localhost:5400{self.path}"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Autenticacao bem-sucedida!")
    
    def log_message(self, *args):
        pass

def authenticate():
    auth_url, state, verifier = CLIENT.get_authorization_url(
        scope="openid profile email",
        use_pkce=True
    )
    
    webbrowser.open(auth_url)
    
    server = HTTPServer(('localhost', 5400), CallbackHandler)
    print("Aguardando autenticação...")
    server.handle_request()
    
    token = CLIENT.handle_authorization_response(
        response_url=auth_data['code'],
        expected_state=state,
        code_verifier=verifier
    )
    
    user = CLIENT.get_user_info(token.access_token)
    print(f"✅ Autenticado: {user.name} ({user.email})")
    return token, user

if __name__ == "__main__":
    authenticate()
```

### 5.2 Integração Flask

```python
"""Exemplo: Integração com Flask"""
from flask import Flask, redirect, request, session
from oidc import OIDCClient
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

oidc_client = OIDCClient(
    issuer_url="https://keycloak.example.com/realms/myrealm",
    client_id="my-app",
    client_secret="secret",
    redirect_uri="http://localhost:5400/callback"
)

@app.route('/')
def index():
    if 'user' in session:
        return f"Olá, {session['user']['name']}!"
    return '<a href="/login">Entrar</a>'

@app.route('/login')
def login():
    auth_url, state, verifier = oidc_client.get_authorization_url(
        scope="openid profile email",
        use_pkce=True
    )
    session['state'] = state
    session['verifier'] = verifier
    return redirect(auth_url)

@app.route('/callback')
def callback():
    token = oidc_client.handle_authorization_response(
        response_url=request.url,
        expected_state=session.get('state'),
        code_verifier=session.get('verifier')
    )
    
    user_info = oidc_client.get_user_info(token.access_token)
    session['user'] = {'name': user_info.name, 'email': user_info.email}
    return redirect('/')

if __name__ == '__main__':
    app.run(port=5400)
```

### 5.3 Integração com FastAPI

Para FastAPI, use dependências (Depends) para proteger rotas:

```python
"""Exemplo simplificado - veja examples/fastapi_integration.py para versão completa"""
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
from oidc_config import create_oidc_client

app = FastAPI()
security = HTTPBearer()

def get_current_user(credentials = Depends(security)):
    """Dependência para autenticação"""
    token = credentials.credentials
    # Validar token e retornar usuário
    # (veja exemplo completo para implementação detalhada)
    return user_info

@app.get("/api/protected")
def protected_route(user = Depends(get_current_user)):
    return {"message": f"Olá, {user['name']}!"}
```

📖 **Exemplo completo:** [examples/fastapi_integration.py](examples/fastapi_integration.py)

Inclui:
- Fluxo OAuth2 completo (login/callback/logout)
- Middleware de autenticação
- Proteção de rotas com `Depends()`
- Suporte a múltiplos provedores
- Documentação Swagger automática

### 5.4 Multi-Provider com Menu

```python
"""Exemplo: Escolher provedor dinamicamente"""
from oidc_config import list_available_providers, create_oidc_client

def escolher_provedor():
    providers = list_available_providers()
    disponiveis = [name for name, ok in providers.items() if ok]
    
    print("Provedores disponíveis:")
    for i, name in enumerate(disponiveis, 1):
        print(f"  [{i}] {name.title()}")
    
    escolha = int(input("Escolha: ")) - 1
    return disponiveis[escolha]

def autenticar(provedor):
    client = create_oidc_client(provedor)
    
    auth_url, state, verifier = client.get_authorization_url(
        scope="openid profile email",
        use_pkce=True
    )
    
    print(f"Visite: {auth_url}")
    callback = input("Cole a URL de callback: ")
    
    token = client.handle_authorization_response(
        response_url=callback,
        expected_state=state,
        code_verifier=verifier
    )
    
    user = client.get_user_info(token.access_token)
    print(f"✅ {provedor.upper()}: {user.name}")
    return token, user

provedor = escolher_provedor()
token, user = autenticar(provedor)
```

### 5.5 Integração com Django 4.x/5.x

A biblioteca pode ser integrada ao Django puro usando middleware, backends de autenticação customizados e decorators. **Ideal para aplicações web tradicionais com templates e sessões.**

```python
# settings.py
OIDC_ISSUER_URL = os.getenv('OIDC_ISSUER_URL')
OIDC_CLIENT_ID = os.getenv('OIDC_CLIENT_ID')
OIDC_CLIENT_SECRET = os.getenv('OIDC_CLIENT_SECRET')
OIDC_REDIRECT_URI = 'http://localhost:8000/auth/callback'

AUTHENTICATION_BACKENDS = [
    'myapp.backends.OIDCAuthenticationBackend',  # Autenticação OIDC
    'django.contrib.auth.backends.ModelBackend',  # Admin padrão
]

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'myapp.middleware.OIDCAuthenticationMiddleware',  # OIDC middleware
    # ... outros middlewares
]

# views.py
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from oidc import OIDCClient

oidc_client = OIDCClient(
    issuer_url=settings.OIDC_ISSUER_URL,
    client_id=settings.OIDC_CLIENT_ID,
    client_secret=settings.OIDC_CLIENT_SECRET,
    redirect_uri=settings.OIDC_REDIRECT_URI
)

def oidc_login(request):
    """Inicia fluxo OAuth2"""
    state = secrets.token_urlsafe(32)
    request.session['oidc_state'] = state
    auth_url = oidc_client.get_authorization_url(state=state)
    return redirect(auth_url)

def oidc_callback(request):
    """Processa callback OAuth2"""
    code = request.GET.get('code')
    state = request.GET.get('state')
    
    # Validar state
    if state != request.session.get('oidc_state'):
        return JsonResponse({'error': 'Invalid state'}, status=400)
    
    # Trocar code por tokens
    token_response = oidc_client.exchange_code_for_tokens(code)
    userinfo = oidc_client.get_userinfo(token_response.access_token)
    
    # Autenticar via backend customizado
    user = authenticate(
        request=request,
        access_token=token_response.access_token,
        userinfo=userinfo.to_dict()
    )
    
    if user:
        login(request, user)
        request.session['oidc_access_token'] = token_response.access_token
        return redirect('/')
    
    return JsonResponse({'error': 'Authentication failed'}, status=401)

@login_required
def protected_view(request):
    """View protegida"""
    return JsonResponse({
        'message': 'Autenticado!',
        'user': request.user.username
    })
```

**Recursos implementados:**
- ✅ Backend de autenticação customizado (`OIDCAuthenticationBackend`)
- ✅ Middleware para validação de tokens em cada requisição
- ✅ Integração com sistema de sessões Django
- ✅ Decorator `@oidc_login_required` para views protegidas
- ✅ Suporte a múltiplos providers (Keycloak, Google, GitHub)

📄 **Exemplo completo:** [`examples/django_integration.py`](examples/django_integration.py) (500+ linhas com middleware, backends, views, models e configurações)

### 5.6 Integração com Django REST Framework (DRF)

Para APIs REST, a integração é feita através de **Authentication Classes** e **Permission Classes**, permitindo autenticação via Bearer token. **Recomendado para SPAs, mobile apps e microservices.**

```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'api.authentication.OIDCAuthentication',  # Autenticação customizada
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

# api/authentication.py
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from oidc import OIDCClient

class OIDCAuthentication(BaseAuthentication):
    """
    Autenticação via Bearer token OIDC.
    Header: Authorization: Bearer <access_token>
    """
    
    def __init__(self):
        self.oidc_client = OIDCClient(
            issuer_url=settings.OIDC_ISSUER_URL,
            client_id=settings.OIDC_CLIENT_ID,
            client_secret=settings.OIDC_CLIENT_SECRET,
            redirect_uri=settings.OIDC_REDIRECT_URI
        )
    
    def authenticate(self, request):
        """Valida token e retorna (user, token)"""
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            return None
        
        access_token = auth_header[7:]
        
        try:
            # Validar token e obter userinfo
            userinfo = self.oidc_client.get_userinfo(access_token)
            
            # Buscar ou criar usuário
            user, created = User.objects.get_or_create(
                username=userinfo.sub,
                defaults={
                    'email': userinfo.email or '',
                    'first_name': getattr(userinfo, 'given_name', '')[:30],
                }
            )
            
            return (user, access_token)
            
        except Exception as e:
            raise AuthenticationFailed('Token inválido ou expirado')

# api/views.py
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from .authentication import OIDCAuthentication

class AuthViewSet(viewsets.ViewSet):
    """ViewSet para autenticação OIDC"""
    
    @action(detail=False, methods=['get'], permission_classes=[AllowAny])
    def login(self, request):
        """GET /api/auth/login - Retorna URL de autorização"""
        state = secrets.token_urlsafe(32)
        auth_url = oidc_client.get_authorization_url(state=state)
        return Response({
            'authorization_url': auth_url,
            'state': state
        })
    
    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def token(self, request):
        """POST /api/auth/token - Troca code por tokens"""
        code = request.data.get('code')
        token_response = oidc_client.exchange_code_for_tokens(code)
        
        return Response({
            'access_token': token_response.access_token,
            'refresh_token': token_response.refresh_token,
            'expires_in': token_response.expires_in,
        })
    
    @action(detail=False, methods=['get'],
            authentication_classes=[OIDCAuthentication],
            permission_classes=[IsAuthenticated])
    def userinfo(self, request):
        """GET /api/auth/userinfo - Dados do usuário autenticado"""
        access_token = request.auth
        userinfo = oidc_client.get_userinfo(access_token)
        return Response(userinfo.__dict__)

# urls.py
from rest_framework.routers import DefaultRouter
from api.views import AuthViewSet

router = DefaultRouter()
router.register(r'auth', AuthViewSet, basename='auth')

urlpatterns = [
    path('api/', include(router.urls)),
]
```

**Recursos implementados:**
- ✅ `OIDCAuthentication` class para validação automática de tokens
- ✅ Integração com permissões DRF (`IsAuthenticated`, custom permissions)
- ✅ ViewSets para endpoints de autenticação (`/api/auth/login`, `/api/auth/token`)
- ✅ Suporte a refresh token (`/api/auth/refresh`)
- ✅ Cache de userinfo para performance
- ✅ Documentação OpenAPI/Swagger com `drf-spectacular`

📄 **Exemplo completo:** [`examples/django_drf_integration.py`](examples/django_drf_integration.py) (700+ linhas com authentication classes, permissions, serializers, ViewSets e testes)

**Diferenças entre Django puro vs. DRF:**

| Aspecto | Django Puro | Django REST Framework |
|---------|-------------|----------------------|
| **Caso de uso** | Apps web tradicionais | APIs REST (SPA, Mobile) |
| **Autenticação** | Sessões Django | Bearer tokens (stateless) |
| **Implementação** | Middleware + Backends | Authentication Classes |
| **Views** | Function/Class views | ViewSets + APIViews |
| **Frontend** | Templates Django | React/Vue/Angular |
| **Sessões** | Server-side sessions | Stateless (JWT) |
| **Complexidade** | Média | Baixa (mais direto) |

💡 **Recomendação:** Use **Django puro** para aplicações monolíticas com templates. Use **DRF** para APIs consumidas por SPAs ou apps mobile.

---

## 6. Arquitetura

### 6.1 Visão Geral

```
┌─────────────────────────────────────────────────────┐
│                   OIDCClient                        │
│  (Interface de alto nível para aplicações)          │
└────────────┬────────────────────────────────────────┘
             │
             ├──────────┐
             │          │
    ┌────────▼─────┐   ┌▼───────────────┐
    │ OAuth2Flow   │   │ TokenValidator │
    │ (RFC 6749)   │   │ (JWT)          │
    └────────┬─────┘   └────────────────┘
             │
             │
    ┌────────▼──────────┐
    │  OIDCDiscovery    │
    │  (.well-known)    │
    └───────────────────┘
             │
        ┌────▼────┐
        │  httpx  │
        └─────────┘
```

#### 6.1.1 Separação Modular

A biblioteca é dividida em:

**📦 Core (Obrigatório)** - `oidc/`
- Implementação pura OAuth2/OIDC
- Sem dependências de configuração externa
- Pode ser usado diretamente em produção

**🔧 Helpers (Opcional)** - `oidc_config.py`
- Facilita uso multi-provider
- Lê configurações do `.env`
- Útil para desenvolvimento e testes
- **Pode ser removido** em produção se não for necessário

```python
# Produção: Uso direto (sem oidc_config.py)
from oidc import OIDCClient
client = OIDCClient(issuer_url="...", client_id="...", ...)

# Desenvolvimento: Com helper multi-provider
from oidc_config import create_oidc_client
client = create_oidc_client('google')
```

### 6.2 Componentes

#### **OIDCClient** (`client.py`)
Interface principal para aplicações.

**Métodos:**
- `get_authorization_url()`: Gera URL de autorização
- `handle_authorization_response()`: Troca código por token
- `get_user_info()`: Obtém perfil do usuário
- `refresh_token()`: Renova token
- `validate_token()`: Valida JWT
- `client_credentials_grant()`: Fluxo M2M

#### **OAuth2Flow** (`oauth2.py`)
Implementação dos fluxos OAuth2 (RFC 6749).

**Fluxos:**
- Authorization Code
- Authorization Code + PKCE
- Client Credentials
- Refresh Token

#### **OIDCDiscovery** (`discovery.py`)
Descoberta automática de endpoints.

```python
# GET {issuer}/.well-known/openid-configuration
config = discovery.get_configuration()
```

#### **TokenValidator** (`tokens.py`)
Validação e manipulação de JWT.

**Funcionalidades:**
- Decode base64url
- Validação de claims
- Verificação HMAC
- Geração PKCE

### 6.3 Fluxo de Autenticação

```
App → OIDCClient → Discovery → Keycloak
                → OAuth2Flow
                → TokenValidator
```

---

## 7. Configuração Keycloak

### 7.1 Criar Realm

1. Acesse console Keycloak
2. **Create Realm** → Nome: `myrealm`
3. **Save**

### 7.2 Criar Cliente

1. **Clients** → **Create client**
2. **Client ID**: `my-app`
3. **Configure**:
   - Client authentication: ON
   - Standard flow: ✅
   - Redirect URIs: `http://localhost:5400/callback`
4. **Copiar Client Secret** (tab Credentials)

### 7.3 Criar Usuário

1. **Users** → **Add user**
2. Configure username, email
3. **Credentials** → Set password

### 7.4 Configurar PKCE

1. Cliente → **Settings** → **Advanced**
2. **Proof Key**: S256
3. **Save**

### 7.5 URLs

```python
ISSUER_URL = "https://keycloak.example.com/realms/myrealm"
```

Endpoints descobertos automaticamente:
- Authorization: `/protocol/openid-connect/auth`
- Token: `/protocol/openid-connect/token`
- Userinfo: `/protocol/openid-connect/userinfo`

### 7.6 Client Credentials (M2M)

1. Novo cliente
2. Configure:
   - Client authentication: ON
   - **Service accounts roles**: ON
   - Standard flow: OFF

```python
client = OIDCClient(
    issuer_url="...",
    client_id="service-account",
    client_secret="secret"
)
token = client.client_credentials_grant()
```

---

## 8. Testes

### 8.1 Status

```
📈 Cobertura: 78%
✅ Passando: 74/82 (90%)
📦 Novos: +26 (multi-provider)
```

### 8.2 Executar

```bash
# Todos os testes
uv run pytest

# Com cobertura
uv run pytest --cov=oidc --cov-report=term-missing

# HTML report
uv run pytest --cov=oidc --cov-report=html

# Específicos
uv run pytest tests/test_multi_provider.py -v
```

### 8.3 Cobertura por Módulo

```
Módulo                Cobertura
─────────────────────────────────
oidc/__init__.py      100%
oidc/exceptions.py    100%
oidc/models.py         92%
oidc/tokens.py         87%
oidc/oauth2.py         72%
oidc/client.py         67%
oidc/discovery.py      66%
─────────────────────────────────
TOTAL                  78%
```

---

## 9. Referência da API

### 9.1 OIDCClient

```python
client = OIDCClient(
    issuer_url: str,
    client_id: str,
    client_secret: str | None = None,
    redirect_uri: str | None = None,
    scopes: str | list[str] = None,
    use_pkce: bool = True,
    verify_ssl: bool = True,
)

# Authorization
auth_url, state, verifier = client.get_authorization_url(
    scope: str | list[str] | None = None,
    use_pkce: bool = True,
)

# Token exchange
token = client.handle_authorization_response(
    response_url: str,
    expected_state: str,
    code_verifier: str | None = None,
)

# User info
user_info = client.get_user_info(access_token: str)

# Refresh
new_token = client.refresh_token(refresh_token: str)

# Validation
claims = client.decode_token(token: str)
claims = client.validate_token(token: str, verify_signature: bool = True)
```

### 9.2 Multi-Provider

```python
from oidc_config import (
    get_oidc_config,
    create_oidc_client,
    list_available_providers,
)

# Get config
config = get_oidc_config(provider: str | None = None)

# Create client
client = create_oidc_client(provider: str | None = None)

# List providers
providers = list_available_providers()
# {'keycloak': True, 'google': True, 'github': True, 'microsoft': False, ...}
```

---

## 10. Auditoria de Segurança

### 10.1 Verificação de Vulnerabilidades (CVEs)

O projeto inclui um script automatizado de auditoria de segurança que verifica:
- ✅ **Vulnerabilidades conhecidas** (CVEs) em dependências
- ✅ **Análise estática** de código (SAST) 
- ✅ **Boas práticas** de segurança

```bash
# Executar auditoria completa
./security_audit.sh

# Instalar ferramentas (primeira vez)
./security_audit.sh --install

# Análise completa com verificações extras
./security_audit.sh --full

# Modo CI/CD (falha se encontrar problemas)
./security_audit.sh --ci
```

### 10.2 Ferramentas Utilizadas

| Ferramenta | Descrição | Database |
|------------|-----------|----------|
| **pip-audit** | Verifica CVEs em dependências | PyPI Advisory Database |
| **safety** | Vulnerabilidades conhecidas | PyUp.io Safety DB |
| **bandit** | Análise estática de código (SAST) | Python security patterns |

### 10.3 Status Atual

**Última auditoria:** 2026-02-24

```
✅ Dependências diretas:      0 vulnerabilidades
✅ Dependências de teste:     0 vulnerabilidades
✅ Análise de código (SAST):  0 problemas
✅ Total de linhas auditadas: 1226
```

**Resultado:** ✅ **APROVADO**

### 10.4 Ambiente de Desenvolvimento

O projeto utiliza:
- **uv** - Gerenciador de pacotes Python rápido e moderno
- **devcontainer** - Ambiente de desenvolvimento isolado e reprodutível
- **pytest** - Framework de testes com 78% de cobertura

Todas as ferramentas de segurança são executadas dentro do ambiente virtual gerenciado pelo `uv`.

### 10.5 Relatório Completo

📄 Para relatório detalhado de segurança, veja: **[SECURITY.md](SECURITY.md)**

O relatório inclui:
- Status detalhado de cada dependência
- Práticas de segurança implementadas
- Recomendações para produção
- Processo de resposta a vulnerabilidades
- Como reportar problemas de segurança

### 10.6 CI/CD Integration

Para integrar a auditoria no seu pipeline:

```yaml
# .github/workflows/security.yml
name: Security Audit

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install uv
        run: curl -LsSf https://astral.sh/uv/install.sh | sh
      - name: Run Security Audit
        run: ./security_audit.sh --ci
```

---

## 11. Segurança

### 10.1 Best Practices

#### 1. Sempre Use PKCE
```python
client.get_authorization_url(use_pkce=True)  # ✅
```

#### 2. Valide State (CSRF)
```python
token = client.handle_authorization_response(
    response_url=callback,
    expected_state=session['state'],  # ✅
    code_verifier=verifier
)
```

#### 3. Nunca Exponha Credenciais
```python
# ❌ ERRADO
client_secret="abc123"

# ✅ CORRETO
from oidc_config import create_oidc_client
client = create_oidc_client()  # Lê do .env
```

#### 4. Valide Tokens
```python
claims = client.decode_token(token)
assert claims['iss'] == expected_issuer
assert claims['exp'] > time.time()
```

#### 5. Use HTTPS em Produção
```python
# Dev: http://localhost:5400
# Prod: https://meuapp.com/callback ✅
```

### 10.2 Gerenciamento de Tokens

```python
# ❌ ERRADO: localStorage
localStorage.setItem('token', token)

# ✅ CORRETO: Cookies HTTP-only
response.set_cookie(
    'access_token',
    value=token.access_token,
    httponly=True,  # Previne XSS
    secure=True,    # HTTPS only
    samesite='Lax'
)
```

### 10.3 Checklist

```
□ PKCE habilitado
□ State validation
□ .env não versionado
□ HTTPS em produção
□ Cookies HTTP-only
□ Token lifespan curto
□ Refresh token rotation
□ MFA habilitado
□ Logs de auditoria
```

---

## 📚 Recursos

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [Keycloak Docs](https://www.keycloak.org/documentation)

---

## 📄 Licença

MIT License - veja [LICENSE](LICENSE).

---

## 🏆 Status

```
✅ Core OAuth2/OIDC: Completo
✅ Multi-Provider: Completo
✅ Keycloak: Testado
✅ Google OAuth: Testado
✅ GitHub OAuth: Testado
✅ Documentação: Completa
✅ Testes: 78% cobertura
```

**Pronto para produção com Keycloak, Google OAuth e GitHub OAuth.**
