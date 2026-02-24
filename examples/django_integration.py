#!/usr/bin/env python3
"""
🔐 Exemplo: Integração da biblioteca OIDC com Django 4.x/5.x
============================================================

Este exemplo demonstra como integrar autenticação OAuth2/OIDC em um projeto Django puro
(sem Django REST Framework).

Recursos:
- Login via OAuth2 (Keycloak, Google, GitHub, etc.)
- Middleware para autenticação por token
- Decorators para proteger views
- Backend de autenticação customizado
- Sistema de sessões integrado

Compatibilidade:
- Django 4.2+
- Django 5.0+

Instalação:
    pip install django>=4.2

Estrutura do Projeto Django:
    myproject/
    ├── settings.py       # Configuração
    ├── urls.py           # Rotas principais
    ├── views.py          # Views de autenticação
    └── middleware.py     # Middleware OIDC

Configuração:
    Adicione ao settings.py as variáveis de ambiente para sua aplicação

Uso:
    # 1. Configure suas variáveis OIDC no settings.py
    # 2. Adicione as URLs ao urls.py
    # 3. Adicione o middleware ao MIDDLEWARE
    # 4. Use @oidc_login_required nas views que precisam autenticação
"""

# =============================================================================
# 1. CONFIGURAÇÃO (settings.py)
# =============================================================================

"""
# myproject/settings.py

import os
from pathlib import Path

# OIDC Configuration
OIDC_PROVIDER = os.getenv('OIDC_PROVIDER', 'keycloak')  # keycloak, google, github
OIDC_ISSUER_URL = os.getenv('OIDC_ISSUER_URL')
OIDC_CLIENT_ID = os.getenv('OIDC_CLIENT_ID')
OIDC_CLIENT_SECRET = os.getenv('OIDC_CLIENT_SECRET')
OIDC_REDIRECT_URI = os.getenv('OIDC_REDIRECT_URI', 'http://localhost:8000/auth/callback')
OIDC_SCOPES = os.getenv('OIDC_SCOPES', 'openid email profile').split()

# Session Configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.db'  # ou 'cache' para Redis
SESSION_COOKIE_AGE = 3600  # 1 hora
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True  # Em produção com HTTPS
SESSION_COOKIE_SAMESITE = 'Lax'

# Middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'myapp.middleware.OIDCAuthenticationMiddleware',  # <-- Adicionar
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Authentication Backends
AUTHENTICATION_BACKENDS = [
    'myapp.backends.OIDCAuthenticationBackend',  # <-- Adicionar
    'django.contrib.auth.backends.ModelBackend',  # Manter para admin
]
"""

# =============================================================================
# 2. BACKEND DE AUTENTICAÇÃO (backends.py)
# =============================================================================

"""
# myapp/backends.py
"""

import logging

from django.conf import settings
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User

from oidc_pure import OIDCClient

logger = logging.getLogger(__name__)


class OIDCAuthenticationBackend(BaseBackend):
    """
    Backend de autenticação que valida tokens OIDC e cria/atualiza usuários Django.
    """

    def authenticate(self, request, access_token=None, id_token=None, userinfo=None):
        """
        Autentica usuário via OIDC token.

        Args:
            request: HttpRequest
            access_token: Access token do OIDC
            id_token: ID token do OIDC (opcional)
            userinfo: Dados do usuário do OIDC

        Returns:
            User instance ou None
        """
        if not access_token or not userinfo:
            return None

        try:
            # Extrair identificador único do usuário
            sub = userinfo.get("sub")
            email = userinfo.get("email")

            if not sub:
                logger.error("UserInfo sem 'sub'")
                return None

            # Buscar ou criar usuário
            user, created = User.objects.get_or_create(
                username=sub,
                defaults={
                    "email": email or "",
                    "first_name": userinfo.get("given_name", "")[:30],
                    "last_name": userinfo.get("family_name", "")[:30],
                },
            )

            # Atualizar informações do usuário
            if not created:
                user.email = email or user.email
                user.first_name = userinfo.get("given_name", user.first_name)[:30]
                user.last_name = userinfo.get("family_name", user.last_name)[:30]
                user.save()

            logger.info(f"Usuário {'criado' if created else 'autenticado'}: {user.username}")
            return user

        except Exception as e:
            logger.error(f"Erro ao autenticar usuário OIDC: {e}")
            return None

    def get_user(self, user_id):
        """
        Recupera usuário pelo ID.
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


# =============================================================================
# 3. MIDDLEWARE (middleware.py)
# =============================================================================

"""
# myapp/middleware.py
"""

import logging

from django.contrib.auth import authenticate, login
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class OIDCAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware que valida tokens OIDC em cada requisição.

    Suporta autenticação via:
    - Header Authorization: Bearer <token>
    - Session storage
    """

    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response

        # Inicializar cliente OIDC
        self.oidc_client = None
        if all([settings.OIDC_ISSUER_URL, settings.OIDC_CLIENT_ID, settings.OIDC_CLIENT_SECRET]):
            try:
                self.oidc_client = OIDCClient(
                    issuer_url=settings.OIDC_ISSUER_URL,
                    client_id=settings.OIDC_CLIENT_ID,
                    client_secret=settings.OIDC_CLIENT_SECRET,
                    redirect_uri=settings.OIDC_REDIRECT_URI,
                    scopes=settings.OIDC_SCOPES,
                )
                logger.info("OIDC Client inicializado com sucesso")
            except Exception as e:
                logger.error(f"Erro ao inicializar OIDC Client: {e}")

    def process_request(self, request):
        """
        Processa requisição para autenticar usuário via OIDC.
        """
        # Skip se usuário já está autenticado
        if request.user.is_authenticated:
            return None

        # Skip se OIDC não está configurado
        if not self.oidc_client:
            return None

        # Tentar autenticação via Authorization header
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if auth_header.startswith("Bearer "):
            access_token = auth_header[7:]
            self._authenticate_with_token(request, access_token)
            return None

        # Tentar autenticação via session
        access_token = request.session.get("oidc_access_token")
        if access_token:
            self._authenticate_with_token(request, access_token)

        return None

    def _authenticate_with_token(self, request, access_token):
        """
        Autentica usuário com access token.
        """
        try:
            # Validar token e obter userinfo
            userinfo = self.oidc_client.get_userinfo(access_token)

            # Autenticar via backend
            user = authenticate(
                request=request, access_token=access_token, userinfo=userinfo.to_dict()
            )

            if user:
                login(request, user, backend="myapp.backends.OIDCAuthenticationBackend")
                logger.info(f"Usuário autenticado via middleware: {user.username}")

        except Exception as e:
            logger.debug(f"Token inválido ou expirado: {e}")
            # Limpar sessão
            request.session.pop("oidc_access_token", None)
            request.session.pop("oidc_refresh_token", None)


# =============================================================================
# 4. VIEWS (views.py)
# =============================================================================

"""
# myapp/views.py
"""

import logging
import secrets
from functools import wraps

from django.contrib.auth import logout
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from oidc_pure.exceptions import OIDCException

logger = logging.getLogger(__name__)

# Inicializar cliente OIDC
oidc_client = OIDCClient(
    issuer_url=settings.OIDC_ISSUER_URL,
    client_id=settings.OIDC_CLIENT_ID,
    client_secret=settings.OIDC_CLIENT_SECRET,
    redirect_uri=settings.OIDC_REDIRECT_URI,
    scopes=settings.OIDC_SCOPES,
)


# Decorator customizado para rotas que requerem OIDC
def oidc_login_required(view_func):
    """
    Decorator que exige autenticação OIDC.
    Redireciona para login se não autenticado.
    """

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("oidc_login")
        return view_func(request, *args, **kwargs)

    return wrapper


@require_http_methods(["GET"])
def oidc_login(request):
    """
    Inicia fluxo de autenticação OIDC.

    GET /auth/login
    """
    # Gerar state para CSRF protection
    state = secrets.token_urlsafe(32)
    request.session["oidc_state"] = state

    # Gerar URL de autorização
    auth_url = oidc_client.get_authorization_url(state=state)

    logger.info("Redirecionando para autorização OIDC")
    return redirect(auth_url)


@csrf_exempt
@require_http_methods(["GET"])
def oidc_callback(request):
    """
    Callback do provider OIDC após autenticação.

    GET /auth/callback?code=...&state=...
    """
    # Validar state
    state = request.GET.get("state")
    expected_state = request.session.get("oidc_state")

    if not state or state != expected_state:
        logger.error("State inválido ou ausente")
        return JsonResponse({"error": "Invalid state"}, status=400)

    # Obter authorization code
    code = request.GET.get("code")
    if not code:
        error = request.GET.get("error", "unknown_error")
        error_description = request.GET.get("error_description", "")
        logger.error(f"Erro no callback: {error} - {error_description}")
        return JsonResponse({"error": error, "error_description": error_description}, status=400)

    try:
        # Trocar code por tokens
        token_response = oidc_client.exchange_code_for_tokens(code)

        # Obter informações do usuário
        userinfo = oidc_client.get_userinfo(token_response.access_token)

        # Autenticar usuário via backend
        user = authenticate(
            request=request,
            access_token=token_response.access_token,
            id_token=token_response.id_token,
            userinfo=userinfo.to_dict(),
        )

        if user:
            # Fazer login
            login(request, user, backend="myapp.backends.OIDCAuthenticationBackend")

            # Armazenar tokens na sessão
            request.session["oidc_access_token"] = token_response.access_token
            if token_response.refresh_token:
                request.session["oidc_refresh_token"] = token_response.refresh_token

            logger.info(f"Login bem-sucedido: {user.username}")

            # Redirecionar para página protegida ou home
            next_url = request.session.pop("next_url", "/")
            return redirect(next_url)
        else:
            logger.error("Falha ao autenticar usuário")
            return JsonResponse({"error": "Authentication failed"}, status=401)

    except OIDCException as e:
        logger.error(f"Erro OIDC: {e}")
        return JsonResponse({"error": str(e)}, status=500)
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
        return JsonResponse({"error": "Internal server error"}, status=500)


@require_http_methods(["GET", "POST"])
def oidc_logout(request):
    """
    Logout do usuário (session Django + provider OIDC).

    GET/POST /auth/logout
    """
    # Limpar sessão Django
    logout(request)
    request.session.flush()

    logger.info("Logout realizado")

    # Redirecionar para home ou logout do provider
    return redirect("/")


@oidc_login_required
@require_http_methods(["GET"])
def protected_view(request):
    """
    Exemplo de view protegida que requer autenticação OIDC.

    GET /protected
    """
    return JsonResponse(
        {
            "message": "Você está autenticado!",
            "user": {
                "id": request.user.id,
                "username": request.user.username,
                "email": request.user.email,
                "first_name": request.user.first_name,
                "last_name": request.user.last_name,
            },
        }
    )


@oidc_login_required
@require_http_methods(["GET"])
def user_profile(request):
    """
    Retorna informações do perfil do usuário autenticado.

    GET /auth/me
    """
    return JsonResponse(
        {
            "id": request.user.id,
            "username": request.user.username,
            "email": request.user.email,
            "first_name": request.user.first_name,
            "last_name": request.user.last_name,
            "is_active": request.user.is_active,
            "is_staff": request.user.is_staff,
            "date_joined": request.user.date_joined.isoformat(),
        }
    )


# =============================================================================
# 5. URLS (urls.py)
# =============================================================================

"""
# myproject/urls.py

from django.contrib import admin
from django.urls import path
from myapp import views

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Rotas OIDC
    path('auth/login', views.oidc_login, name='oidc_login'),
    path('auth/callback', views.oidc_callback, name='oidc_callback'),
    path('auth/logout', views.oidc_logout, name='oidc_logout'),
    path('auth/me', views.user_profile, name='user_profile'),
    
    # Rotas protegidas (exemplo)
    path('protected', views.protected_view, name='protected'),
    path('', views.home, name='home'),  # Sua página inicial
]
"""

# =============================================================================
# 6. MODELOS (models.py - OPCIONAL)
# =============================================================================

"""
# myapp/models.py

# Se você quiser estender o modelo User com informações adicionais do OIDC:

from django.db import models
from django.contrib.auth.models import User

class OIDCUserProfile(models.Model):
    '''
    Perfil estendido para armazenar informações adicionais do OIDC.
    '''
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='oidc_profile')
    sub = models.CharField(max_length=255, unique=True)  # Subject do OIDC
    provider = models.CharField(max_length=50)  # keycloak, google, github
    access_token = models.TextField(blank=True)
    refresh_token = models.TextField(blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)
    last_login = models.DateTimeField(auto_now=True)
    extra_data = models.JSONField(default=dict, blank=True)  # Claims adicionais
    
    class Meta:
        db_table = 'oidc_user_profile'
        verbose_name = 'OIDC User Profile'
        verbose_name_plural = 'OIDC User Profiles'
    
    def __str__(self):
        return f"{self.user.username} ({self.provider})"
"""

# =============================================================================
# 7. EXEMPLO DE USO COMPLETO
# =============================================================================

"""
# Configurar projeto Django:

1. Criar projeto:
   django-admin startproject myproject
   cd myproject
   python manage.py startapp myapp

2. Configurar settings.py:
   - Adicionar variáveis OIDC
   - Adicionar middleware
   - Adicionar authentication backend

3. Criar arquivos:
   - myapp/backends.py
   - myapp/middleware.py
   - myapp/views.py

4. Configurar urls.py

5. Migrations:
   python manage.py makemigrations
   python manage.py migrate

6. Criar superuser (para admin):
   python manage.py createsuperuser

7. Rodar servidor:
   python manage.py runserver

8. Testar:
   - http://localhost:8000/auth/login (inicia login OIDC)
   - http://localhost:8000/protected (view protegida)
   - http://localhost:8000/auth/me (perfil do usuário)
   - http://localhost:8000/auth/logout (logout)
"""

# =============================================================================
# 8. CONSIDERAÇÕES DE PRODUÇÃO
# =============================================================================

"""
# Segurança:

1. Use HTTPS em produção:
   - SESSION_COOKIE_SECURE = True
   - CSRF_COOKIE_SECURE = True

2. Configure CORS corretamente:
   pip install django-cors-headers
   
3. Use cache/Redis para sessões:
   SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
   CACHES = {
       'default': {
           'BACKEND': 'django_redis.cache.RedisCache',
           'LOCATION': 'redis://127.0.0.1:6379/1',
       }
   }

4. Configure refresh token automático:
   - Implementar lógica para renovar tokens antes de expirar
   - Usar celery para tarefas assíncronas

5. Logging e monitoramento:
   - Configure logging adequado
   - Monitore falhas de autenticação
   - Alerte sobre tokens expirados

# Performance:

1. Cache de configurações OIDC:
   - Cachear discovery document
   - Cachear JWKS

2. Connection pooling:
   - Configure httpx com connection pooling

3. Async views (Django 4.1+):
   - Use views assíncronas quando possível
   - Beneficia-se de async OIDC client
"""

if __name__ == "__main__":
    print(__doc__)
    print("\n" + "=" * 70)
    print("📋 Checklist de Integração Django:")
    print("=" * 70)
    print("✓ 1. Configurar settings.py com variáveis OIDC")
    print("✓ 2. Adicionar OIDCAuthenticationBackend em AUTHENTICATION_BACKENDS")
    print("✓ 3. Adicionar OIDCAuthenticationMiddleware em MIDDLEWARE")
    print("✓ 4. Criar backends.py com OIDCAuthenticationBackend")
    print("✓ 5. Criar middleware.py com OIDCAuthenticationMiddleware")
    print("✓ 6. Criar views.py com login/callback/logout")
    print("✓ 7. Configurar urls.py com rotas de autenticação")
    print("✓ 8. Rodar migrations")
    print("✓ 9. Testar fluxo completo de autenticação")
    print("=" * 70)
