#!/usr/bin/env python3
"""
🚀 Exemplo: Integração da biblioteca OIDC com Django REST Framework (DRF)
==========================================================================

Este exemplo demonstra como integrar autenticação OAuth2/OIDC em uma API REST
usando Django REST Framework.

Recursos:
- Authentication class customizada para OIDC
- Permission classes
- Token authentication via Bearer header
- ViewSets protegidos
- Refresh token automático
- Integração com drf-spectacular (OpenAPI/Swagger)

Compatibilidade:
- Django 4.2+
- Django 5.0+
- Django REST Framework 3.14+

Instalação:
    pip install djangorestframework>=3.14
    pip install drf-spectacular  # Para documentação OpenAPI

Estrutura do Projeto:
    myproject/
    ├── settings.py           # Configuração Django + DRF
    ├── urls.py               # Rotas principais
    └── api/
        ├── authentication.py # Authentication classes
        ├── permissions.py    # Permission classes
        ├── views.py          # ViewSets e APIViews
        └── serializers.py    # Serializers

Uso:
    # 1. Configure settings.py
    # 2. Use OIDCAuthentication nas views
    # 3. Acesse API com header: Authorization: Bearer <token>
"""

# =============================================================================
# 1. CONFIGURAÇÃO (settings.py)
# =============================================================================

"""
# myproject/settings.py

import os

# Django REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'api.authentication.OIDCAuthentication',  # <-- Authentication customizada
        'rest_framework.authentication.SessionAuthentication',  # Para browsable API
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'EXCEPTION_HANDLER': 'api.exceptions.custom_exception_handler',

    # OpenAPI/Swagger (drf-spectacular)
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# drf-spectacular configuration
SPECTACULAR_SETTINGS = {
    'TITLE': 'API com OIDC',
    'DESCRIPTION': 'API REST protegida com OAuth2/OIDC',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'SECURITY': [{
        'BearerAuth': {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': 'JWT',
        }
    }],
}

# OIDC Configuration
OIDC_PROVIDER = os.getenv('OIDC_PROVIDER', 'keycloak')
OIDC_ISSUER_URL = os.getenv('OIDC_ISSUER_URL')
OIDC_CLIENT_ID = os.getenv('OIDC_CLIENT_ID')
OIDC_CLIENT_SECRET = os.getenv('OIDC_CLIENT_SECRET')
OIDC_REDIRECT_URI = os.getenv('OIDC_REDIRECT_URI', 'http://localhost:8000/api/auth/callback')
OIDC_SCOPES = os.getenv('OIDC_SCOPES', 'openid email profile').split()

# Token cache (opcional, para performance)
OIDC_CACHE_TIMEOUT = 300  # 5 minutos
"""

# =============================================================================
# 2. AUTHENTICATION CLASS (authentication.py)
# =============================================================================

"""
# api/authentication.py
"""

import logging

from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from oidc_pure import OIDCClient
from oidc_pure.exceptions import TokenError, ValidationError

logger = logging.getLogger(__name__)


class OIDCAuthentication(BaseAuthentication):
    """
    Authentication class que valida tokens OIDC via Bearer header.

    Usage:
        @authentication_classes([OIDCAuthentication])
        class MyViewSet(viewsets.ModelViewSet):
            ...

    Header:
        Authorization: Bearer <access_token>
    """

    keyword = "Bearer"

    def __init__(self):
        super().__init__()
        self.oidc_client = self._get_oidc_client()

    def _get_oidc_client(self):
        """Inicializa e retorna cliente OIDC."""
        if not all(
            [settings.OIDC_ISSUER_URL, settings.OIDC_CLIENT_ID, settings.OIDC_CLIENT_SECRET]
        ):
            logger.error("Configuração OIDC incompleta")
            return None

        try:
            return OIDCClient(
                issuer_url=settings.OIDC_ISSUER_URL,
                client_id=settings.OIDC_CLIENT_ID,
                client_secret=settings.OIDC_CLIENT_SECRET,
                redirect_uri=settings.OIDC_REDIRECT_URI,
                scopes=settings.OIDC_SCOPES,
            )
        except Exception as e:
            logger.error(f"Erro ao inicializar OIDC Client: {e}")
            return None

    def authenticate(self, request):
        """
        Autentica requisição via OIDC token.

        Returns:
            (user, token) tuple ou None
        """
        if not self.oidc_client:
            return None

        # Extrair token do header
        auth_header = self.get_authorization_header(request)
        if not auth_header:
            return None

        # Validar formato
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != self.keyword.lower().encode():
            return None

        access_token = parts[1].decode("utf-8")

        # Verificar cache (performance)
        cache_key = f"oidc_user_{access_token[:20]}"
        cached_user = cache.get(cache_key)
        if cached_user:
            logger.debug(f"Usuário recuperado do cache: {cached_user.username}")
            return (cached_user, access_token)

        # Validar token e obter userinfo
        try:
            userinfo = self.oidc_client.get_userinfo(access_token)
            user = self._get_or_create_user(userinfo)

            # Cachear resultado
            if hasattr(settings, "OIDC_CACHE_TIMEOUT"):
                cache.set(cache_key, user, settings.OIDC_CACHE_TIMEOUT)

            logger.info(f"Usuário autenticado: {user.username}")
            return (user, access_token)

        except (TokenError, ValidationError) as e:
            logger.warning(f"Token inválido: {e}")
            raise AuthenticationFailed("Token inválido ou expirado")
        except Exception as e:
            logger.error(f"Erro ao autenticar: {e}")
            raise AuthenticationFailed("Erro na autenticação")

    def _get_or_create_user(self, userinfo):
        """
        Cria ou atualiza usuário Django a partir do userinfo.
        """
        sub = userinfo.sub
        email = userinfo.email

        # Buscar ou criar usuário
        user, created = User.objects.get_or_create(
            username=sub,
            defaults={
                "email": email or "",
                "first_name": getattr(userinfo, "given_name", "")[:30],
                "last_name": getattr(userinfo, "family_name", "")[:30],
            },
        )

        # Atualizar informações
        if not created:
            user.email = email or user.email
            user.first_name = getattr(userinfo, "given_name", user.first_name)[:30]
            user.last_name = getattr(userinfo, "family_name", user.last_name)[:30]
            user.save()

        return user

    def get_authorization_header(self, request):
        """
        Extrai header Authorization da requisição.
        """
        auth = request.META.get("HTTP_AUTHORIZATION", b"")
        if isinstance(auth, str):
            auth = auth.encode("iso-8859-1")
        return auth

    def authenticate_header(self, request):
        """
        Retorna string usada no header WWW-Authenticate quando autenticação falha.
        """
        return f'{self.keyword} realm="api"'


# =============================================================================
# 3. PERMISSION CLASSES (permissions.py)
# =============================================================================

"""
# api/permissions.py
"""

from rest_framework.permissions import BasePermission


class IsOIDCAuthenticated(BasePermission):
    """
    Permission que verifica se usuário foi autenticado via OIDC.
    """

    message = "Autenticação OIDC requerida."

    def has_permission(self, request, view):
        """
        Verifica se usuário está autenticado e tem token OIDC.
        """
        if not request.user or not request.user.is_authenticated:
            return False

        # Verificar se autenticação foi via OIDC
        auth = request.auth
        return auth is not None


class HasOIDCScope(BasePermission):
    """
    Permission que verifica se token tem scope específico.

    Usage:
        class MyViewSet(viewsets.ModelViewSet):
            permission_classes = [HasOIDCScope]
            required_scopes = ['read:data', 'write:data']
    """

    message = "Scopes insuficientes."

    def has_permission(self, request, view):
        """
        Verifica se token tem scopes requeridos.
        """
        if not request.user or not request.user.is_authenticated:
            return False

        # Obter scopes requeridos da view
        required_scopes = getattr(view, "required_scopes", [])
        if not required_scopes:
            return True

        # Token scopes (normalmente armazenado em request.auth ou user profile)
        token_scopes = getattr(request.user, "oidc_scopes", [])

        # Verificar se todos os scopes requeridos estão presentes
        return all(scope in token_scopes for scope in required_scopes)


# =============================================================================
# 4. SERIALIZERS (serializers.py)
# =============================================================================

"""
# api/serializers.py
"""

from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer para User model.
    """

    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "is_active", "date_joined"]
        read_only_fields = ["id", "username", "date_joined"]


class TokenObtainSerializer(serializers.Serializer):
    """
    Serializer para obter tokens OIDC via authorization code.
    """

    code = serializers.CharField(required=True, help_text="Authorization code do provider")
    state = serializers.CharField(required=False, help_text="State para validação CSRF")


class TokenResponseSerializer(serializers.Serializer):
    """
    Serializer para resposta de token.
    """

    access_token = serializers.CharField()
    token_type = serializers.CharField(default="Bearer")
    expires_in = serializers.IntegerField(required=False)
    refresh_token = serializers.CharField(required=False)
    id_token = serializers.CharField(required=False)


class UserInfoSerializer(serializers.Serializer):
    """
    Serializer para informações do usuário OIDC.
    """

    sub = serializers.CharField()
    email = serializers.EmailField(required=False)
    email_verified = serializers.BooleanField(required=False)
    name = serializers.CharField(required=False)
    given_name = serializers.CharField(required=False)
    family_name = serializers.CharField(required=False)
    preferred_username = serializers.CharField(required=False)
    picture = serializers.URLField(required=False)


# =============================================================================
# 5. VIEWS (views.py)
# =============================================================================

"""
# api/views.py
"""

import logging
import secrets

from django.contrib.auth.models import User
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from oidc_pure.exceptions import OIDCException

from .authentication import OIDCAuthentication
from .permissions import IsOIDCAuthenticated
from .serializers import (
    TokenObtainSerializer,
    TokenResponseSerializer,
    UserInfoSerializer,
    UserSerializer,
)

logger = logging.getLogger(__name__)

# Inicializar cliente OIDC
oidc_client = OIDCClient(
    issuer_url=settings.OIDC_ISSUER_URL,
    client_id=settings.OIDC_CLIENT_ID,
    client_secret=settings.OIDC_CLIENT_SECRET,
    redirect_uri=settings.OIDC_REDIRECT_URI,
    scopes=settings.OIDC_SCOPES,
)


class AuthViewSet(viewsets.ViewSet):
    """
    ViewSet para autenticação OIDC.

    Endpoints:
    - GET  /api/auth/login     - Inicia fluxo OAuth2
    - POST /api/auth/token     - Troca code por tokens
    - GET  /api/auth/userinfo  - Informações do usuário
    - POST /api/auth/refresh   - Renova access token
    - POST /api/auth/logout    - Logout
    """

    @extend_schema(
        summary="Iniciar login OIDC",
        description="Retorna URL de autorização do provider OIDC",
        responses={
            200: {
                "type": "object",
                "properties": {
                    "authorization_url": {"type": "string"},
                    "state": {"type": "string"},
                },
            }
        },
    )
    @action(detail=False, methods=["get"], permission_classes=[AllowAny])
    def login(self, request):
        """
        Inicia fluxo de autenticação OIDC.

        GET /api/auth/login
        """
        state = secrets.token_urlsafe(32)
        auth_url = oidc_client.get_authorization_url(state=state)

        return Response({"authorization_url": auth_url, "state": state})

    @extend_schema(
        summary="Obter tokens",
        description="Troca authorization code por access/refresh tokens",
        request=TokenObtainSerializer,
        responses={
            200: TokenResponseSerializer,
            400: OpenApiResponse(description="Código inválido"),
        },
    )
    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def token(self, request):
        """
        Troca authorization code por tokens.

        POST /api/auth/token
        Body: {"code": "...", "state": "..."}
        """
        serializer = TokenObtainSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]

        try:
            token_response = oidc_client.exchange_code_for_tokens(code)

            response_serializer = TokenResponseSerializer(
                {
                    "access_token": token_response.access_token,
                    "token_type": "Bearer",
                    "expires_in": token_response.expires_in,
                    "refresh_token": token_response.refresh_token,
                    "id_token": token_response.id_token,
                }
            )

            return Response(response_serializer.data)

        except OIDCException as e:
            logger.error(f"Erro ao trocar code por tokens: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        summary="Informações do usuário",
        description="Retorna informações do usuário autenticado",
        responses={200: UserInfoSerializer, 401: OpenApiResponse(description="Não autenticado")},
    )
    @action(
        detail=False,
        methods=["get"],
        authentication_classes=[OIDCAuthentication],
        permission_classes=[IsAuthenticated],
    )
    def userinfo(self, request):
        """
        Retorna informações do usuário autenticado.

        GET /api/auth/userinfo
        Header: Authorization: Bearer <token>
        """
        access_token = request.auth

        try:
            userinfo = oidc_client.get_userinfo(access_token)
            serializer = UserInfoSerializer(userinfo.__dict__)
            return Response(serializer.data)

        except OIDCException as e:
            logger.error(f"Erro ao obter userinfo: {e}")
            return Response({"error": str(e)}, status=status.HTTP_401_UNAUTHORIZED)

    @extend_schema(
        summary="Renovar token",
        description="Renova access token usando refresh token",
        request={"type": "object", "properties": {"refresh_token": {"type": "string"}}},
        responses={
            200: TokenResponseSerializer,
            400: OpenApiResponse(description="Refresh token inválido"),
        },
    )
    @action(detail=False, methods=["post"], permission_classes=[AllowAny])
    def refresh(self, request):
        """
        Renova access token usando refresh token.

        POST /api/auth/refresh
        Body: {"refresh_token": "..."}
        """
        refresh_token = request.data.get("refresh_token")

        if not refresh_token:
            return Response(
                {"error": "refresh_token é obrigatório"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            token_response = oidc_client.refresh_tokens(refresh_token)

            response_serializer = TokenResponseSerializer(
                {
                    "access_token": token_response.access_token,
                    "token_type": "Bearer",
                    "expires_in": token_response.expires_in,
                    "refresh_token": token_response.refresh_token,
                }
            )

            return Response(response_serializer.data)

        except OIDCException as e:
            logger.error(f"Erro ao renovar token: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        summary="Logout",
        description="Realiza logout (invalida tokens no cliente)",
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
    )
    @action(
        detail=False,
        methods=["post"],
        authentication_classes=[OIDCAuthentication],
        permission_classes=[IsAuthenticated],
    )
    def logout(self, request):
        """
        Logout do usuário.

        POST /api/auth/logout
        Header: Authorization: Bearer <token>
        """
        # Em produção, adicionar token a blacklist
        return Response({"message": "Logout realizado com sucesso"})


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet para gerenciar usuários (somente leitura).

    Endpoints:
    - GET /api/users      - Lista usuários
    - GET /api/users/:id  - Detalhes do usuário
    - GET /api/users/me   - Dados do usuário autenticado
    """

    queryset = User.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [OIDCAuthentication]
    permission_classes = [IsOIDCAuthenticated]

    @extend_schema(
        summary="Usuário atual",
        description="Retorna dados do usuário autenticado",
        responses={200: UserSerializer},
    )
    @action(detail=False, methods=["get"])
    def me(self, request):
        """
        Retorna dados do usuário autenticado.

        GET /api/users/me
        """
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)


# Exemplo de APIView protegida
class ProtectedAPIView(APIView):
    """
    Exemplo de APIView protegida com OIDC.
    """

    authentication_classes = [OIDCAuthentication]
    permission_classes = [IsOIDCAuthenticated]

    @extend_schema(
        summary="Endpoint protegido",
        description="Exemplo de endpoint que requer autenticação OIDC",
        responses={
            200: {
                "type": "object",
                "properties": {"message": {"type": "string"}, "user": {"type": "string"}},
            }
        },
    )
    def get(self, request):
        """
        GET /api/protected
        """
        return Response(
            {"message": "Você está autenticado via OIDC!", "user": request.user.username}
        )


# =============================================================================
# 6. URLS (urls.py)
# =============================================================================

"""
# myproject/urls.py

from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from api.views import AuthViewSet, UserViewSet, ProtectedAPIView

# Router para ViewSets
router = DefaultRouter()
router.register(r'auth', AuthViewSet, basename='auth')
router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    path('admin/', admin.site.urls),

    # API
    path('api/', include(router.urls)),
    path('api/protected', ProtectedAPIView.as_view(), name='protected'),

    # OpenAPI/Swagger
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
"""

# =============================================================================
# 7. EXCEPTION HANDLER (exceptions.py)
# =============================================================================

"""
# api/exceptions.py

from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from oidc_pure.exceptions import OIDCException
import logging

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    '''
    Exception handler customizado para OIDC exceptions.
    '''
    # Chamar handler padrão primeiro
    response = exception_handler(exc, context)

    # Tratar exceções OIDC
    if isinstance(exc, OIDCException):
        logger.error(f"OIDC Exception: {exc}")
        return Response(
            {'error': str(exc), 'type': exc.__class__.__name__},
            status=status.HTTP_401_UNAUTHORIZED
        )

    return response
"""

# =============================================================================
# 8. TESTES (tests.py)
# =============================================================================

"""
# api/tests.py

from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.contrib.auth.models import User
from unittest.mock import patch, MagicMock


class OIDCAuthenticationTestCase(APITestCase):
    '''
    Testes para autenticação OIDC.
    '''

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='testuser', email='test@example.com')

    def test_protected_endpoint_without_token(self):
        '''Testa acesso a endpoint protegido sem token.'''
        response = self.client.get('/api/protected')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('api.authentication.OIDCClient')
    def test_protected_endpoint_with_valid_token(self, mock_oidc_client):
        '''Testa acesso a endpoint protegido com token válido.'''
        # Mock userinfo
        mock_userinfo = MagicMock()
        mock_userinfo.sub = 'testuser'
        mock_userinfo.email = 'test@example.com'
        mock_oidc_client.return_value.get_userinfo.return_value = mock_userinfo

        # Fazer requisição com token
        self.client.credentials(HTTP_AUTHORIZATION='Bearer valid_token')
        response = self.client.get('/api/protected')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch('api.authentication.OIDCClient')
    def test_protected_endpoint_with_invalid_token(self, mock_oidc_client):
        '''Testa acesso a endpoint protegido com token inválido.'''
        # Mock erro de validação
        from oidc_pure.exceptions import TokenError
        mock_oidc_client.return_value.get_userinfo.side_effect = TokenError('Token inválido')

        # Fazer requisição com token inválido
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid_token')
        response = self.client.get('/api/protected')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
"""

# =============================================================================
# 9. EXEMPLO DE USO COMPLETO
# =============================================================================

"""
# Fluxo completo de autenticação:

1. Frontend obtém URL de autorização:
   GET /api/auth/login/
   Response: {"authorization_url": "https://...", "state": "..."}

2. Frontend redireciona usuário para authorization_url

3. Usuário faz login no provider (Keycloak, Google, GitHub)

4. Provider redireciona para redirect_uri com code:
   http://localhost:8000/api/auth/callback?code=...&state=...

5. Frontend troca code por tokens:
   POST /api/auth/token
   Body: {"code": "...", "state": "..."}
   Response: {"access_token": "...", "refresh_token": "...", "expires_in": 3600}

6. Frontend armazena tokens (localStorage, sessionStorage, etc.)

7. Frontend faz requisições autenticadas:
   GET /api/users/me
   Header: Authorization: Bearer <access_token>

8. Quando token expira, renovar:
   POST /api/auth/refresh
   Body: {"refresh_token": "..."}
   Response: {"access_token": "...", "expires_in": 3600}

9. Logout:
   POST /api/auth/logout
   Header: Authorization: Bearer <access_token>
"""

# =============================================================================
# 10. CONSIDERAÇÕES DE PRODUÇÃO
# =============================================================================

"""
# Performance:

1. Cache de userinfo:
   - Cachear resultados de get_userinfo() por 5 minutos
   - Usar Redis para cache distribuído

2. Connection pooling:
   - Configure httpx com connection pooling no OIDCClient

3. Async support:
   - DRF não suporta views assíncronas nativamente
   - Considere usar Django Ninja ou FastAPI para async

# Segurança:

1. Token blacklist:
   - Implementar blacklist para tokens revogados
   - Usar django-redis para armazenar blacklist

2. Rate limiting:
   pip install django-ratelimit

   @ratelimit(key='ip', rate='5/m', method='POST')
   def token(self, request):
       ...

3. CORS:
   pip install django-cors-headers

   CORS_ALLOWED_ORIGINS = [
       "https://frontend.example.com",
   ]

4. Logging e monitoramento:
   - Log todas as tentativas de autenticação
   - Monitore tokens inválidos/expirados
   - Alerte sobre padrões suspeitos

# Testes:

1. Unit tests:
   - Testar authentication class
   - Testar permission classes
   - Mock OIDC client

2. Integration tests:
   - Testar fluxo completo de autenticação
   - Testar refresh token
   - Testar logout

3. Load tests:
   pip install locust

   # Testar performance com muitas requisições simultâneas
"""

if __name__ == "__main__":
    print(__doc__)
    print("\n" + "=" * 70)
    print("📋 Checklist de Integração DRF:")
    print("=" * 70)
    print("✓ 1. Instalar djangorestframework e drf-spectacular")
    print("✓ 2. Configurar REST_FRAMEWORK em settings.py")
    print("✓ 3. Criar api/authentication.py com OIDCAuthentication")
    print("✓ 4. Criar api/permissions.py com custom permissions")
    print("✓ 5. Criar api/serializers.py com serializers")
    print("✓ 6. Criar api/views.py com ViewSets")
    print("✓ 7. Configurar urls.py com router")
    print("✓ 8. Configurar OpenAPI/Swagger")
    print("✓ 9. Criar testes em api/tests.py")
    print("✓ 10. Testar fluxo completo via Swagger UI")
    print("=" * 70)
    print("\n💡 Dica: Acesse /api/docs/ para ver documentação interativa!")
