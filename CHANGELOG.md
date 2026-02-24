# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planejado para Próximas Versões
- Suporte para Device Authorization Flow (RFC 8628)
- Suporte para Token Introspection (RFC 7662)
- Suporte para Token Revocation (RFC 7009)
- Cache de JWKs para melhor performance
- Suporte assíncrono completo (async/await)
- Integração com mais frameworks (Starlette, Quart)

---

## [1.1.4] - 2026-02-24

### ✨ Improvements

#### Testing Coverage
- **Cobertura geral aumentada de 89% → 99%** (+10 pontos percentuais)
- **Total de testes: 173 → 213** (+40 novos testes)
- **6 de 7 módulos agora com 100% de cobertura**

#### Novos Testes - models.py (100% coverage)
- **+22 testes abrangentes** para modelos de dados
- Testes para `OIDCConfig`, `TokenResponse`, `UserInfo`, `JWK`, `JWKSet`
- Cobertura de formatos OIDC padrão e provider-específicos (GitHub)
- Testes de fallback mechanisms e edge cases
- Validação de mapeamento de claims não-OIDC
- **models.py: 86% → 100%** (+14%)

#### Novos Testes - tokens.py (100% coverage)
- **+18 testes de validação JWT e PKCE**
- Testes para todos os algoritmos HMAC (HS256, HS384, HS512)
- Validação de algoritmos não suportados (RS256, ES256, none)
- Testes de assinaturas inválidas e adulteradas
- Validação de claims (issuer, audience, exp, nbf, iat)
- Testes de PKCE com comprimentos inválidos
- Método `extract_claims()` testado
- **tokens.py: 87% → 100%** (+13%)

#### Code Quality
- **Ruff linting**: All checks passed (zero erros)
- **Type hints**: Tipagem completa em todos os módulos
- **Test organization**: Classes de teste bem organizadas por funcionalidade

#### Documentation
- **README atualizado** com estatísticas de cobertura atualizadas
- Tabela de cobertura por módulo atualizada
- Status dos testes refletindo 99% de cobertura

### 📊 Test Coverage Summary

| Módulo | Antes | Depois | Tests |
|--------|-------|--------|-------|
| `__init__.py` | 100% | 100% | - |
| `exceptions.py` | 100% | 100% | - |
| `discovery.py` | 100% | 100% | 25 |
| `client.py` | 100% | 100% | 24 |
| `models.py` | **86%** | **100%** ✅ | **22** |
| `tokens.py` | **87%** | **100%** ✅ | **30** |
| `oauth2.py` | 97% | 97% | 86 |
| **TOTAL** | **89%** | **99%** | **213** |

---

## [1.1.3] - 2026-02-24

### ✨ Improvements

#### Testing
- **+19 testes de edge cases**: Testes abrangentes para respostas malformadas e vazias
  - Testes para campos obrigatórios ausentes (access_token, token_type)
  - Testes para respostas vazias, whitespace, null JSON
  - Testes para tipos JSON inválidos (arrays, syntax errors)
  - Testes para content-types errados (HTML, XML, binary)
  - Testes para casos extremos (tokens grandes, unicode, BOM)
  - Testes para form-urlencoded malformado
  - Total: **142 testes** (86 no módulo oauth2)
  - **Cobertura aumentada**: oauth2.py de 95% → 97%

#### Code Quality
- **Validação de tipo JSON**: Adiciona verificação `isinstance(response_data, dict)` para prevenir TypeError com JSON arrays
- **Melhor tratamento de erros**: Mensagens de erro mais claras indicando tipo de problema

#### CI/CD
- **Fix GitHub Actions deprecated**: Substituído `actions/create-release@v1` e `actions/upload-release-asset@v1` por `softprops/action-gh-release@v2`
- **Workflow simplificado**: Upload de múltiplos arquivos em um único step com glob patterns
- **Sem warnings**: Elimina avisos de deprecation do GitHub Actions

---

## [1.1.2] - 2026-02-24

### 🐛 Bug Fixes

#### CI/CD
- **Fix workflow installation test (segunda tentativa)**: Corrigido teste usando caminho absoluto do Python do venv antes de mudar para /tmp
- Substituído `uv venv` por `python -m venv` para compatibilidade
- Captura do caminho do Python do venv com `$PWD` antes de mudar diretório

---

## [1.1.1] - 2026-02-24 [YANKED]

### 🐛 Bug Fixes (tentativa malsucedida)

#### CI/CD
- Tentativa de corrigir teste de instalação mudando para /tmp, mas ainda apresentou erro
- Esta versão foi marcada como yanked devido à falha no workflow

---

## [1.1.0] - 2026-02-24

### 🎉 Primeiro Release Público

Este é o primeiro release público do `oidc_pure`, uma implementação pura em Python de OAuth2 e OpenID Connect.

### ✨ Features Implementadas

#### Core OAuth2/OIDC
- **Authorization Code Flow** com suporte completo ao RFC 6749
- **PKCE (Proof Key for Code Exchange)** seguindo RFC 7636
- **Client Credentials Flow** para autenticação machine-to-machine
- **Refresh Token Flow** para renovação de tokens
- **OIDC Discovery** automático de configuração de provedores
- **JWT Token Validation** com verificação de assinatura e claims
- **UserInfo Endpoint** para obtenção de informações do usuário

#### Multi-Provider Support
- Sistema genérico para qualquer provedor OIDC compatível
- Configurações pré-definidas para provedores populares:
  - Keycloak
  - Google
  - GitHub (OAuth2)
  - Microsoft Azure AD
  - Okta
  - Auth0
- Mapeamento automático de claims não-OIDC para formato OIDC

#### Integrações com Frameworks
- **Flask**: Middleware e decoradores
- **FastAPI**: Dependency injection e rotas protegidas
- **Django**: Middleware e views
- **Django REST Framework (DRF)**: Authentication classes

#### Developer Experience
- Type hints completos para melhor suporte em IDEs
- Cliente HTTP moderno com `httpx` (sync)
- Sem dependências de banco de dados (stateless)
- Exemplos práticos para cada framework
- Documentação completa em português

#### Testing & Quality
- Cobertura de testes em 78%+
- Testes unitários e de integração com pytest
- Mocks com respx para chamadas HTTP
- Auditoria de segurança automatizada
- Linting com ruff

#### CI/CD & Automation
- GitHub Actions para CI/CD completo
- Workflow de testes em múltiplas versões Python (3.12, 3.13)
- Workflow de segurança com pip-audit, safety e bandit
- Workflow de release automatizado com publicação no PyPI
- Scripts auxiliares para build, release e auditoria

### 📦 Dependências

#### Core
- `httpx >= 0.27.0` - Cliente HTTP moderno
- `python-dotenv >= 1.2.1` - Gerenciamento de variáveis de ambiente

#### Optional
- `django >= 4.2` - Para integração com Django
- `djangorestframework >= 3.14` - Para integração com DRF
- `fastapi >= 0.104.0` - Para integração com FastAPI
- `flask >= 3.0.0` - Para integração com Flask

### 🔒 Segurança

- Implementação segura de PKCE para prevenir code interception
- Validação completa de JWT tokens
- Verificação de state para prevenir CSRF
- Auditoria de segurança automatizada em CI
- Sem vulnerabilidades conhecidas nas dependências

### 📚 Documentação

- README completo com 1300+ linhas
- Exemplos práticos para cada use case
- Guia de configuração multi-provider
- Documentação de integração com frameworks
- Guia de deployment e release

### 🛠️ Scripts e Ferramentas

- `build_package.sh` - Build automatizado do pacote
- `publish_to_pypi.sh` - Publicação no PyPI/TestPyPI
- `security_audit.sh` - Auditoria de segurança
- `release.sh` - Auxiliar para criação de releases
- `pre-release-check.sh` - Verificações pré-release

### 🎯 Compatibilidade

- Python 3.12+
- Suporte para Python 3.13 e 3.14
- Testado em Linux, macOS, Windows
- Dev Container configurado para desenvolvimento

### 📖 Exemplos Incluídos

- `simple_example.py` - Uso básico do cliente
- `async_example.py` - Uso assíncrono
- `keycloak_example.py` - Integração com Keycloak
- `flask_integration.py` - Exemplo completo com Flask
- `fastapi_integration.py` - Exemplo completo com FastAPI
- `django_integration.py` - Exemplo completo com Django
- `django_drf_integration.py` - Exemplo completo com DRF

### 🐛 Known Issues

Nenhum conhecido até o momento.

### 🙏 Agradecimentos

- Comunidade Python pela infraestrutura e ferramentas
- Mantenedores dos projetos de código aberto utilizados
- RFCs 6749 (OAuth2) e especificações OpenID Connect

---

## Como Usar Este Changelog

### Tipos de Mudanças

- **Added** - Novas features adicionadas
- **Changed** - Mudanças em funcionalidades existentes
- **Deprecated** - Features que serão removidas em breve
- **Removed** - Features removidas
- **Fixed** - Correções de bugs
- **Security** - Correções de vulnerabilidades

### Versionamento

Este projeto segue o [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0) - Mudanças incompatíveis na API
- **MINOR** (0.X.0) - Novas funcionalidades compatíveis
- **PATCH** (0.0.X) - Correções de bugs compatíveis

### Links

[Unreleased]: https://github.com/Pacalexandre/oidc_pure/compare/v1.1.2...HEAD
[1.1.2]: https://github.com/Pacalexandre/oidc_pure/compare/v1.1.0...v1.1.2
[1.1.1]: https://github.com/Pacalexandre/oidc_pure/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Pacalexandre/oidc_pure/releases/tag/v1.1.0
