#!/usr/bin/env bash
##############################################################################
# pre-release-check.sh - Verificações antes de criar um release
#
# Este script verifica se tudo está pronto para um release
#
# Uso:
#   ./pre-release-check.sh [versão]
##############################################################################

set -euo pipefail

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

VERSION=${1:-""}
EXIT_CODE=0

print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

check_ok() {
    echo -e "  ${GREEN}✓${NC} $1"
}

check_warning() {
    echo -e "  ${YELLOW}⚠${NC} $1"
}

check_error() {
    echo -e "  ${RED}✗${NC} $1"
    EXIT_CODE=1
}

check_info() {
    echo -e "  ${CYAN}ℹ${NC} $1"
}

print_header "🔍 Verificação Pré-Release"

# ==================== Git ====================
echo -e "${YELLOW}[1/8]${NC} Verificando Git..."

if ! git rev-parse --git-dir > /dev/null 2>&1; then
    check_error "Não está em um repositório Git"
else
    check_ok "Repositório Git encontrado"
    
    CURRENT_BRANCH=$(git branch --show-current)
    if [ "$CURRENT_BRANCH" = "main" ]; then
        check_ok "Branch: main"
    else
        check_warning "Branch atual: ${CURRENT_BRANCH} (deveria ser 'main')"
    fi
    
    if git diff-index --quiet HEAD --; then
        check_ok "Sem mudanças não commitadas"
    else
        check_warning "Há mudanças não commitadas"
        git status --short | sed 's/^/      /'
    fi
    
    # Verificar se está atualizado com remote
    if git remote show origin &> /dev/null; then
        git fetch origin --quiet
        LOCAL=$(git rev-parse @)
        REMOTE=$(git rev-parse @{u} 2>/dev/null || echo "")
        
        if [ -n "$REMOTE" ]; then
            if [ "$LOCAL" = "$REMOTE" ]; then
                check_ok "Sincronizado com origin"
            else
                check_warning "Branch não está sincronizada com origin"
            fi
        fi
    fi
fi

echo ""

# ==================== Version ====================
echo -e "${YELLOW}[2/8]${NC} Verificando Versão..."

if [ -f "pyproject.toml" ]; then
    CURRENT_VERSION=$(grep '^version = ' pyproject.toml | cut -d'"' -f2)
    check_ok "Versão no pyproject.toml: ${CURRENT_VERSION}"
    
    if [ -n "$VERSION" ]; then
        if [ "$VERSION" = "$CURRENT_VERSION" ]; then
            check_ok "Versão solicitada corresponde: ${VERSION}"
        else
            check_error "Versão não corresponde!"
            check_info "pyproject.toml: ${CURRENT_VERSION}"
            check_info "Solicitado: ${VERSION}"
        fi
    fi
    
    # Verificar __init__.py
    if [ -f "oidc_pure/__init__.py" ]; then
        INIT_VERSION=$(grep '__version__ = ' oidc_pure/__init__.py | cut -d'"' -f2)
        if [ "$INIT_VERSION" = "$CURRENT_VERSION" ]; then
            check_ok "Versão em __init__.py corresponde: ${INIT_VERSION}"
        else
            check_warning "Versão em __init__.py difere: ${INIT_VERSION}"
        fi
    fi
else
    check_error "pyproject.toml não encontrado"
fi

echo ""

# ==================== Tests ====================
echo -e "${YELLOW}[3/8]${NC} Verificando Testes..."

if command -v pytest &> /dev/null || [ -f ".venv/bin/pytest" ]; then
    check_ok "pytest disponível"
    
    check_info "Executando testes..."
    if [ -f ".venv/bin/pytest" ]; then
        if .venv/bin/pytest -q --tb=no 2>&1 | grep -q "passed"; then
            check_ok "Testes passaram"
        else
            check_error "Alguns testes falharam"
        fi
    else
        check_warning "Ambiente virtual não encontrado, pulando testes"
    fi
else
    check_warning "pytest não encontrado"
fi

echo ""

# ==================== Lint ====================
echo -e "${YELLOW}[4/8]${NC} Verificando Lint..."

if command -v ruff &> /dev/null || [ -f ".venv/bin/ruff" ]; then
    check_ok "ruff disponível"
    
    RUFF_CMD="ruff"
    if [ -f ".venv/bin/ruff" ]; then
        RUFF_CMD=".venv/bin/ruff"
    fi
    
    if $RUFF_CMD check . --quiet 2>&1; then
        check_ok "Lint sem erros"
    else
        check_warning "Há avisos de lint"
    fi
else
    check_warning "ruff não encontrado"
fi

echo ""

# ==================== Build ====================
echo -e "${YELLOW}[5/8]${NC} Verificando Build..."

if [ -d "dist" ] && [ "$(ls -A dist 2>/dev/null)" ]; then
    check_warning "Diretório dist/ existente (será limpo no build)"
fi

if [ -f "build_package.sh" ]; then
    check_ok "Script de build encontrado"
else
    check_warning "build_package.sh não encontrado"
fi

echo ""

# ==================== Documentation ====================
echo -e "${YELLOW}[6/8]${NC} Verificando Documentação..."

if [ -f "README.md" ]; then
    LINES=$(wc -l < README.md)
    check_ok "README.md encontrado (${LINES} linhas)"
else
    check_error "README.md não encontrado"
fi

if [ -f "CHANGELOG.md" ]; then
    check_ok "CHANGELOG.md encontrado"
else
    check_warning "CHANGELOG.md não encontrado (recomendado)"
fi

if [ -f "LICENSE" ]; then
    check_ok "LICENSE encontrado"
else
    check_error "LICENSE não encontrado"
fi

echo ""

# ==================== Workflows ====================
echo -e "${YELLOW}[7/8]${NC} Verificando Workflows..."

if [ -d ".github/workflows" ]; then
    check_ok "Diretório de workflows encontrado"
    
    WORKFLOWS=$(find .github/workflows -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l)
    check_ok "${WORKFLOWS} workflow(s) configurado(s)"
    
    if [ -f ".github/workflows/release-publish.yml" ]; then
        check_ok "Workflow de release configurado"
    else
        check_warning "Workflow de release não encontrado"
    fi
    
    if [ -f ".github/workflows/ci.yml" ]; then
        check_ok "Workflow de CI configurado"
    else
        check_warning "Workflow de CI não encontrado"
    fi
else
    check_warning "Diretório de workflows não encontrado"
fi

echo ""

# ==================== Tags ====================
echo -e "${YELLOW}[8/8]${NC} Verificando Tags..."

if [ -n "$VERSION" ]; then
    TAG_NAME="v${VERSION}"
    
    if git rev-parse "$TAG_NAME" >/dev/null 2>&1; then
        check_error "Tag ${TAG_NAME} já existe!"
    else
        check_ok "Tag ${TAG_NAME} disponível"
    fi
fi

if git tag -l | grep -q .; then
    LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "nenhuma")
    check_info "Última tag: ${LAST_TAG}"
else
    check_info "Nenhuma tag encontrada (primeiro release)"
fi

echo ""

# ==================== Summary ====================
print_header "📊 Resumo"

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✅ Tudo pronto para release!${NC}"
    echo ""
    
    if [ -n "$VERSION" ]; then
        echo "Próximos passos:"
        echo ""
        echo "  1. Fazer release:"
        echo -e "     ${CYAN}./release.sh ${VERSION} --push${NC}"
        echo ""
        echo "  2. Ou criar tag manualmente:"
        echo -e "     ${CYAN}git tag -a v${VERSION} -m 'Release v${VERSION}'${NC}"
        echo -e "     ${CYAN}git push origin v${VERSION}${NC}"
    else
        echo "Para criar um release:"
        echo -e "  ${CYAN}./release.sh <versão>${NC}"
        echo ""
        echo "Exemplo:"
        echo -e "  ${CYAN}./release.sh 0.2.0 --push${NC}"
    fi
    echo ""
else
    echo -e "${RED}❌ Há problemas que precisam ser corrigidos!${NC}"
    echo ""
    echo "Revise os itens marcados com ${RED}✗${NC} acima."
    echo ""
fi

exit $EXIT_CODE
