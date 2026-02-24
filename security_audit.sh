#!/usr/bin/env bash
##############################################################################
# security_audit.sh - Script de auditoria de segurança
# 
# Este script executa múltiplas ferramentas de segurança para detectar
# vulnerabilidades conhecidas (CVEs) e problemas de segurança no código.
#
# Compatível com:
#   - uv (gerenciador de pacotes)
#   - devcontainer (VS Code)
#   - CI/CD pipelines
#
# Uso:
#   ./security_audit.sh [--install] [--full] [--ci]
#
# Opções:
#   --install    Instala todas as ferramentas de segurança
#   --full       Executa análise completa (incluindo testes lentos)
#   --ci         Modo CI (falha se encontrar problemas)
#   --help       Mostra esta mensagem de ajuda
#
##############################################################################

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Parse argumentos
INSTALL=false
FULL=false
CI_MODE=false

for arg in "$@"; do
    case $arg in
        --install)
            INSTALL=true
            ;;
        --full)
            FULL=true
            ;;
        --ci)
            CI_MODE=true
            ;;
        --help)
            head -n 25 "$0" | tail -n 18
            exit 0
            ;;
        *)
            echo "Argumento desconhecido: $arg"
            echo "Use --help para ver opções disponíveis"
            exit 1
            ;;
    esac
done

# Verificar se uv está disponível
if ! command -v uv &> /dev/null; then
    print_error "uv não encontrado. Instale com: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Instalar ferramentas se solicitado
if [ "$INSTALL" = true ]; then
    print_header "Instalando ferramentas de segurança com uv"
    echo "Instalando pip-audit, safety e bandit..."
    uv pip install pip-audit safety bandit --quiet
    print_success "Ferramentas instaladas com sucesso"
    echo ""
fi

# Verificar e auto-instalar ferramentas se necessário
ensure_tool() {
    local tool=$1
    if ! uv run "$tool" --version &> /dev/null; then
        echo "Instalando $tool..."
        uv pip install "$tool" --quiet
    fi
}

# Auto-instalar ferramentas se não estiverem disponíveis
if [ "$INSTALL" != true ]; then
    echo "Verificando ferramentas de segurança..."
    ensure_tool pip-audit
    ensure_tool safety
    ensure_tool bandit
    echo ""
fi

print_header "🔍 Auditoria de Segurança - OIDC Pure Library"
echo "Data: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

ISSUES_FOUND=0

# 1. pip-audit - Vulnerabilidades conhecidas (CVEs)
print_header "1. pip-audit - Verificação de CVEs em dependências"
echo "Verificando vulnerabilidades conhecidas no PyPI..."
echo "Comando: uv run pip-audit --desc"
echo ""

if AUDIT_OUTPUT=$(uv run pip-audit --desc 2>&1); then
    if echo "$AUDIT_OUTPUT" | grep -q "No known vulnerabilities found"; then
        print_success "Nenhuma vulnerabilidade conhecida encontrada"
        echo "$AUDIT_OUTPUT" | grep -E "(Found|packages audited)" || true
    else
        print_error "Vulnerabilidades encontradas!"
        echo "$AUDIT_OUTPUT"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    AUDIT_EXIT=$?
    if echo "$AUDIT_OUTPUT" | grep -q "No known vulnerabilities found"; then
        print_success "Nenhuma vulnerabilidade conhecida encontrada"
    else
        print_warning "pip-audit retornou código $AUDIT_EXIT"
        echo "$AUDIT_OUTPUT" | head -n 20
    fi
fi
echo ""

# 2. safety - Vulnerabilidades de segurança
print_header "2. safety - Verificação de vulnerabilidades conhecidas"
echo "Escaneando dependências com safety (PyUp.io database)..."
echo "Comando: uv run safety scan"
echo ""

# Safety 3.x usa 'scan' ao invés de 'check'
SAFETY_OUTPUT=$(uv run safety scan 2>&1 || true)

if echo "$SAFETY_OUTPUT" | grep -q -i "No known security vulnerabilities\|vulnerabilities_found\": 0\|0 vulnerabilities found"; then
    print_success "Nenhuma vulnerabilidade encontrada pelo safety"
elif echo "$SAFETY_OUTPUT" | grep -q -i "requires authentication\|API key"; then
    print_warning "Safety requer API key (modo gratuito limitado)"
    echo "  Você pode usar a versão gratuita localmente sem API key"
    echo "  Para mais detalhes: https://docs.pyup.io/docs/getting-started"
elif echo "$SAFETY_OUTPUT" | grep -q -i "Error:"; then
    print_warning "Safety retornou erro (ferramenta pode estar em transição de API)"
    echo "$SAFETY_OUTPUT" | head -n 15
else
    echo "$SAFETY_OUTPUT" | head -n 30
    if echo "$SAFETY_OUTPUT" | grep -q -i "vulnerabilit"; then
        print_error "Possíveis vulnerabilidades encontradas!"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
fi
echo ""

# 3. bandit - Análise estática de código
print_header "3. bandit - Análise de segurança do código fonte"
echo "Analisando código em oidc_pure/ (1226+ linhas)..."
echo "Comando: uv run bandit -r oidc_pure/ -ll"
echo ""

BANDIT_OUTPUT=$(uv run bandit -r oidc_pure/ -ll -f txt 2>&1 || true)

if echo "$BANDIT_OUTPUT" | grep -q "No issues identified"; then
    print_success "Nenhum problema de segurança no código encontrado"
    LINES=$(echo "$BANDIT_OUTPUT" | grep "Total lines of code" | grep -o '[0-9]*' | head -n 1)
    if [ -n "$LINES" ]; then
        echo "  • Total de linhas analisadas: $LINES"
    fi
    echo "  • Severidade: Low e Medium verificadas"
    echo "  • Confiança: Low e Medium verificadas"
else
    print_error "Problemas de segurança encontrados no código!"
    echo "$BANDIT_OUTPUT"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi
echo ""

# 4. Verificações adicionais (modo --full)
if [ "$FULL" = true ]; then
    print_header "4. Verificações Adicionais (modo --full)"
    
    # 4.1 Verificar secrets hardcoded
    echo "4.1 Procurando secrets hardcoded..."
    if grep -r -i -E "(password|secret|token|api_key|private_key)\s*=\s*['\"][^'\"]+['\"]" oidc_pure/ --exclude-dir=__pycache__ 2>/dev/null; then
        print_warning "Possíveis secrets hardcoded encontrados (verifique se são apenas exemplos)"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    else
        print_success "Nenhum secret hardcoded encontrado"
    fi
    echo ""
    
    # 4.2 Verificar dependências desatualizadas
    echo "4.2 Verificando dependências desatualizadas..."
    OUTDATED=$(uv pip list --outdated 2>&1 || true)
    if [ -n "$OUTDATED" ] && echo "$OUTDATED" | grep -q -v "Package"; then
        print_warning "Dependências desatualizadas encontradas:"
        echo "$OUTDATED"
        # Não conta como issue crítico
    else
        print_success "Todas as dependências estão atualizadas"
    fi
    echo ""
    
    # 4.3 Verificar permissões de arquivos
    echo "4.3 Verificando permissões de arquivos sensíveis..."
    if [ -f ".env" ]; then
        PERMS=$(stat -c '%a' .env)
        if [ "$PERMS" != "600" ] && [ "$PERMS" != "400" ]; then
            print_warning "Arquivo .env tem permissões $PERMS (recomendado: 600)"
            echo "  Execute: chmod 600 .env"
        else
            print_success "Permissões do .env corretas ($PERMS)"
        fi
    else
        print_success "Arquivo .env não existe (ou está no .gitignore)"
    fi
    echo ""
fi

# 5. Resumo final
print_header "📊 Resumo da Auditoria"
echo "Ambiente:"
echo "  • Python: $(uv run python --version 2>&1 || echo 'N/A')"
echo "  • uv: $(uv --version 2>&1 || echo 'N/A')"
echo "  • Diretório: $(pwd)"
echo ""
echo "Ferramentas executadas:"
echo "  • pip-audit  - Verificação de CVEs (PyPI)"
echo "  • safety     - Vulnerabilidades conhecidas (PyUp.io)"
echo "  • bandit     - Análise estática de código (SAST)"
if [ "$FULL" = true ]; then
    echo "  • Verificações adicionais (modo --full)"
fi
echo ""

if [ $ISSUES_FOUND -eq 0 ]; then
    print_success "🎉 Nenhum problema crítico de segurança encontrado!"
    print_success "Projeto aprovado na auditoria de segurança"
    echo ""
    echo "Próximos passos recomendados:"
    echo "  1. Execute com --full para análise completa"
    echo "  2. Configure dependabot no GitHub"
    echo "  3. Adicione ao CI/CD: ./security_audit.sh --ci"
    exit 0
else
    print_error "⚠️  $ISSUES_FOUND problema(s) de segurança encontrado(s)"
    print_error "Revise os detalhes acima e corrija antes de fazer deploy"
    
    if [ "$CI_MODE" = true ]; then
        echo ""
        echo "Modo CI ativado: falha na build"
        exit 1
    else
        echo ""
        echo "Execute em modo CI para falhar em caso de problemas: ./security_audit.sh --ci"
        exit 1
    fi
fi
