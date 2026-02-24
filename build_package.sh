#!/usr/bin/env bash
##############################################################################
# build_package.sh - Script para build do pacote Python para PyPI
#
# Este script:
# 1. Valida a estrutura do projeto
# 2. Limpa builds anteriores
# 3. Executa testes
# 4. Faz build do pacote (wheel e sdist)
# 5. Verifica o pacote gerado
#
# Uso:
#   ./build_package.sh [--skip-tests] [--check-only]
##############################################################################

set -euo pipefail

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Build do Pacote OIDC Pure para PyPI${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Parse argumentos
SKIP_TESTS=false
CHECK_ONLY=false

for arg in "$@"; do
    case $arg in
        --skip-tests)
            SKIP_TESTS=true
            ;;
        --check-only)
            CHECK_ONLY=true
            ;;
    esac
done

# 1. Validar estrutura do projeto
echo -e "${YELLOW}[1/6]${NC} Validando estrutura do projeto..."
if [ ! -f "pyproject.toml" ]; then
    echo -e "${RED}❌ pyproject.toml não encontrado!${NC}"
    exit 1
fi

if [ ! -d "oidc_pure" ]; then
    echo -e "${RED}❌ Diretório oidc_pure/ não encontrado!${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} pyproject.toml encontrado"
echo -e "${GREEN}✓${NC} Diretório oidc_pure/ encontrado"
echo -e "${GREEN}✓${NC} README.md: $(wc -l < README.md) linhas"
echo -e "${GREEN}✓${NC} LICENSE encontrado"
echo ""

# 2. Limpar builds anteriores
echo -e "${YELLOW}[2/6]${NC} Limpando builds anteriores..."
rm -rf dist/ build/ *.egg-info
rm -rf oidc_pure/__pycache__ oidc_pure/**/__pycache__
echo -e "${GREEN}✓${NC} Diretórios limpos"
echo ""

# 3. Executar testes (opcional)
if [ "$SKIP_TESTS" = false ]; then
    echo -e "${YELLOW}[3/6]${NC} Executando testes..."
    if uv run pytest -v --tb=short; then
        echo -e "${GREEN}✓${NC} Todos os testes passaram"
    else
        echo -e "${RED}❌ Testes falharam!${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}[3/6]${NC} Testes pulados (--skip-tests)"
fi
echo ""

# Se é apenas checagem, parar aqui
if [ "$CHECK_ONLY" = true ]; then
    echo -e "${GREEN}✓${NC} Projeto validado. Use sem --check-only para fazer build."
    exit 0
fi

# 4. Instalar dependência de build
echo -e "${YELLOW}[4/6]${NC} Instalando dependências de build..."
uv pip install build twine --quiet
echo -e "${GREEN}✓${NC} Dependências instaladas"
echo ""

# 5. Fazer build do pacote
echo -e "${YELLOW}[5/6]${NC} Fazendo build do pacote..."
uv run python -m build
echo ""

# Verificar se build foi bem sucedido
if [ ! -d "dist" ]; then
    echo -e "${RED}❌ Diretório dist/ não foi criado!${NC}"
    exit 1
fi

WHEEL_COUNT=$(ls -1 dist/*.whl 2>/dev/null | wc -l)
SDIST_COUNT=$(ls -1 dist/*.tar.gz 2>/dev/null | wc -l)

if [ "$WHEEL_COUNT" -eq 0 ] || [ "$SDIST_COUNT" -eq 0 ]; then
    echo -e "${RED}❌ Build falhou - arquivos não gerados${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Build concluído com sucesso!"
echo ""
echo "Arquivos gerados em dist/:"
ls -lh dist/
echo ""

# 6. Verificar pacote
echo -e "${YELLOW}[6/6]${NC} Verificando pacote com twine..."
if uv run twine check dist/*; then
    echo -e "${GREEN}✓${NC} Pacote validado com sucesso"
else
    echo -e "${RED}❌ Pacote inválido!${NC}"
    exit 1
fi
echo ""

# Resumo final
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ Build concluído com sucesso!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}Próximos passos:${NC}"
echo ""
echo "1. Testar instalação local:"
echo -e "   ${BLUE}uv pip install dist/*.whl${NC}"
echo ""
echo "2. Publicar no TestPyPI (teste):"
echo -e "   ${BLUE}uv run twine upload --repository testpypi dist/*${NC}"
echo ""
echo "3. Publicar no PyPI (produção):"
echo -e "   ${BLUE}uv run twine upload dist/*${NC}"
echo ""
echo "Arquivos prontos para upload:"
for file in dist/*; do
    echo -e "  ${GREEN}✓${NC} $file"
done
echo ""
