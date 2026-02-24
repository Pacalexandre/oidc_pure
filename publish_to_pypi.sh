#!/usr/bin/env bash
##############################################################################
# publish_to_pypi.sh - Script para publicar no PyPI
#
# Este script facilita a publicação no TestPyPI ou PyPI
#
# Uso:
#   ./publish_to_pypi.sh testpypi   # Publicar no TestPyPI (teste)
#   ./publish_to_pypi.sh pypi       # Publicar no PyPI (produção)
##############################################################################

set -euo pipefail

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ $# -eq 0 ]; then
    echo -e "${RED}Erro: especifique 'testpypi' ou 'pypi'${NC}"
    echo ""
    echo "Uso:"
    echo "  $0 testpypi   # Publicar no TestPyPI (recomendado primeiro)"
    echo "  $0 pypi       # Publicar no PyPI (produção)"
    exit 1
fi

TARGET=$1

# Validar target
if [ "$TARGET" != "testpypi" ] && [ "$TARGET" != "pypi" ]; then
    echo -e "${RED}Erro: target deve ser 'testpypi' ou 'pypi'${NC}"
    exit 1
fi

# Verificar se dist/ existe
if [ ! -d "dist" ] || [ -z "$(ls -A dist 2>/dev/null)" ]; then
    echo -e "${RED}❌ Diretório dist/ vazio ou inexistente!${NC}"
    echo ""
    echo "Execute primeiro:"
    echo "  ./build_package.sh"
    exit 1
fi

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Publicação no $(echo $TARGET | tr '[:lower:]' '[:upper:]')${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Mostrar arquivos que serão publicados
echo "Arquivos que serão publicados:"
ls -lh dist/
echo ""

# Instruções específicas por target
if [ "$TARGET" = "testpypi" ]; then
    echo -e "${YELLOW}📝 TestPyPI - Ambiente de Testes${NC}"
    echo ""
    echo "1. Crie uma conta (se não tiver):"
    echo "   https://test.pypi.org/account/register/"
    echo ""
    echo "2. Crie um token de API:"
    echo "   https://test.pypi.org/manage/account/token/"
    echo ""
    echo "3. Use as credenciais:"
    echo "   Username: __token__"
    echo "   Password: pypi-<seu-token>"
    echo ""
    read -p "Pressione ENTER para continuar com o upload ou Ctrl+C para cancelar..."
    echo ""
    
    echo -e "${BLUE}Fazendo upload para TestPyPI...${NC}"
    uv run twine upload --repository testpypi dist/*
    
    echo ""
    echo -e "${GREEN}✅ Publicado com sucesso no TestPyPI!${NC}"
    echo ""
    echo "Verificar em:"
    echo "  https://test.pypi.org/project/oidc_pure/"
    echo ""
    echo "Testar instalação:"
    echo "  pip install --index-url https://test.pypi.org/simple/ oidc_pure"
    
else
    echo -e "${YELLOW}📝 PyPI - Produção${NC}"
    echo ""
    echo -e "${RED}⚠️  ATENÇÃO: Você está prestes a publicar no PyPI REAL!${NC}"
    echo ""
    echo "Certifique-se de que:"
    echo "  ✓ Testou no TestPyPI primeiro"
    echo "  ✓ A versão está correta (0.1.0)"
    echo "  ✓ Todos os testes estão passando"
    echo "  ✓ A documentação está atualizada"
    echo ""
    echo "1. Crie uma conta (se não tiver):"
    echo "   https://pypi.org/account/register/"
    echo ""
    echo "2. Crie um token de API:"
    echo "   https://pypi.org/manage/account/token/"
    echo ""
    echo "3. Use as credenciais:"
    echo "   Username: __token__"
    echo "   Password: pypi-<seu-token>"
    echo ""
    read -p "Tem certeza? Digite 'yes' para confirmar: " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo "Cancelado."
        exit 0
    fi
    
    echo ""
    echo -e "${BLUE}Fazendo upload para PyPI...${NC}"
    uv run twine upload dist/*
    
    echo ""
    echo -e "${GREEN}✅ Publicado com sucesso no PyPI!${NC}"
    echo ""
    echo "Verificar em:"
    echo "  https://pypi.org/project/oidc_pure/"
    echo ""
    echo "Instalar:"
    echo "  pip install oidc_pure"
    echo ""
    echo "Próximos passos:"
    echo "  1. Criar release no GitHub: git tag v0.1.0 && git push origin v0.1.0"
    echo "  2. Criar GitHub Release com artefatos"
    echo "  3. Atualizar CHANGELOG.md"
fi

echo ""
echo -e "${GREEN}🎉 Concluído!${NC}"
