#!/usr/bin/env bash
##############################################################################
# release.sh - Script auxiliar para criar releases
#
# Facilita o processo de criação de releases com validações
#
# Uso:
#   ./release.sh 0.2.0            # Criar release para versão 0.2.0
#   ./release.sh 0.2.0 --push     # Criar e fazer push da tag
#   ./release.sh --check          # Verificar configuração atual
##############################################################################

set -euo pipefail

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Funções auxiliares
print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

# Função para verificar configuração
check_configuration() {
    print_header "Verificação de Configuração"
    
    local has_errors=0
    
    # Verificar git
    if command -v git &> /dev/null; then
        print_success "Git instalado: $(git --version | head -n1)"
    else
        print_error "Git não encontrado!"
        has_errors=1
    fi
    
    # Verificar se está em repositório git
    if git rev-parse --git-dir > /dev/null 2>&1; then
        print_success "Repositório Git encontrado"
        
        # Verificar branch
        CURRENT_BRANCH=$(git branch --show-current)
        print_info "Branch atual: ${CURRENT_BRANCH}"
        
        if [ "$CURRENT_BRANCH" != "main" ]; then
            print_warning "Você não está na branch 'main'"
        fi
        
        # Verificar se há mudanças não commitadas
        if git diff-index --quiet HEAD --; then
            print_success "Sem mudanças não commitadas"
        else
            print_warning "Há mudanças não commitadas"
        fi
    else
        print_error "Não está em um repositório Git!"
        has_errors=1
    fi
    
    # Verificar pyproject.toml
    if [ -f "pyproject.toml" ]; then
        print_success "pyproject.toml encontrado"
        
        CURRENT_VERSION=$(grep '^version = ' pyproject.toml | cut -d'"' -f2)
        print_info "Versão atual: ${CURRENT_VERSION}"
    else
        print_error "pyproject.toml não encontrado!"
        has_errors=1
    fi
    
    # Verificar workflows
    if [ -d ".github/workflows" ]; then
        print_success "Diretório de workflows encontrado"
        
        if [ -f ".github/workflows/release-publish.yml" ]; then
            print_success "Workflow de release configurado"
        else
            print_warning "Workflow de release não encontrado"
        fi
        
        if [ -f ".github/workflows/ci.yml" ]; then
            print_success "Workflow de CI configurado"
        else
            print_warning "Workflow de CI não encontrado"
        fi
    else
        print_warning "Diretório de workflows não encontrado"
    fi
    
    # Verificar se há tags
    if git tag -l | grep -q .; then
        print_success "Tags existentes encontradas:"
        git tag -l | tail -5 | sed 's/^/    /'
    else
        print_info "Nenhuma tag encontrada (primeiro release)"
    fi
    
    echo ""
    
    if [ $has_errors -eq 0 ]; then
        print_success "Configuração OK!"
        return 0
    else
        print_error "Há problemas na configuração!"
        return 1
    fi
}

# Função para validar versão
validate_version() {
    local version=$1
    
    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9]+)?$ ]]; then
        print_error "Versão inválida: ${version}"
        print_info "Formato esperado: X.Y.Z ou X.Y.Z-suffix"
        print_info "Exemplos: 0.1.0, 1.2.3, 0.1.0-rc1, 1.0.0-beta"
        return 1
    fi
    
    return 0
}

# Função para criar release
create_release() {
    local version=$1
    local should_push=${2:-false}
    
    print_header "Criando Release v${version}"
    
    # Validar versão
    if ! validate_version "$version"; then
        exit 1
    fi
    
    # Verificar versão no pyproject.toml
    CURRENT_VERSION=$(grep '^version = ' pyproject.toml | cut -d'"' -f2)
    
    if [ "$version" != "$CURRENT_VERSION" ]; then
        print_error "Versão não corresponde ao pyproject.toml!"
        print_info "pyproject.toml: ${CURRENT_VERSION}"
        print_info "Solicitado: ${version}"
        echo ""
        read -p "Deseja atualizar o pyproject.toml? (y/N) " -n 1 -r
        echo ""
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Atualizar pyproject.toml
            if command -v sed &> /dev/null; then
                sed -i.bak "s/^version = .*/version = \"${version}\"/" pyproject.toml
                rm pyproject.toml.bak
                print_success "pyproject.toml atualizado"
                
                # Commit da mudança
                git add pyproject.toml
                git commit -m "chore: bump version to ${version}"
                print_success "Mudança commitada"
            else
                print_error "sed não disponível. Atualize manualmente."
                exit 1
            fi
        else
            print_error "Release cancelado"
            exit 1
        fi
    else
        print_success "Versão validada: ${version}"
    fi
    
    # Verificar se tag já existe
    if git rev-parse "v${version}" >/dev/null 2>&1; then
        print_error "Tag v${version} já existe!"
        print_info "Use 'git tag -d v${version}' para deletar localmente"
        exit 1
    fi
    
    # Criar tag
    TAG_NAME="v${version}"
    print_info "Criando tag ${TAG_NAME}..."
    
    # Gerar mensagem da tag
    TAG_MESSAGE="Release ${TAG_NAME}"
    
    git tag -a "$TAG_NAME" -m "$TAG_MESSAGE"
    print_success "Tag ${TAG_NAME} criada"
    
    # Push se solicitado
    if [ "$should_push" = true ]; then
        echo ""
        print_warning "Você está prestes a fazer push da tag ${TAG_NAME}"
        print_info "Isso irá triggar o workflow de release no GitHub!"
        echo ""
        read -p "Confirma o push? (y/N) " -n 1 -r
        echo ""
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git push origin "$TAG_NAME"
            print_success "Tag pushed para origin"
            
            echo ""
            print_header "✅ Release Iniciado!"
            echo ""
            print_info "Acompanhe o progresso em:"
            print_info "https://github.com/Pacalexandre/oidc_pure/actions"
            echo ""
            print_info "Após a conclusão, o pacote estará disponível em:"
            print_info "https://pypi.org/project/oidc_pure/${version}/"
        else
            print_warning "Push cancelado"
            print_info "Para fazer push manualmente:"
            echo "    git push origin ${TAG_NAME}"
        fi
    else
        echo ""
        print_success "Tag criada com sucesso!"
        echo ""
        print_info "Para fazer push e iniciar o release:"
        echo "    git push origin ${TAG_NAME}"
        echo ""
        print_info "Ou execute novamente com --push:"
        echo "    ./release.sh ${version} --push"
    fi
}

# Função para mostrar ajuda
show_help() {
    cat << EOF
Uso: ./release.sh [COMANDO]

COMANDOS:
    VERSION              Criar release para a versão especificada
    VERSION --push       Criar release e fazer push da tag
    --check              Verificar configuração atual
    --help               Mostrar esta ajuda

EXEMPLOS:
    ./release.sh 0.2.0           # Criar tag v0.2.0 localmente
    ./release.sh 0.2.0 --push    # Criar tag v0.2.0 e fazer push
    ./release.sh --check         # Verificar configuração

NOTAS:
    - A versão deve corresponder ao pyproject.toml
    - O formato esperado é X.Y.Z (ex: 0.1.0, 1.2.3)
    - O push da tag irá triggar o workflow de release no GitHub
    - O workflow irá publicar automaticamente no TestPyPI e PyPI

Para mais informações, consulte:
    .github/WORKFLOWS_GUIDE.md
EOF
}

# Main
main() {
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi
    
    case "$1" in
        --check)
            check_configuration
            ;;
        --help|-h)
            show_help
            ;;
        *)
            VERSION=$1
            SHOULD_PUSH=false
            
            if [ $# -eq 2 ] && [ "$2" = "--push" ]; then
                SHOULD_PUSH=true
            fi
            
            create_release "$VERSION" "$SHOULD_PUSH"
            ;;
    esac
}

main "$@"
