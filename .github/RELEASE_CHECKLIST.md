# Release Checklist v0.1.0

## 📋 Pré-Release (Antes de criar a tag)

### Configuração Inicial (Fazer uma vez)
- [x] Criar conta no [PyPI](https://pypi.org/account/register/)
- [x] Criar conta no [TestPyPI](https://test.pypi.org/account/register/)
- [x] Gerar [API Token no PyPI](https://pypi.org/manage/account/token/)
- [x] Gerar [API Token no TestPyPI](https://test.pypi.org/manage/account/token/)
- [x] Adicionar `PYPI_API_TOKEN` nos [GitHub Secrets](https://github.com/Pacalexandre/oidc_pure/settings/secrets/actions)
- [x] Adicionar `TEST_PYPI_API_TOKEN` nos GitHub Secrets
- [x] Configurar environments no GitHub (opcional)
- [x] (Opcional) Configurar [Codecov](https://codecov.io/) e adicionar token

### Preparação do Código
- [x] Todos os testes estão passando localmente (`pytest`)
- [x] Código formatado com ruff (`ruff format .`)
- [ ] Lint sem erros (`ruff check .`)
- [x] Auditoria de segurança OK (`./security_audit.sh`)
- [x] Exemplos testados e funcionando
- [x] Documentação atualizada (README.md, docstrings)

### Preparação da Versão
- [x] Decidir número da versão seguindo [SemVer](https://semver.org/)
  - **Patch** (0.1.X): Bug fixes, pequenas correções
  - **Minor** (0.X.0): Novas features, compatível com versão anterior
  - **Major** (X.0.0): Breaking changes
- [x] Atualizar versão no `pyproject.toml`
- [x] Atualizar `__version__` em `oidc_pure/__init__.py` (se diferente)
- [x] Criar/atualizar `CHANGELOG.md` com as mudanças da versão
- [ ] Verificar e atualizar dependências se necessário

### Validação Local
- [x] Build local bem-sucedido (`./build_package.sh`)
- [x] Instalação local testada (`pip install dist/*.whl`)
- [x] Imports funcionando (`python -c "import oidc_pure"`)
- [ ] Testar examples/ com a versão local
- [ ] Verificar metadados do pacote (`pip show oidc_pure`)

### Git e GitHub
- [x] Branch está atualizada com `main`
- [ ] Não há commits pendentes
- [ ] Não há conflitos
- [ ] Todos os workflows estão passando no GitHub Actions

---

## 🚀 Release (Criação da tag)

### Criar Release Localmente
```bash
# Método 1: Usando script auxiliar (recomendado)
./release.sh 0.1.0 --push

# Método 2: Manual
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### Checklist de Criação
- [ ] Tag criada no formato correto `v0.1.0`
- [ ] Tag pushed para o repositório remoto
- [ ] Workflow trigado no GitHub Actions

---

## 🔍 Pós-Release (Monitoramento)

### GitHub Actions
- [ ] Workflow `Release and Publish` iniciado
- [ ] Job `validate-version` passou
- [ ] Job `build-and-test` passou
- [ ] Job `create-github-release` passou
- [ ] Release criado no GitHub
- [ ] Job `publish-to-testpypi` passou

### Validação TestPyPI
- [ ] Pacote visível no [TestPyPI](https://test.pypi.org/project/oidc_pure/)
- [ ] Metadados corretos (descrição, autor, links)
- [ ] README renderizado corretamente
- [ ] Testar instalação do TestPyPI:
  ```bash
  pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ oidc_pure
  ```

### Aprovação para PyPI (se configurado)
- [ ] Revisar logs do TestPyPI
- [ ] Aprovar deployment para PyPI no GitHub
- [ ] Job `publish-to-pypi` passou

### Validação PyPI (Produção)
- [ ] Pacote visível no [PyPI](https://pypi.org/project/oidc_pure/)
- [ ] Metadados corretos
- [ ] README renderizado corretamente
- [ ] Testar instalação do PyPI:
  ```bash
  pip install oidc_pure==0.1.0
  ```
- [ ] Testar import:
  ```bash
  python -c "import oidc_pure; print(oidc_pure.__version__)"
  ```

### GitHub Release
- [ ] Release notes geradas corretamente
- [ ] Assets (wheel e tar.gz) anexados
- [ ] Links funcionando
- [ ] Marcado como pre-release se for alpha/beta/rc

---

## 📢 Pós-Publicação

### Comunicação
- [ ] Atualizar README.md com badges (se primeira release)
- [ ] Anunciar release (se aplicável)
- [ ] Atualizar documentação externa (se houver)
- [ ] Notificar usuários (se aplicável)

### Badges para Adicionar ao README.md (Primeiro Release)
```markdown
[![PyPI version](https://img.shields.io/pypi/v/oidc_pure)](https://pypi.org/project/oidc_pure/)
[![Python versions](https://img.shields.io/pypi/pyversions/oidc_pure)](https://pypi.org/project/oidc_pure/)
[![License](https://img.shields.io/github/license/Pacalexandre/oidc_pure)](https://github.com/Pacalexandre/oidc_pure/blob/main/LICENSE)
[![CI](https://github.com/Pacalexandre/oidc_pure/workflows/CI%20-%20Tests%20and%20Validation/badge.svg)](https://github.com/Pacalexandre/oidc_pure/actions)
[![Security](https://github.com/Pacalexandre/oidc_pure/workflows/Security%20Audit/badge.svg)](https://github.com/Pacalexandre/oidc_pure/actions)
[![codecov](https://codecov.io/gh/Pacalexandre/oidc_pure/branch/main/graph/badge.svg)](https://codecov.io/gh/Pacalexandre/oidc_pure)
```

### Verificação Final
- [ ] Instalação clean em ambiente novo testada
- [ ] Documentação de instalação atualizada
- [ ] Issues relacionadas fechadas/atualizadas
- [ ] Milestone da versão fechada (se usar)

---

## 🔄 Próxima Versão

### Preparação para Próximo Ciclo
- [ ] Criar branch `develop` para próxima versão (se não existir)
- [ ] Incrementar versão no `pyproject.toml` para próximo ciclo (ex: 0.1.0 → 0.2.0-dev)
- [ ] Criar milestone para próxima versão
- [ ] Planejar features/fixes para próxima release

---

## ⚠️ Troubleshooting

### Se algo der errado:

#### Release no GitHub falhou
```bash
# Deletar tag localmente
git tag -d v0.1.0

# Deletar tag remotamente
git push origin :refs/tags/v0.1.0

# Corrigir o problema e recriar
```

#### Versão publicada com erro no PyPI
⚠️ **IMPORTANTE**: PyPI não permite republicar uma mesma versão!

Opções:
1. Publicar uma versão patch (ex: 0.1.0 → 0.1.1)
2. Marcar como yanked no PyPI (não recomendado)
3. Contactar suporte do PyPI em casos extremos

#### Workflow não trigou
```bash
# Verificar se a tag foi criada
git tag -l

# Verificar se foi pushed
git ls-remote --tags origin

# Re-push se necessário
git push origin v0.1.0
```

---

## 📞 Recursos

- [Guia de Workflows](.github/WORKFLOWS_GUIDE.md)
- [Semantic Versioning](https://semver.org/)
- [Python Packaging Guide](https://packaging.python.org/)
- [GitHub Actions - Python Publishing](https://docs.github.com/en/actions/automating-builds-and-tests/building-and-testing-python)

---

**Data do Template**: Fevereiro 2026  
**Versão**: 0.1.0
