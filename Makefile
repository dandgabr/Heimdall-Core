# Heimdall Core — build, teste e empacotamento.
#
# Nada aqui depende de cgo: todo artefato é compilado com CGO_ENABLED=0, que é o
# que mantém o cross-compile amd64 -> arm64 em um único comando (ADR-001).
#
# Pipeline de CI reproduzido localmente:
#   make vet lint race cover-check vuln
# Release (linux/amd64 + linux/arm64):
#   make dist

SHELL := /bin/sh

GO      ?= go
BIN     ?= heimdall
CMD_PKG ?= ./cmd/heimdall

BIN_DIR  := bin
DIST_DIR := dist
COVERAGE := coverage.out

# Artefatos de integridade do release (F6, ADR-SEC-09).
SUMS_FILE ?= SHA256SUMS
SBOM_FILE ?= $(DIST_DIR)/sbom.cdx.json
# Ferramenta do SBOM. Padrão `cdxgomod`: roda o cyclonedx-gomod pinado via
# `go run` e é DETERMINÍSTICO (-noserial -notimestamp), então dist/SHA256SUMS é
# reproduzível. `syft` (opt-in) também é suportado e cobre os componentes NPM da
# SPA; `auto` usa o syft se estiver no PATH e cai para o cyclonedx-gomod.
SBOM_TOOL ?= cdxgomod

# Versão embutida no binário via -ldflags; derivada do git e sobrescrevível:
#   make dist VERSION=v0.1.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Símbolo que o produto expõe para injeção em tempo de link
# (internal/cli/cli.go: `var Version = "dev"`). Deliberadamente não emitimos a
# data do build: carimbá-la tornaria o binário irreprodutível bit-a-bit, que é
# requisito de release (F6).
#
# `-s -w` (ADR-SEC-09 §4.1) descarta tabela de símbolos e DWARF: o binário de
# release não precisa deles e o artefato fica menor. Não afeta a
# reprodutibilidade — ambos são derivados do mesmo input.
VERSION_PKG ?= github.com/dandgabr/heimdall-core/internal/cli

LDFLAGS := -s -w -X $(VERSION_PKG).Version=$(VERSION)

# Plataformas do alvo `dist`. Restringível para o job de matriz do CI:
#   make dist PLATFORMS="linux/arm64"
PLATFORMS ?= linux/amd64 linux/arm64

# Versões das ferramentas de análise, mantidas iguais às do
# .github/workflows/ci.yml para que o resultado local seja o mesmo do CI.
STATICCHECK_VERSION  ?= v0.8.1
GOVULNCHECK_VERSION  ?= v1.8.0

# Ferramentas do empacotamento de release (F6, ADR-SEC-09), pinadas na versão
# exata. O cyclonedx-gomod roda via `go run ...@versão`: sem binário externo
# pré-instalado e sem download não pinado — o que faz o job de release do CI
# funcionar só com o toolchain Go.
CYCLONEDX_GOMOD_VERSION ?= v1.12.0
# Versão recomendada do cosign; a instalação é manual (ver alvo `sign`).
COSIGN_VERSION          ?= v2.5.0

# Piso de cobertura global (percentual) exigido por `cover-check`.
# Medido em 2026-09-22: 100,0% em 20 pacotes (2680 instruções). O piso em 98 deixa
# ~2 pp de folga — cerca de 54 instruções: o bastante para caminhos de erro
# pontuais, e pouco o suficiente para que nenhum subsistema fique sem teste sem o
# pipeline acusar. Deve acompanhar a suíte; 99 é o próximo passo natural quando as
# suítes da fase estiverem completas.
COVER_MIN ?= 98

# --- GUI web embutida (F5.2b) -----------------------------------------------
#
# `web/` é um projeto Svelte/Vite que builda para `internal/webui/dist/`, o
# diretório que `//go:embed dist` embute no binário. O `dist/` buildado é
# COMMITADO, então `go build` funciona sem Node instalado; `make web` regenera
# o dist/ a partir do fonte quando a SPA muda.
#
# Gerenciador: pnpm (lockfile pnpm-lock.yaml). Sobrescreva com
# `make web PKG_MGR=npm` se o ambiente só tiver npm.
PKG_MGR ?= pnpm
WEB_DIR := web

# node_modules é pré-requisito só quando ausente: um build repetido não
# reinstala; `pnpm install` (ou npm install) é a fonte do lockfile.
NODE_MODULES := $(WEB_DIR)/node_modules

.PHONY: build test vet lint race cover cover-check vuln dist dist-verify sbom \
        sbom-check checksums checksums-verify sign release-check clean web \
        web-deps web-test

# build: compila o binário local em bin/ (estático, sem cgo).
# `-buildvcs=false` (ADR-SEC-09 §4.1): não injeta o pseudoversion do git
# (`v0.0.0-<timestamp>-<sha>+dirty`) nem `vcs.modified` no binário — ambos
# tornariam o build dependente do estado do working tree, não só do fonte.
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BIN) $(CMD_PKG)

# test: roda a suíte de testes
test:
	$(GO) test ./...

# vet: análise estática do toolchain
vet:
	$(GO) vet ./...

# lint: staticcheck; a configuração vem de staticcheck.conf na raiz do módulo.
#
# Roda via `go run <módulo>@<versão>` em vez de exigir o binário no PATH: assim o
# alvo funciona numa máquina limpa (sem `go install` prévio) e continua pinado na
# MESMA versão que o CI usa. O CI instala o binário e roda `staticcheck` direto,
# então o gate remoto segue estrito — este alvo apenas deixa de ser um bloqueio
# artificial no ambiente local. O download do módulo exige rede na primeira vez e
# depois fica em cache. A receita não define GOFLAGS nem depende de vendor/.
lint:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

# race: testes sob o detector de corrida
race:
	$(GO) test -race ./...

# cover: testes com cobertura (-covermode=atomic é obrigatório sob -race)
cover:
	$(GO) test -race -covermode=atomic -coverprofile=$(COVERAGE) ./...
	$(GO) tool cover -func=$(COVERAGE) | tail -n 1

# cover-check: roda `cover` e falha se a cobertura global ficar abaixo de
# COVER_MIN%. O total sai da última linha do relatório por função, que já é o
# agregado de todos os pacotes do perfil.
cover-check: cover
	@total=$$($(GO) tool cover -func=$(COVERAGE) | awk '/^total:/ { gsub(/%/, "", $$NF); print $$NF }'); \
	if [ -z "$$total" ]; then \
		echo "cover-check: não foi possível extrair o total de $(COVERAGE)"; \
		exit 1; \
	fi; \
	echo "cover-check: cobertura total $$total% (piso $(COVER_MIN)%)"; \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { \
		if (t + 0 < m + 0) { \
			printf "cover-check: FALHOU — %.1f%% abaixo do piso de %s%%\n", t, m; \
			exit 1; \
		} \
		printf "cover-check: OK — %.1f%% >= %s%%\n", t, m; \
	}'

# vuln: govulncheck sobre o grafo de módulos
vuln:
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "govulncheck não está no PATH."; \
		echo "instale com: go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)"; \
		exit 1; \
	}
	govulncheck ./...

# dist: cross-compila para cada plataforma de PLATFORMS e nomeia o artefato com
# versão, OS e arquitetura (dist/heimdall-<versão>-<os>-<arch>).
#
# Flags de reprodutibilidade (ADR-SEC-09 §4): `-trimpath` remove caminhos
# absolutos do host; `-buildvcs=false` remove o pseudoversion/timestamp do git e
# o flag `vcs.modified`; `-s -w` vem do LDFLAGS. Compilação estática
# (CGO_ENABLED=0) e sem carimbo de data. Para que dois builds coincidam, a versão
# precisa ser fixada (`make dist VERSION=v1.0.0`) — ela é embutida no binário.
dist:
	@mkdir -p $(DIST_DIR)
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=$(DIST_DIR)/$(BIN)-$(VERSION)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then out="$$out.exe"; fi; \
		echo "==> $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o "$$out" $(CMD_PKG); \
	done
	@echo "artefatos:"
	@ls -l $(DIST_DIR)

# clean: remove artefatos de build, dist e cobertura
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR) $(COVERAGE)

# web-deps: instala as dependências da SPA (idempotente).
web-deps: $(NODE_MODULES)

$(NODE_MODULES): $(WEB_DIR)/package.json $(WEB_DIR)/pnpm-lock.yaml
	cd $(WEB_DIR) && $(PKG_MGR) install

# web: builda a SPA para internal/webui/dist/ (o diretório embutido pelo Go).
# Sem Node, `go build` continua funcionando com o dist/ commitado.
web: $(NODE_MODULES)
	cd $(WEB_DIR) && $(PKG_MGR) run build

# web-test: testes de contrato da SPA (Node test runner, sem DOM).
web-test: $(NODE_MODULES)
	cd $(WEB_DIR) && $(PKG_MGR) test

# ============================================================================
# Release, integridade e cadeia de suprimentos (F6 — ADR-SEC-09)
# ============================================================================
#
# Fluxo de um release:
#   make release-check   # gates + binários + SBOM + checksums + verificação
#   make sign            # assinatura cosign (keyless) — se o cosign existir
#
# dist/ recebe os binários da matriz PLATFORMS, o SBOM CycloneDX
# (dist/sbom.cdx.json) e o manifesto dist/SHA256SUMS.

# dist-verify: prova de reprodutibilidade bit-a-bit (ADR-SEC-09 §4.4).
# Copia o fonte para DOIS diretórios limpos (sem .git, dist, bin e node_modules)
# e roda `make dist` em cada um com a MESMA VERSION; se os SHA-256 dos binários
# coincidirem, o build é reprodutível. As cópias não têm .git, então o alvo
# também prova que o build não depende de metadados de VCS.
dist-verify:
	@set -eu; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	for c in 1 2; do \
		mkdir -p "$$tmp/$$c"; \
		tar --exclude='./.git' --exclude='./.maestri' --exclude='./.commandcode' \
		    --exclude='./$(DIST_DIR)' --exclude='./$(BIN_DIR)' \
		    --exclude='./$(WEB_DIR)/node_modules' \
		    -cf - . | tar -C "$$tmp/$$c" -xf -; \
		echo "==> cópia $$c: make dist VERSION=$(VERSION)"; \
		$(MAKE) --no-print-directory -C "$$tmp/$$c" dist \
			VERSION="$(VERSION)" PLATFORMS="$(PLATFORMS)" >/dev/null; \
		( cd "$$tmp/$$c/$(DIST_DIR)" && sha256sum $(BIN)-$(VERSION)-* ) \
			| awk '{ print $$1 "  " $$2 }' | sort -k2 > "$$tmp/$$c.sums"; \
	done; \
	echo "--- SHA-256 cópia 1 ---"; cat "$$tmp/1.sums"; \
	echo "--- SHA-256 cópia 2 ---"; cat "$$tmp/2.sums"; \
	if diff -u "$$tmp/1.sums" "$$tmp/2.sums"; then \
		echo "dist-verify: OK — dois builds limpos produziram hashes idênticos"; \
	else \
		echo "dist-verify: FALHOU — os binários divergem"; exit 1; \
	fi

# sbom: gera o SBOM CycloneDX 1.6 em dist/sbom.cdx.json.
#
# Padrão `SBOM_TOOL=cdxgomod`: o cyclonedx-gomod pinado roda por
# `go run ...@versão` — pinado a uma versão exata de módulo e servido pelo
# toolchain que o CI já tem, sem instalar binário externo por `curl | sh` (risco
# de supply chain) nem depender de ferramenta não pinada. Com `-noserial
# -notimestamp` a saída é determinística, o que mantém dist/SHA256SUMS estável.
# `SBOM_TOOL=syft` usa o syft (se instalado) e inclui também os componentes NPM
# da SPA; `auto` prefere o syft e cai para o cyclonedx-gomod. Os três caminhos
# produzem CycloneDX válido listando todos os `require` do go.mod.
sbom:
	@mkdir -p $(DIST_DIR); \
	set -eu; \
	tool="$(SBOM_TOOL)"; \
	if [ "$$tool" = "auto" ]; then \
		if command -v syft >/dev/null 2>&1; then tool=syft; else tool=cdxgomod; fi; \
	fi; \
	case "$$tool" in \
	syft) \
		echo "sbom: syft $$(syft version 2>/dev/null | awk '/^Version:/{print $$2}')"; \
		syft scan dir:. \
			--exclude ./$(WEB_DIR)/node_modules \
			--exclude ./$(DIST_DIR) --exclude ./$(BIN_DIR) \
			--source-name $(BIN) --source-version $(VERSION) \
			-o "cyclonedx-json@1.6=$(SBOM_FILE)" -q ;; \
	cdxgomod) \
		echo "sbom: cyclonedx-gomod $(CYCLONEDX_GOMOD_VERSION) via 'go run' (pinado)"; \
		$(GO) run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_GOMOD_VERSION) \
			mod -json -output-version 1.6 -noserial -notimestamp -std \
			-type application -output $(SBOM_FILE) . ;; \
	*) \
		echo "sbom: SBOM_TOOL inválido: $$tool (use auto | syft | cdxgomod)"; exit 1 ;; \
	esac; \
	echo "sbom: $(SBOM_FILE)"

# sbom-check: valida o SBOM — JSON bem-formado, CycloneDX, com componentes e
# cobrindo todos os `require` do go.mod (ADR-SEC-09 §7.4).
sbom-check:
	@test -f $(SBOM_FILE) || { echo "sbom-check: $(SBOM_FILE) ausente — rode 'make sbom'"; exit 1; }
	@scripts/sbom-check.sh $(SBOM_FILE)

# checksums: manifesto SHA-256 dos binários e do SBOM (dist/SHA256SUMS).
checksums: dist sbom
	@cd $(DIST_DIR) && sha256sum $(BIN)-$(VERSION)-* $(notdir $(SBOM_FILE)) > $(SUMS_FILE)
	@echo "checksums: $(DIST_DIR)/$(SUMS_FILE)"
	@cat $(DIST_DIR)/$(SUMS_FILE)

# checksums-verify: recalcula e confere o manifesto JÁ existente contra os
# arquivos em dist/ (falha se algo divergir). Não regenera nada — se dependesse
# de `checksums` reescreveria o manifesto antes de conferir e a verificação não
# valeria nada.
checksums-verify:
	@test -f $(DIST_DIR)/$(SUMS_FILE) || { echo "checksums-verify: $(DIST_DIR)/$(SUMS_FILE) ausente — rode 'make checksums'"; exit 1; }
	@cd $(DIST_DIR) && sha256sum -c $(SUMS_FILE)

# sign: assinatura criptográfica do manifesto com cosign (keyless/OIDC,
# ADR-SEC-09 §3.2). Se o cosign não estiver instalado o alvo NÃO falha: imprime
# o comando de assinatura e o de verificação e segue. A ausência de assinatura
# em ambiente offline é dívida aceita (D-SEC-09-01, docs/SECURITY-DEBT.md).
# Assina o manifesto existente — não o regenera — para que a assinatura
# corresponda exatamente ao que `checksums-verify` validou.
sign:
	@test -f $(DIST_DIR)/$(SUMS_FILE) || { echo "sign: $(DIST_DIR)/$(SUMS_FILE) ausente — rode 'make checksums'"; exit 1; }
	@if command -v cosign >/dev/null 2>&1; then \
		echo "sign: cosign encontrado — assinatura keyless de $(DIST_DIR)/$(SUMS_FILE)"; \
		cosign sign-blob --yes \
			--output-signature $(DIST_DIR)/$(SUMS_FILE).sig \
			--output-certificate $(DIST_DIR)/$(SUMS_FILE).pem \
			$(DIST_DIR)/$(SUMS_FILE); \
		echo "sign: gerados $(SUMS_FILE).sig e $(SUMS_FILE).pem"; \
	else \
		echo "sign: cosign ausente — assinatura PULADA (o build NÃO falha)."; \
		echo "      Dívida registrada: D-SEC-09-01 em docs/SECURITY-DEBT.md."; \
		echo "      Para assinar: instale cosign $(COSIGN_VERSION) e rode 'make sign'."; \
		echo "      Verificação pelo operador (no release assinado):"; \
		echo "        cosign verify-blob \\"; \
		echo "          --certificate $(SUMS_FILE).pem --signature $(SUMS_FILE).sig \\"; \
		echo "          --certificate-identity-regexp '^https://github.com/dandgabr/heimdall-core/' \\"; \
		echo "          --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\"; \
		echo "          $(DIST_DIR)/$(SUMS_FILE)"; \
		echo "        sha256sum -c $(DIST_DIR)/$(SUMS_FILE)"; \
	fi

# release-check: gate de release completo — gates de qualidade + binários
# reprodutíveis + SBOM + checksums + verificação. Qualquer ausência derruba o
# alvo (ADR-SEC-09 §5.2).
release-check: vet lint cover-check vuln dist dist-verify sbom checksums checksums-verify sbom-check
	@echo "release-check: OK — gates, binários reprodutíveis, SBOM e checksums verificados"
