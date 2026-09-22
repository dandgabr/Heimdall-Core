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

# Versão embutida no binário via -ldflags; derivada do git e sobrescrevível:
#   make dist VERSION=v0.1.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Símbolo que o produto expõe para injeção em tempo de link
# (internal/cli/cli.go: `var Version = "dev"`). Deliberadamente não emitimos a
# data do build: carimbá-la tornaria o binário irreprodutível bit-a-bit, que é
# requisito de release (F6).
VERSION_PKG ?= github.com/dandgabr/heimdall-core/internal/cli

LDFLAGS := -X $(VERSION_PKG).Version=$(VERSION)

# Plataformas do alvo `dist`. Restringível para o job de matriz do CI:
#   make dist PLATFORMS="linux/arm64"
PLATFORMS ?= linux/amd64 linux/arm64

# Versões das ferramentas de análise, mantidas iguais às do
# .github/workflows/ci.yml para que o resultado local seja o mesmo do CI.
STATICCHECK_VERSION  ?= v0.8.1
GOVULNCHECK_VERSION  ?= v1.8.0

# Piso de cobertura global (percentual) exigido por `cover-check`.
# Medido em 2026-09-21: 74,3%. O piso fica 4,3 pontos abaixo: folga para o código
# crescer mais rápido que os testes, sem deixar a cobertura erodir em silêncio.
# Deve subir junto com a suíte.
COVER_MIN ?= 70

.PHONY: build test vet lint race cover cover-check vuln dist clean

# build: compila o binário local em bin/ (estático, sem cgo)
build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BIN) $(CMD_PKG)

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
# artificial no ambiente local. O download do módulo exige rede na primeira vez;
# `GOFLAGS=-mod=mod` evita que um vendor/ ausente quebre a execução.
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
# versão, OS e arquitetura (dist/heimdall-<versão>-<os>-<arch>)
dist:
	@mkdir -p $(DIST_DIR)
	@set -e; for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=$(DIST_DIR)/$(BIN)-$(VERSION)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then out="$$out.exe"; fi; \
		echo "==> $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o "$$out" $(CMD_PKG); \
	done
	@echo "artefatos:"
	@ls -l $(DIST_DIR)

# clean: remove artefatos de build, dist e cobertura
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR) $(COVERAGE)
