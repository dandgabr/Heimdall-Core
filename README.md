# Heimdall-Core
Heimdall Core is an open-source routing and proxy engine built for community-driven, transparent traffic management. Inspired by the vigilant guardian of the Bifröst, it offers robust edge inspection, deterministic routing, and open collaboration, ensuring free, secure, and verifiable access control for everyone.

## Build local

Requisitos: Go **1.27.1** (`go version`), `git` e `make`. Nenhum passo exige cgo —
todo artefato é compilado com `CGO_ENABLED=0`, que é o que sustenta o
cross-compile amd64 → arm64 em um único comando.

```sh
make build     # bin/heimdall (estático, sem cgo)
make dist      # dist/heimdall-<versão>-<os>-<arch> para linux/amd64 e linux/arm64
```

`VERSION` vem de `git describe --tags --always --dirty`, então cada artefato
carrega a versão de origem no próprio nome. Pode ser sobrescrita:
`make dist VERSION=v0.1.0`. `BIN`, `CMD_PKG`, `VERSION_PKG`, `COVER_MIN` e
`PLATFORMS` seguem a mesma regra (`make dist PLATFORMS="linux/arm64"`).

A versão é injetada no símbolo que o produto expõe para isso
(`internal/cli.Version`, ver `internal/cli/cli.go`), via
`-ldflags "-X <VERSION_PKG>.Version=<VERSION>"`. A data do build não é embutida
de propósito: carimbá-la tornaria o binário irreprodutível bit-a-bit.

Ferramentas de análise (instale uma vez; ficam em `$(go env GOPATH)/bin`). As
versões abaixo são as mesmas pinadas no Makefile e no CI — se divergirem, o
resultado local deixa de representar o do pipeline:

```sh
go install honnef.co/go/tools/cmd/staticcheck@v0.8.1
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
```

| Alvo | O que faz |
| --- | --- |
| `build` | compila `./cmd/heimdall` em `bin/` |
| `test` | `go test ./...` |
| `vet` | `go vet ./...` |
| `lint` | `staticcheck ./...` (usa a `staticcheck.conf` da raiz) |
| `race` | `go test -race ./...` |
| `cover` | `go test -race -covermode=atomic -coverprofile=coverage.out ./...` + resumo |
| `cover-check` | como `cover`, mas falha se o total ficar abaixo de `COVER_MIN` (padrão 70%) |
| `vuln` | `govulncheck ./...` |
| `dist` | cross-compile estático para `PLATFORMS` |
| `clean` | remove `bin/`, `dist/` e `coverage.out` |

Para reproduzir o pipeline do CI (`.github/workflows/ci.yml`) do começo ao fim:

```sh
make vet lint race cover-check vuln
```

### Estado atual

Medido em 2026-09-22: `make build`, `make vet`, `make lint`, `make test`,
`make race`, `make cover` (total **74,3%**), `make vuln` e `make dist`
(linux/amd64 + linux/arm64) passam.

O CI **bloqueia** o merge: nenhuma etapa usa `continue-on-error`, e
`make cover-check` derruba o run se a cobertura global cair abaixo do
`COVER_MIN`. O piso está em 70% — 4,3 pontos abaixo dos 74,3% medidos: folga
para o código crescer mais rápido que os testes, sem deixar a cobertura erodir
em silêncio. Deve subir junto com a suíte.

### Segurança

As dívidas de segurança conhecidas, com status, impacto e gatilho de resolução,
ficam em [`docs/SECURITY-DEBT.md`](docs/SECURITY-DEBT.md). O item **aberto** hoje
é o **P1-6** (anti-DNS-rebinding/CSRF da Management API e autenticação de cliente
em `/v1/*`), que bloqueia a F5 (ADR-SEC-06) e qualquer exposição do gateway além
do uso local; a mitigação vigente é bind loopback + token de gestão + catch-all.
