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

Versões das ferramentas de análise pinadas em `STATICCHECK_VERSION` e
`GOVULNCHECK_VERSION` (as mesmas do CI). O staticcheck não precisa de instalação —
`make lint` o executa via `go run` na versão pinada. Só o `govulncheck` precisa
estar no PATH, instalado uma vez:

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
```

Se a versão instalada divergir da pinada, o resultado local deixa de representar
o do pipeline.

| Alvo | O que faz |
| --- | --- |
| `build` | compila `./cmd/heimdall` em `bin/` |
| `test` | `go test ./...` |
| `vet` | `go vet ./...` |
| `lint` | staticcheck via `go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)` (usa a `staticcheck.conf` da raiz) |
| `race` | `go test -race ./...` |
| `cover` | `go test -race -covermode=atomic -coverprofile=coverage.out ./...` + resumo |
| `cover-check` | como `cover`, mas falha se o total ficar abaixo de `COVER_MIN` (padrão 98%) |
| `vuln` | `govulncheck ./...` |
| `web` | builda a SPA Svelte em `internal/webui/dist/` (requer Node/pnpm) |
| `web-test` | testes de contrato da SPA (`node --test`) |
| `dist` | cross-compile estático para `PLATFORMS` |
| `clean` | remove `bin/`, `dist/` e `coverage.out` |

Para reproduzir o pipeline do CI (`.github/workflows/ci.yml`) do começo ao fim:

```sh
make vet lint race cover-check vuln
```

### GUI web embutida (F5.2b)

A Management API é consumida por uma SPA Svelte embutida no próprio binário
(`internal/webui`, via `//go:embed dist`). **Não há Tauri/Wails nem runtime
extra**: o `net/http` serve os assets e a mesma porta/loopback do gateway
(ADR-002). A SPA é servida em `http://127.0.0.1:8787/web/` e cobre Status,
Provedores, Credenciais, Combos, Cotas, Gates, Uso, Token de gestão e Chaves de
cliente, com i18n `pt-BR`/`en` (os `code` de erro do backend são traduzidos
pelos mesmos catálogos que o servidor embute).

- **Autenticação:** a SPA envia o token de gestão no header
  `Authorization: Bearer <token>` (nunca cookie, nunca query); o token fica em
  memória/sessão do navegador e é revalidado no boot. CORS fechado; a SPA só
  chama a própria origem.
- **Build:** o `dist/` buildado é **commitado**, então `go build`/`make build`
  funciona numa máquina sem Node. Para regenerar após mudar a SPA:

  ```sh
  make web          # pnpm install + build em web/ -> internal/webui/dist/
  make web-test     # testes de contrato da SPA
  ```

  O gerenciador padrão é `pnpm` (`make web PKG_MGR=npm` se o ambiente só tiver
  npm). O código-fonte fica em `web/` (Svelte 5 + Vite).

### Estado atual

Medido em 2026-09-22: `make build`, `make vet`, `make lint`, `make test`,
`make race`, `make cover` (total **100,0%**, exato e não arredondado: **0 blocos
descobertos** nas 2680 instruções dos 20 pacotes, com 644 testes),
`make vuln` e `make dist` (linux/amd64 + linux/arm64) passam.

O CI **bloqueia** o merge: nenhuma etapa usa `continue-on-error`, e
`make cover-check` derruba o run se a cobertura global cair abaixo do
`COVER_MIN`. O piso está em 98% e não descreve a cobertura de hoje: 1 pp vale
~27 instruções, então o piso tolera ~54 instruções descobertas — folga para
caminhos de erro que ainda vão aparecer, sem que nenhum subsistema fique sem
teste em silêncio. Deve acompanhar a suíte; 99% é o próximo passo natural
conforme as novas fases entrarem.

### Segurança

As dívidas de segurança conhecidas, com status, impacto e gatilho de resolução,
ficam em [`docs/SECURITY-DEBT.md`](docs/SECURITY-DEBT.md). O item **aberto** hoje
é o **P1-6** (anti-DNS-rebinding/CSRF da Management API e autenticação de cliente
em `/v1/*`), que bloqueia a F5 (ADR-SEC-06) e qualquer exposição do gateway além
do uso local; a mitigação vigente é bind loopback + token de gestão + catch-all.
