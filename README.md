# Heimdall-Core

Roteador local multi-provedor de LLM. Um binário Go, estático (sem cgo), que
fala a **API OpenAI-compatible** na frente e fala os dialetos dos provedores
atrás — com **gates plugáveis** (memória, economia de token, segurança) e
**combos** nomeados de roteamento. A ideia é simples: seus clientes OpenAI
apontam para `http://127.0.0.1:8787/v1`, e o Heimdall decide para qual
provedor/conta a requisição vai, aplica suas políticas e registra o uso.

Guarda as credenciais num **cofre cifrado** (AES-256-GCM, envelope DEK/KEK),
serve uma **GUI web embutida** em `/web/` e não sai de loopback por padrão.
Nada de servidor externo, nada de conta na nuvem: é um daemon local.

> Leia também [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (como as peças se
> encaixam), [`docs/PROVIDERS.md`](docs/PROVIDERS.md) (catálogo e como adicionar
> provedores), [`docs/GATES.md`](docs/GATES.md) (catálogo e como escrever um
> gate) e [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) (fronteiras de
> confiança e riscos).

## Estado atual (F0–F6)

O projeto foi construído em fases (F0..F6). O que **funciona hoje**, verificado
contra o commit `4a68b7e`:

| Área | Estado |
| --- | --- |
| Núcleo Go, config TOML, SQLite WAL, i18n `pt-BR`/`en`, redator central | **Pronto** (F0) |
| Cofre cifrado, providers, `AuthFlow` (device code / PKCE / API key) | **Pronto** (F1) |
| Executors, tradutores (OpenAI↔Anthropic↔Gemini) e streaming SSE | **Pronto** (F2) |
| Router (10 estratégias), combos como DAG, cotas, breaker, `Dispatcher` | **Pronto** (F3) |
| Gates: logger, token, memória, segurança + DAG de gates | **Pronto** (F4) |
| GUI Svelte embutida, CLI completa, auth de cliente em `/v1/*` | **Pronto** (F5) |
| Cross-compile reprodutível, SBOM CycloneDX, checksums, gate de release | **Pronto** (F6) |

O que **não** funciona nesta build, dito sem rodeio:

- **Antigravity** (Google CloudCode) é um provedor `future`: o conector e a
  ocultação existem e são testados, mas não há login OAuth interativo nem wiring
  no roteador ainda. `heimdall provider list` o mostra como `future`.
- **Busca vetorial da memória (`vec0`) não existe.** O driver
  `modernc.org/sqlite v1.59.0` não expõe a extensão `vec0`, então o gate de
  memória é **FTS5-only** (retrieval lexical). É a dívida **M-1** em
  [`docs/SECURITY-DEBT.md`](docs/SECURITY-DEBT.md); o modo vetorial degrada para
  FTS5 sem falhar o boot.
- **`heimdall login` não existe.** Provedores OAuth dependem de um fluxo que
  ainda não tem superfície na CLI; hoje só os provedores por API key
  (`z.ai`, `ollama-cloud`, `command-code`) são utilizáveis de ponta a ponta.
- **`GET /v1/models` devolve uma lista vazia.** A rota existe e responde no
  envelope OpenAI, mas o catálogo servido por ela ainda não é populado a partir
  do registry.

### Medições desta build

Verificado em 2026-09-23, commit `4a68b7e`:

- `go build` e `go vet` OK;
- `go test -race -covermode=atomic ./...` — **35 pacotes**, 0 falhas, 0 corridas;
- cobertura **100,0%** exata — **6.586 blocos, 0 com contagem zero**, 9.990
  instruções; 1.829 funções `Test`;
- `make lint`, `make cover-check` e `make dist` (linux/amd64 + linux/arm64) OK.

## Quick start

Requisitos: Go **1.27.1** (`go version`), `git` e `make`. Nenhum passo exige
cgo — todo artefato é compilado com `CGO_ENABLED=0`, que é o que sustenta o
cross-compile amd64 → arm64 em um único comando.

```sh
make build                 # bin/heimdall (estático, sem cgo)
./bin/heimdall serve       # sobe o gateway em http://127.0.0.1:8787
```

Na primeira execução o Heimdall gera um **token de gestão** e o escreve em
`$XDG_DATA_HOME/heimdall/management-token` (modo `0600`). No mesmo diretório
fica o banco (`heimdall.db`). O caminho do cofre segue `XDG_DATA_HOME`
(`~/.local/share` por padrão).

Fluxo mínimo de uso:

```sh
# 1. cadastre uma chave de provedor (a chave é lida do stdin, nunca de argv)
printf '%s' "$ZAI_API_KEY" | ./bin/heimdall provider add-key z.ai --label work

# 2. confira que o provedor ficou pronto
./bin/heimdall provider status

# 3. (opcional) um combo nomeado sobre dois provedores
./bin/heimdall combo create fast model:glm-4.6 provider:z.ai --strategy fallback

# 4. aponte qualquer cliente OpenAI para o gateway
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
```

A GUI fica em **`http://127.0.0.1:8787/web/`** — Status, Provedores,
Credenciais, Combos, Cotas, Gates, Uso, Token de gestão e Chaves de cliente,
com i18n `pt-BR`/`en`. A SPA envia o token de gestão no header
`Authorization: Bearer <token>` (nunca cookie, nunca query string).

### Configuração mínima

A config é **TOML**, opcional: sem arquivo, os padrões embutidos valem. A
seleção do arquivo é `--config` > `HEIMDALL_CONFIG` > `heimdall.toml` >
`config.toml`, no diretório corrente. A precedência de valores é
**env > flag > arquivo > default**.

```toml
config_version = 1

[server]
host = "127.0.0.1"
port = 8787
# allow_remote = true   # obrigatório para bind fora de loopback

[features.gates]
token    = true
memory   = true
security = true

[[providers]]
id         = "z.ai"
base_url   = "https://api.z.ai/api/paas/v4"
enabled    = true
models     = ["glm-4.6"]
```

Para inspecionar o que a resolução produziu, com a origem de cada campo e sem
vazar segredo:

```sh
./bin/heimdall config show      # key <TAB> value <TAB> default|file|flag|env
./bin/heimdall config validate  # erro por `code` i18n
./bin/heimdall config path      # qual arquivo está em vigor
```

Comportamento real de `config path` (medido): ele **imprime o caminho
selecionado** — um `--config <arquivo>` explícito (ou `HEIMDALL_CONFIG`) é
reportado como "em vigor" mesmo que o arquivo não exista, e a saída é rc=0.
Somente quando **nenhum** arquivo é encontrado (nem explícito, nem
`HEIMDALL_CONFIG`, nem os nomes padrão `heimdall.toml`/`config.toml`) é que ele
imprime o aviso "Nenhum arquivo de configuração encontrado; os padrões embutidos
estão em vigor" e sai com **rc=1**. Para saber se o arquivo existe de fato,
use `heimdall config validate`, que falha com `config.load_failed` se o caminho
explícito não puder ser lido.

## Comandos da CLI

```
heimdall [command]

  serve        Sobe o gateway e a Management API
  version      Imprime a versão
  token        Gestão do token de gestão (rotate)
  client-key   Chaves de cliente para o gateway de inferência (create/list/revoke)
  provider     Inspeção e importação de credenciais
  combo        Criação, listagem e remoção de combos nomeados
  quota        Inspeção das janelas de cota por credencial
  gate         Inspeção da cadeia efetiva de gates (ordem do DAG, estágios, políticas)
  config       Inspeção e validação da configuração efetiva
```

Detalhe dos subcomandos (todos aceitam `--config`):

| Comando | O que faz |
| --- | --- |
| `serve [--host] [--port] [--allow-remote] [--config]` | Sobe o listener. `--allow-remote` é obrigatório para qualquer bind que não seja loopback (`127.0.0.1`, `localhost`, `::1`). |
| `version` | Imprime `internal/cli.Version` (injetada no link). |
| `token rotate` | Emite um token de gestão novo, persiste só o hash e grava o texto puro no arquivo `0600`. Invalida o anterior. |
| `client-key create --label <l>` | Emite uma chave de cliente; o texto puro é impresso **uma vez** e nunca logado. |
| `client-key list` | Lista `id`/`label`/estado (`active`/`revoked`); nunca a chave. |
| `client-key revoke <id>` | Revoga uma chave por id. |
| `provider add-key <id> [--label]` | Lê a API key do **stdin** (sem eco no terminal) e a sela no cofre. |
| `provider list` | Provedores registrados, modos de auth e estado (`ready`/`blocked(...)`/`future`). |
| `provider status` | Readiness real: um provedor só é `ready` com credencial utilizável no cofre. |
| `provider test <id>` | Probe ponta a ponta: monta o executor e chama `GET {base}/models`. Não envia chat. |
| `provider import` | Importa credenciais de arquivos locais de harness (read-only) para o cofre. |
| `combo create <nome> <step>... [--strategy]` | Cria (ou substitui) um combo; cada step é `kind:ref[:weight]`. |
| `combo list` / `combo delete <nome>` | Lista os combos persistidos / remove um. |
| `quota list` / `quota show <cred-id>` | Janelas de cota e fração restante. **Não há `reset`**: cota é estado observado, não dado editável. |
| `gate list` / `gate show <nome>` | A cadeia efetiva na ordem do DAG, com estágios, política de falha e dependências. |
| `config show` / `config validate` / `config path` | Config efetiva redigida (com origem) / validação / arquivo em uso. |

## Provedores

Quatro provedores são registrados (ver [`docs/PROVIDERS.md`](docs/PROVIDERS.md)
para o catálogo completo e como adicionar novos):

| ID | Protocolo | Auth | Utilizável hoje |
| --- | --- | --- | --- |
| `z.ai` | `openai` | API key | Sim |
| `ollama-cloud` | `openai` | API key | Sim |
| `command-code` | `openai` | API key | Sim |
| `antigravity` | `cloudcode` | OAuth | Não — `future` (sem login/wiring) |

Um provedor só é considerado utilizável quando o cofre tem uma credencial cujo
modo de auth a família suporta. Cadastre a chave com
`provider add-key` (ou `provider import`). Para um provedor por API key o teste
offline valida a forma da chave, e `provider test` valida contra o upstream.

Cada provedor tem seu transporte declarado em `[[providers]]` (`base_url`,
`auth_header`, `ttft`, `idle`, `allow_loopback`, `models`). Uma URL `http://`
só é aceita para um literal de loopback com `allow_loopback = true`; qualquer
outro destino passa pela política de egress (HTTPS obrigatório, denylist de
ranges privados — ADR-SEC-05).

## Combos

Um **combo** é um DAG nomeado e validado de passos de roteamento (ADR-0013). O
corpo é persistido no banco (não na config): combos são **dados do operador**,
como as credenciais, e mudam em runtime.

```sh
./bin/heimdall combo create fast \
    model:glm-4.6 \
    provider:z.ai \
    combo:base \
    --strategy fallback
```

Cada passo é `kind:ref[:weight]`, com `kind` em `model` | `provider` | `combo`.
O `--strategy` é uma das dez do registry: `priority`, `fallback`,
`round-robin`, `weighted`, `fill-first`, `cost`, `p2c`, `fusion`, `pipeline`,
`auto`. A validação rejeita ciclo no save e aplica um cap de profundidade. O
cursor de rotação (round-robin) é estado em memória e reinicia com o processo;
só a política é durável.

No request, `model` pode ser o nome de um combo; o gateway detecta isso e o
Router expande o DAG. Fora disso, a resolução é automática.

## Gates

Gates são o ponto de extensão do pipeline. Cada um declara em quais **estágios**
atua (`PreRequest`, `OnResponseChunk`, `PostResponse`), sua **política de falha**
(`FailOpen`/`FailClosed`) e, opcionalmente, um conjunto de leitura/escrita sobre
o request que define a **ordem por grafo de dependência** — não uma ordem fixa
de valor. A cadeia é montada **uma vez no boot**; não há enable/disable em
runtime.

Catálogo desta build (ver [`docs/GATES.md`](docs/GATES.md) para a semântica, a
ordem topológica real e como escrever um gate novo). A tabela abaixo é
**agrupada por estágio/grupo, não é a ordem de execução**; a ordem é derivada do
grafo e a fonte de verdade é `heimdall gate list`:

| Gate | Estágios | Política | Grupo |
| --- | --- | --- | --- |
| `logger` | pre, chunk, post | `fail_open` | logger |
| `credential-masker` | pre | `fail_closed` | security |
| `ssrf-guard` | pre | `fail_closed` | security |
| `pii-masker` | pre | `fail_closed` | security |
| `injection-guard` | pre | `fail_closed` | security |
| `rate-limit` | pre | `fail_open` | security |
| `token` | pre | `fail_open` | token |
| `memory-retriever` | pre | `fail_open` | memory |
| `memory-writer` | post | `fail_open` | memory |

Com todos os gates ligados, `heimdall gate list` produz a ordem real:
`credential-masker`, `logger`, `memory-retriever`, `rate-limit`, `ssrf-guard`,
`token`, `injection-guard`, `pii-masker`, `memory-writer`.

Ligar/desligar um gate é mudar a config e reiniciar. `features.gates.<id>` é o
switch **individual** (vence o switch de grupo nos dois sentidos); os três
booleanos `token`/`memory`/`security` são os switches de **grupo**:

```toml
[features.gates]
"pii-masker"     = true     # switch individual, chave = id do gate
"rate-limit"     = true

[features.gates.memory]
retrieval_limit = 5

[features.gates.security]
pii_policy       = "mask"   # mask | block | off
injection_policy = "block"  # block | flag
```

> Como `security` é o nome do grupo **e** da tabela de parâmetros, o TOML não
> aceita `security = true` junto com `[features.gates.security]` no mesmo
> arquivo. Para combinar grupo e parâmetros, use os switches individuais acima
> ou ligue o grupo por `HEIMDALL_FEATURES_GATES_SECURITY=true`.

Os gates efetivos, com a ordem derivada do grafo, aparecem em `gate list` e
`gate show`; nada é escondido. Ver [`docs/GATES.md`](docs/GATES.md) para a
semântica de cada gate, a política de falha e como escrever um gate novo.

## Segurança

O modelo completo está em [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) e nas
ADRs de segurança (`docs/adr/sec-*`). O essencial:

- **Bind loopback por padrão.** Um bind não-loopback exige
  `server.allow_remote = true` explícito, e o boot emite um aviso.
- **Dois tokens segregados.** O *token de gestão* autentica `/api/mgmt/*` e a
  GUI; a *chave de cliente* autentica o gateway de inferência `/v1/*`. São
  classes de credencial diferentes, ambos guardados só como hash, comparados em
  tempo constante. Uma chave nunca é aceita na query string (400).
- **Cofre cifrado.** Credenciais em repouso usam AES-256-GCM com envelope
  DEK/KEK (`enc:v1:`), IV de 12 bytes e salt por instalação com Argon2id. Sem
  a KEK, o banco vazado é ilegível (ADR-SEC-01).
- **Redator central.** Nenhum segredo em log; corpo de requisição nunca é
  logado. Gates recebem o **mínimo** de conteúdo necessário: nomes de header,
  nunca valores.
- **Guardas catch-all.** `HostGuard` (anti-DNS-rebinding), `OriginGuard`
  (anti-CSRF), CORS fechado e `LocalOnly` embrulham o mux inteiro, então uma
  rota nova nasce protegida (ADR-SEC-06).

Dívidas de segurança conhecidas, com status, impacto e gatilho, ficam em
[`docs/SECURITY-DEBT.md`](docs/SECURITY-DEBT.md). Hoje: **M-1** (busca vetorial
`vec0` ausente — FTS5-only, não bloqueia fase) e o aceite de
**D-SEC-09-01** (assinatura cosign depende de OIDC; o fallback offline é
checksums + proveniência SLSA).

## Build, release e integridade

```sh
make build     # bin/heimdall (estático, sem cgo)
make dist      # dist/heimdall-<versão>-linux-{amd64,arm64}
```

`VERSION` vem de `git describe --tags --always --dirty`, então cada artefato
carrega a versão de origem no nome (sobrescreva com `make dist VERSION=v0.1.0`).
A data do build **não** é embutida de propósito: carimbá-la tornaria o binário
irreprodutível bit-a-bit.

Os binários de release são **reprodutíveis bit-a-bit** (ADR-SEC-09 §4): o build
usa `-trimpath`, `-buildvcs=false` e `-s -w`, sem relaxar `CGO_ENABLED=0`. Com
`VERSION` fixada, o mesmo fonte produz o mesmo SHA-256 — `make dist-verify`
comprova com dois builds de cópias limpas.

| Alvo | O que faz |
| --- | --- |
| `build` | compila `./cmd/heimdall` em `bin/` |
| `test` / `vet` / `race` | `go test ./...` / `go vet ./...` / `go test -race ./...` |
| `lint` | staticcheck via `go run` na versão pinada (usa `staticcheck.conf`) |
| `cover` / `cover-check` | cobertura `-race -covermode=atomic`; `cover-check` falha abaixo de `COVER_MIN` |
| `vuln` | `govulncheck ./...` |
| `web` / `web-test` | builda a SPA Svelte em `internal/webui/dist/` / testes de contrato da SPA |
| `dist` / `dist-verify` | cross-compile estático reprodutível / prova de reprodutibilidade |
| `sbom` / `sbom-check` | SBOM CycloneDX 1.6 em `dist/sbom.cdx.json` / validação |
| `checksums` / `checksums-verify` | manifesto `dist/SHA256SUMS` / conferência |
| `sign` | assina o manifesto com cosign keyless (não falha sem cosign) |
| `release-check` | gate completo: gates + dist + dist-verify + SBOM + checksums + verificação |
| `clean` | remove `bin/`, `dist/` e `coverage.out` |

Reproduzir o pipeline do CI localmente:

```sh
make vet lint race cover-check vuln
```

O CI (`.github/workflows/ci.yml`) **bloqueia** o merge: nenhuma etapa usa
`continue-on-error`, e `make cover-check` derruba o run abaixo do `COVER_MIN`
(piso 98%, com folga para ramos defensivos novos). O valor de aceite da fase é
a cobertura **medida** de 100,0%, não o piso.

### Release, SBOM e assinatura (F6 — ADR-SEC-09)

```sh
make release-check   # gates + dist + dist-verify + SBOM + checksums + verificação
```

Saída em `dist/`:

- `heimdall-<versão>-linux-amd64` e `-linux-arm64` — ELF estáticos
  (`file` reporta `statically linked`);
- `sbom.cdx.json` — SBOM **CycloneDX 1.6** gerado pelo `cyclonedx-gomod` pinado
  (via `go run`, sem binário externo) e determinístico (`-noserial -notimestamp`),
  cobrindo todos os `require` do `go.mod`;
- `SHA256SUMS` — manifesto SHA-256 dos binários e do SBOM.

Comportamento real do SBOM (medido nesta build — o alvo `sbom` é do Makefile,
não desta documentação; ver "Pendências conhecidas" abaixo):

- **Nome do artefato:** sai como `dist/sbom.cdx.json`, e **não** como
  `heimdall-<versão>-cyclonedx.json`. A ADR-SEC-09 §2.2/§7.4 nomeia a segunda
  forma; o alvo atual usa a primeira. Divergência registrada (ver abaixo).
- **Versão:** o binário honra `VERSION` (injetado por `-ldflags`), mas o
  `metadata.component.version` do SBOM é derivado pelo `cyclonedx-gomod` a
  partir do git (`v0.0.0-<timestamp>-<sha>`), **ignorando** a flag `VERSION`; em
  uma cópia limpa sem `.git`, esse campo fica `null`.
- **Licenças:** o SBOM atual **não** inclui `licenses` no componente principal
  nem nos componentes; a ADR-SEC-09 §2.1 prevê a licença do produto.
- **NPM/SPA:** por padrão (`SBOM_TOOL=cdxgomod`) o SBOM cobre só os módulos Go —
  os componentes NPM da SPA **não** entram. Use `SBOM_TOOL=syft` para incluí-los
  (o `syft` precisa estar instalado); `SBOM_TOOL=auto` prefere o `syft` e cai
  para o `cdxgomod`.

### Verificação de Integridade e Assinatura

Verificação da integridade pelo operador que baixou o release, por checksums
SHA-256:

```sh
sha256sum -c dist/SHA256SUMS
```

**Assinatura.** Em release publicado por tag no GitHub Actions o manifesto é
assinado com `cosign` keyless (OIDC/Fulcio/Rekor) por `make sign`. Sem o cosign
no ambiente o alvo **não falha**: imprime o comando de assinatura e o de
verificação e segue. Verificação do release assinado (o operador confirma o
checksum **e** a identidade OIDC de quem assinou):

```sh
cosign verify-blob \
  --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/dandgabr/heimdall-core/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  dist/SHA256SUMS
sha256sum -c dist/SHA256SUMS
```

A ausência de assinatura em ambiente offline é dívida de infraestrutura aceita
— **D-SEC-09-01** em [`docs/SECURITY-DEBT.md`](docs/SECURITY-DEBT.md) — cujo
fallback é a proveniência SLSA do GitHub (`actions/attest-build-provenance`,
passo preparado no workflow).

#### Pendências conhecidas do empacotamento

Estas divergências entre a ADR-SEC-09 e o alvo `sbom` do Makefile estão
**reportadas ao responsável do empacotamento** (não são desta documentação):

- nome do SBOM (`sbom.cdx.json` vs `heimdall-<versão>-cyclonedx.json`);
- `VERSION` não honrado no SBOM e versão `null` sem `.git`;
- licenças ausentes no SBOM;
- NPM/SPA só com `SBOM_TOOL=syft`.

Enquanto não forem corrigidas, a descrição acima é o comportamento **real**.

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

## Avisos legais e risco aceito

- **Risco de ToS por provedor de sessão.** O conector Antigravity implementa uma
  camada de **ocultação de harness** (User-Agent, reescrita de prompt, tool
  cloaking) porque o backend do provedor rejeita clientes não-oficiais. Isso
  **pode violar os termos de uso e causar suspensão ou banimento da conta**.
  O risco é **aceito explicitamente pelo dono do projeto** (ADR-0003, que
  revoga a cláusula "sem cloaking" da ADR-003). A ocultação é *do harness*,
  nunca da identidade do usuário. O aviso aparece em `provider list`/`status`,
  na GUI e via `RISK_NOTICE` (`provider.risk_notice.antigravity`).
- **Escopo de segurança v1.** O hardening cobre o escopo aplicável do v1;
  gates de terceiros/WASM ficam fora da v1 (ADR-003, ADR-SEC-03). Ver
  [`docs/SECURITY-DEBT.md`](docs/SECURITY-DEBT.md).

## Documentação

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — camadas, pipeline, contratos,
  árvore de pacotes e modelo de dados.
- [`docs/PROVIDERS.md`](docs/PROVIDERS.md) — catálogo e como adicionar provedores.
- [`docs/GATES.md`](docs/GATES.md) — catálogo, política de falha e como escrever
  um gate.
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — modelo de ameaças consolidado.
- [`docs/openai-compat.md`](docs/openai-compat.md) — subset OpenAI suportado.
- [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) — regra de saída por fase.
- [`docs/SECURITY-DEBT.md`](docs/SECURITY-DEBT.md) — dívidas de segurança.
- [`docs/adr/`](docs/adr/README.md) — todas as ADRs (arquitetura e segurança).
