# Gates — catálogo e como escrever um

Um **gate** é o ponto de extensão do pipeline. Ele vê a requisição (ou a
resposta) em um dos três estágios e devolve uma decisão. O conjunto ordenado de
gates é a **GateChain**. O contrato está congelado em
`internal/contracts/gate.go` (o `Gate` da F1) e o motor que o ordena vive em
`internal/gates` (engine da ADR-0014).

## O contrato congelado

```go
type Gate interface {
    ID() string
    Stages() GateStageSet
    RequiredCaps() GateCaps
    FailurePolicy() FailurePolicy
    PreRequest(ctx context.Context, in GateInput) (Decision, error)
    OnResponseChunk(ctx context.Context, in ChunkInput) (ChunkDecision, error)
    PostResponse(ctx context.Context, in GateInput) error
    Close() error
}
```

Nenhum tipo Go nativo cruza a fronteira (bytes, strings, mapas): isso é o que
mantém um adaptador WASM pós-v1 possível. Um gate é **stateless entre
requisições**; estado por requisição vive em `GateInput.Meta`/`ChunkInput.Meta`.

Declarações adicionais, todas **opcionais e aditivas** (não mudam o `Gate`):

- `contracts.GateDeclarer` → `Declare() Declared` declara o conjunto de
  leitura/escrita sobre os campos de dados (`DataField`) e o quebra-empate
  explícito `After`. É o que dá as **arestas** do grafo.
- `contracts.BodyConsumer` → `NeedsBody() bool` declara que o gate precisa do
  corpo. Sem isso, `GateInput.Body` fica `nil` (ADR-SEC-03 §2: "o mínimo que o
  gate precisa").

## Estágios

| Estágio | Quando | Vocabulário de decisão |
| --- | --- | --- |
| `StagePreRequest` | Antes do roteamento/execução | `Decision`: `Continue` \| `Modify` \| `Block` \| `Reroute` |
| `StageOnResponseChunk` | Por chunk, **depois do commit** | `ChunkDecision`: `PassThrough` \| `Replace` \| `Drop` |
| `StagePostResponse` | Uma vez ao fim da troca (inclusive em erro) | erro opcional (observável, nunca aborta) |

Regras semânticas:

- **`committed`.** Depois do primeiro byte downstream, `Committed` é `true` e não
  há mais `Reroute` nem troca de modelo. Um `Decision` pós-commit é violação de
  contrato.
- **`Block` carrega `SyntheticResponse`.** Um cache hit é um **sucesso** entregue
  como resposta; uma negação de política também é entregue como resposta (o
  `Status` diz a intenção). Não é um erro HTTP.
- **`Reroute`** é pré-commit e só para um alvo na allowlist; hoje o gateway
  responde `provider.reroute_unsupported` até o dispatcher de allowlist existir.
- **`PostResponse` é sempre `FailOpen`** por contrato: roda fora do caminho do
  primeiro byte.

## Catálogo desta build

Nove gates são registrados, conforme a config. **A tabela abaixo é agrupada por
estágio/grupo — ela NÃO é a ordem de execução.** A ordem de execução é derivada
do grafo de dependência e **muda com a config** (um gate desligado some). A
fonte de verdade é o comando:

```sh
heimdall gate list        # ordem do DAG: id, estágios, política, grupo
heimdall gate show <id>   # estágios, política, caps, reads/writes/after
```

Tabela de referência (sem ordem implícita), por estágio e grupo:

| Gate | Grupo | Estágios | Política | Lê (`Reads`) | Escreve (`Writes`) |
| --- | --- | --- | --- | --- | --- |
| `credential-masker` | security | pre | `fail_closed` | — | `prompt_text` |
| `rate-limit` | security | pre | `fail_open` | — | — |
| `ssrf-guard` | security | pre | `fail_closed` | — | — |
| `logger` | logger | pre, chunk, post | `fail_open` | — | — |
| `memory-retriever` | memory | pre | `fail_open` | `cache_lookup` | `context` |
| `token` | token | pre | `fail_open` | `cache_lookup`, `context` | `prefix_range`, `prompt_text` |
| `injection-guard` | security | pre | `fail_closed` | `context`, `prompt_text` | `injection_flag` |
| `pii-masker` | security | pre | `fail_closed` | `prompt_text` | `pii` |
| `memory-writer` | memory | post | `fail_open` | — | — |

### Ordem topológica real (medida)

Com **todos os gates ligados** (token + memory + security + `rate-limit`
configurado), `heimdall gate list` produz exatamente:

```
credential-masker   pre_request
logger              pre_request,on_response_chunk,post_response
memory-retriever    pre_request
rate-limit          pre_request
ssrf-guard          pre_request
token               pre_request
injection-guard     pre_request
pii-masker          pre_request
memory-writer       post_response
```

A ordem acima foi medida nesta build (commit `4a68b7e`); `rate-limit` só aparece
quando a config o habilita (o zero `rate` o mantém off por padrão).

Como ler a ordem: a aresta A→B existe quando **A escreve um campo que B lê**.
Ex.: `memory-retriever` escreve `context` e o `token` lê `context`, então a
memória é injetada **antes** da compressão. `credential-masker` e `token`
escrevem `prompt_text`; `pii-masker` e `injection-guard` o leem, então rodam
depois de ambos. Quando não há aresta, o desempate é o **ID lexicográfico** — é
por isso que os gates de contenção sem aresta saem em `credential-masker` <
`rate-limit` < `ssrf-guard`, e por isso `logger` (sem aresta) intercala onde o
desempate o põe. **Não há uma ordem fixa "por valor"**: a tabela acima não
implica ordem e a ordem real deve ser lida de `heimdall gate list`.

### O que cada gate faz

- **`logger`** — observabilidade pura: registra request id, provider,
  credential, modelo e **nomes** de header (nunca valores), no pre, por chunk
  (índice e tamanho, nunca bytes) e no post. `FailOpen`: observabilidade nunca
  derruba o pipeline. Não implementa `GateDeclarer` com campos — não tem aresta.
- **`token`** (ADR-0015) — comprime o prompt no pre respeitando o **prefixo
  cacheável congelado** (`prefix-freeze`). Engines declaram `lossy` e
  `cacheImpact`; uma reescrita de prefixo só ocorre com opt-in explícito de um
  engine `ImpactHigh` e é **verificada**: se o prefixo congelado mudar sem
  opt-in, a mudança é descartada. `FailOpen`.
- **`memory-retriever`** (ADR-SEC-07) — busca o último turno do usuário no store
  local (FTS5) e injeta como contexto **delimitado e marcado como dados**, nunca
  instruções. Namespace obrigatório por chave de cliente; sem chave, é inerte.
  Budget síncrono de 100 ms; `FailOpen`.
- **`memory-writer`** — extrai o último turno **depois** da troca e entrega a um
  `AsyncSink` limitado; a fila transborda **descartando** (backpressure). Redige
  via redator central antes de persistir. Post-only, `FailOpen`.
- **`credential-masker`** — remove credenciais do corpo antes do egress (o
  smoke real da F4 provou que `sk-live-SECRET` chegou como `[REDACTED]`).
  `FailClosed`.
- **`ssrf-guard`** — nega URLs fornecidas pelo cliente para alvos de rede
  protegidos. `FailClosed`.
- **`pii-masker`** — mascara/bloqueia dados pessoais no corpo. Política
  configurável (`mask` default, `block`, `off`). `FailClosed`.
- **`injection-guard`** — detecta assinaturas de prompt injection. `block`
  (default, `FailClosed`) ou `flag` (`FailOpen`). A decisão é função pura de
  política estática + casamento determinístico; **nada no conteúdo pode virar
  uma instrução**.
- **`rate-limit`** — throttle por chave de cliente (token bucket). Sem chave
  autenticada, cai no balde compartilhado documentado. `FailOpen`: throttling é
  disponibilidade, como a cota.

## Política de falha

Declarada **por gate**, nunca global (`FailurePolicy()`):

- **`FailClosed`** — um erro do gate **aborta** a requisição. Gates de segurança
  (credential-masker, ssrf-guard, pii-masker, injection-guard em `block`).
- **`FailOpen`** — um erro é registrado e o pipeline **continua com o input
  inalterado** (um `Modify` meio-aplicado nunca é publicado). Observabilidade,
  token, memória e rate-limit.

Como o motor aplica: no pre, `FailClosed` retorna o erro (vira resposta de erro);
`FailOpen` dá `continue` com o input de antes do gate. No chunk, `FailClosed`
vira evento SSE terminal; `FailOpen` passa o chunk inalterado. O registry
**recusa no boot** declarações incoerentes:

- um gate `FailOpen` que **escreve** `pii` ou `injection_flag` (mascararia o
  próprio efeito);
- um gate **post-only** declarado `FailClosed`;
- estágios declarados que divergem de `Stages()`;
- ID que não bate com o nome de registro; gate sem estágio; duplicata; ciclo no
  grafo; `After` apontando para gate não registrado.

Todos esses são erros de boot (`error.internal`), porque grafo ruim é bug do
binário, não do request.

## Habilitar e desabilitar

A cadeia é montada **uma vez no boot** a partir da config; não há enable/disable
em runtime. Desligar um gate é mudar a config e reiniciar.

> **Atenção ao TOML.** `features.gates.security` é ao mesmo tempo o switch de
> grupo (`security = true`) e a tabela de parâmetros (`[features.gates.security]`).
> Em TOML, um escalar e uma tabela sob a mesma chave colidem, então **não** se
> pode escrever `security = true` junto com `[features.gates.security]` no mesmo
> arquivo (o carregador rejeita com `config.load_failed`, "invalid TOML"). Para
> combinar grupo e parâmetros, use o switch **individual** por gate (que é uma
> chave distinta, `"<id>"`) ou ligue o grupo por variável de ambiente
> (`HEIMDALL_FEATURES_GATES_SECURITY=true`).

Forma válida combinando parâmetros e switches individuais:

```toml
# switches INDIVIDUAIS (vencem o grupo nos dois sentidos); a chave é o id do gate,
# então não colidem com a tabela [features.gates.security]
[features.gates]
"memory-retriever" = true
"pii-masker"       = true

[features.gates.memory]
retrieval_limit = 5

[features.gates.security]
pii_policy       = "mask"    # mask | block | off
injection_policy = "block"   # block | flag
```

E a forma só com switches de grupo (sem tabela de parâmetros):

```toml
[features.gates]
token    = true
memory   = true
security = true
```

`features.gates.<id>` liga/desliga um gate individualmente e vence o switch de
grupo nos dois sentidos (`config.GateEnabled`). O parâmetro `pii_policy = "off"`
é o "desligado" próprio do PII masker: o construtor devolve `nil` e o
`Assemble` simplesmente o omite. Um gate desabilitado **nunca é construído** e
nunca entra no grafo; a ordem derivada dos demais continua válida (nenhum gate
usa `After`, então nenhuma combinação de gates desligados quebra o boot).

Para ver o resultado efetivo:

```sh
heimdall gate list          # ordem do DAG: id, estágios, política, grupo
heimdall gate show token    # estágios, política, caps, reads/writes/after
```

## Como escrever um gate novo

1. **Implemente `contracts.Gate`.** Mínimo necessário:
   - `ID()` estável e igual ao nome de registro (o registry rejeita divergência);
   - `Stages()` com **pelo menos um** estágio (vazio é erro);
   - `RequiredCaps()` (0 se não precisa de nada; a cadeia só roda o gate se a
     rota resolveu satisfizer tudo que ele pediu);
   - `FailurePolicy()` explícita (não há default silencioso);
   - `PreRequest`/`OnResponseChunk`/`PostResponse` coerentes com os estágios;
   - `Close()` idempotente.

2. **Declare as dependências do DAG (opcional, mas recomendado).** Implemente
   `contracts.GateDeclarer`:

   ```go
   func (g *MyGate) Declare() contracts.Declared {
       return contracts.Declared{
           Stages: g.Stages(),                       // igual a Stages()
           Reads:  []contracts.DataField{contracts.FieldPromptText},
           Writes: []contracts.DataField{contracts.FieldContext},
           After:  nil,                              // só se não der para expressar como campo
       }
   }
   ```

   Os `DataField` são um **conjunto fechado** (`modality`, `cache_lookup`,
   `context`, `prompt_text`, `prefix_range`, `pii`, `injection_flag`,
   `token_budget`, `route`). Um campo novo é mudança de contrato, não string
   solta, para o grafo continuar verificável. Use `After` só como exceção
   documentada. **Não crie ciclo** — ele é recusado no boot.

3. **Se precisar do corpo, implemente `BodyConsumer`** (`NeedsBody() bool`).
   Caso contrário o `Body` chega `nil` por design; nunca leia header
   *valores* — `GateInput.Headers` só traz nomes.

4. **Escolha a política de falha com cuidado.** Segurança → `FailClosed`;
   disponibilidade/observabilidade → `FailOpen`. Se escrever `pii`/
   `injection_flag`, **precisa** ser `FailClosed`.

5. **Registre no composition root** (`internal/app/app.go`, `wireGates`), atrás
   do switch de config, sem tocar o core:

   ```go
   if a.Config.Features.Gates.GateEnabled("meu-gate", a.Config.Features.Gates.Security) {
       g := mypkg.New(...)
       if err := reg.RegisterGate(g.ID(), func() contracts.Gate { return g }); err != nil {
           return err
       }
   }
   ```

   O registro é por `RegisterGate(name, factory)`; um gate desabilitado tem sua
   factory simplesmente **não chamada**, então não entra no grafo.

6. **Teste.** O gate deve ter testes de comportamento (decisão e política) e a
   integração com a ordem do DAG. A cobertura exigida é 100,0% em
   `-race -covermode=atomic`, sem bloco descoberto.

O motor (`internal/gates/registry.go`) cuida do resto: ordenação topológica
determinística (Kahn com desempate por ID), rejeição de ciclo e validação da
coerência no boot.
