# ADR-0010 — `Dispatcher`: tentativa, failover e accounting

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F3 (Router, Combos e Cotas)
- **Relaciona-se com:** ADR-0009 (estratégias/`RoutePlan`), ADR-0001 (`ProviderFamily` × `Credential`), ADR-0002 (taxonomia de erro), ADR-0011 (cota/`UsageRecorder`), ADR-0012 (`Breaker`)

## Contexto

A revisão de arquitetura (`notes/revisao-plano-arq-sec.md`, mudança estrutural nº 2)
apontou que o plano v1 não tinha **dono do laço de tentativas**: o failover, a
decisão de "tentar o próximo" e o accounting ficariam diluídos no handler HTTP,
produzindo um handler-god que fala upstream, aplica gate, decide cooldown e
serializa SSE na mesma função. A ADR-0009 congelou a **saída** do Router
(`RoutePlan`/`Candidate`) e proibiu o Router de executar; esta ADR congela o
componente que **executa o plano**.

O repo já tem o que o Dispatcher consome e produz:

- `contracts.Executor` (`Do`, `DoStream`, `Family`, `CountTokens`) — transporte+auth,
  construído por família a partir de uma `Credential` (ADR-0001);
- `contracts.Stream` — pull-based, com a invariante de `committed` no 1º byte
  (`internal/contracts/executor.go`, "STREAMING INVARIANTS");
- `domain.DomainError` com `Scope`/`Retryable`/`RetryAfter` (ADR-0002);
- `contracts.Clock` e `contracts.IDGen` — os seams de determinismo já usados em
  auth/executors;
- a decisão de que **cota não é gate** (ADR-0009; revisão nº 2): `QuotaFilter` +
  `Breaker` filtram no preflight, `UsageRecorder` observa.

Falta o dono do laço. Esta ADR o define **antes** de a F3 começar para que o
handler HTTP não volte a ser o lugar do failover.

## Decisão

### 1. Posição na pipeline e contrato

O **Dispatcher NÃO é gate e NÃO é handler HTTP**. É o dono do laço de tentativas,
do failover e do accounting: recebe o `RoutePlan` já resolvido pelo Router e fala
com o `Executor`.

```go
// Dispatcher executa UM RoutePlan. É o dono do laço de tentativas, do failover
// e do accounting. Ele NÃO resolve rota (Router), NÃO aplica gate de conteúdo
// (GateChain) e NÃO serializa HTTP (api/openai). Ele usa o Executor por
// credencial e reporta Usage ao UsageRecorder.
type Dispatcher interface {
    // Do executa um plano não-streaming e devolve a resposta canônica da
    // tentativa vencedora.
    Do(ctx context.Context, req contracts.WireRequest, plan RoutePlan) (*Response, error)
    // DoStream executa um plano streaming. O Stream devolvido é "committed no
    // 1º byte": a partir daí nenhuma troca de candidato é legal.
    DoStream(ctx context.Context, req contracts.WireRequest, plan RoutePlan) (contracts.Stream, error)
}

// Response é o resultado de UMA tentativa vencedora: o WireResponse do executor
// mais a procedência (qual Candidate respondeu), para auditoria/accounting.
type Response struct {
    Candidate Candidate
    Wire      contracts.WireResponse
    Attempts  int // tentativas consumidas até o vencedor (>=1)
}
```

Os tipos `RoutePlan` e `Candidate` são os da ADR-0009 e **não** são redefinidos
aqui. O Dispatcher é uma camada NOVA sobre `Executor` + `RoutePlan`; ele não
importa o Router nem a GateChain.

### 2. Fluxo de uma rodada

Para cada `Candidate` de `plan.Attempts`, em ordem, até o teto:

```
1. Preflight do candidato (filtros, NÃO gates):
     - Breaker.State(scope) == aberto?       -> Skip (sem Executor, sem custo)
     - QuotaFilter permite a credencial?      -> Skip se restante <= cutoff
   Um Skip NÃO consome rodada nem credencial; o laço avança.

2. Selecionar a credencial concreta:
     - Candidate.Credential != zero -> essa conta (account-aware, ADR-0009 §2);
     - zero -> escolher UMA credencial sadia da família (breaker fechado, cota
       permitida), determinística dada a ordem do CredentialStore.
   Nenhuma credencial elegível -> Skip.

3. Executor := family.BuildExecutor(cred, deps); chamar Do / DoStream.

4. Classificar o resultado (ADR-0002), SEMPRE pelos campos tipados:
     - sucesso                 -> retorna (Response / Stream committed);
     - ScopeRequest            -> retorna IMEDIATAMENTE, sem retentar e SEM
                                  cooldownar (erro do cliente não é
                                  responsabilidade de outra credencial);
     - ScopeCredential         -> Record(credential, RetryAfter); próximo
                                  candidato com cooldown = RetryAfter (ou
                                  backoff+jitter quando ausente);
     - ScopeProvider           -> Record(provider|model, RetryAfter); próximo
                                  candidato com cooldown exponencial;
     - Retryable=false de credencial (auth.credential_invalid) -> invalida a
       conta após N falhas (ADR-0002 §2) e segue para o próximo candidato.

5. Guardas do laço:
     - ctx cancelado            -> aborta e devolve o erro do ctx (não é falha
                                   de candidato; não cooldowna);
     - MaxRounds atingido       -> para;
     - max_credentials atingido -> para.
```

Regras normativas:

1. **Um erro `ScopeRequest` é terminal.** Ele retorna ao cliente sem tentar o
   próximo passo e sem `Record` — a ADR-0002 o isola como erro do cliente (ex.:
   `error.invalid_request`, `error.upstream_response_too_large`,
   `error.upstream_destination_denied`). Retentar um `400` queima cota e é a
   regressão que a ADR-0002 existe para impedir.
2. **`RetryAfter` vence o backoff.** Quando o candidato devolve `RetryAfter`
   (cota/reset, ADR-0002 §7), o cooldown é esse valor, não o exponencial.
3. **`ctx` manda.** `select` em `ctx.Done()` em todo `Sleep`/espera de cooldown;
   cancelamento devolve o erro do `ctx` (`transportError` já o mapeia para
   `error.upstream_timeout`, ADR-0002), nunca "esgotou candidatos".
4. **Determinismo.** O Dispatcher usa `Clock` (cooldown, `After`) e `IDGen`
   (correlação) injetáveis; em teste, ambos são fixos e o laço é reproduzível.

### 3. Streaming e `committed`

- `DoStream` abre o stream no candidato escolhido. A flag **`committed`** é
  marcada no **primeiro byte downstream** (invariante já congelada em
  `contracts.Stream`).
- **Após `committed`, nenhuma troca de candidato é legal.** Um erro pós-commit
  vira **evento SSE terminal** (`event: error`, ver `passthrough/stream.go`
  `writeSSEError`), **nunca** um HTTP error: o status `200` já foi enviado.
- Um erro **pré-commit** (TTFT estourou, non-2xx, corpo vazio) é tratado como
  tentativa falha: classifica-se e passa ao próximo candidato.
- `Do` é o caso não-streaming: não há commit downstream antes da resposta
  completa, então todo erro é pré-commit e o failover é sempre legal.

### 4. Accounting (`Usage` por tentativa)

- **Uma `Usage` por tentativa**, emitida para o `UsageRecorder` (ADR-0011), não
  por request: um failover queima cota de DUAS contas e o accounting tem de
  refletir isso. Cada `Usage` carrega `{Provider, Credential, Model, Tokens,
  Requests, Outcome}` e a chave idempotente da tentativa.
- **Uso parcial:** um stream abortado no meio (cliente desconectou, idle
  estourou) ainda reporta os tokens observados até o abort (`Outcome=aborted`).
  O `UsageRecorder` é idempotente por chave de tentativa, então uma reentrega
  (ex.: retry do próprio recorder) não duplica.
- **Failover conta N×:** `N` tentativas ⇒ `N` usos. Isso é deliberado e
  auditável (`Response.Attempts`).
- O Dispatcher **não** decide cota: ele só **reporta** e consulta o filtro. O
  estado de cota é da ADR-0011.

### 5. Reroute e o plano

- Um gate pode pedir `DecisionReroute` **pré-commit** (ADR-0009 §7 / ADR-0013 §6).
  O Dispatcher aceita um **plano injetado** para essa tentativa: o reroute
  **substitui `plan.Attempts`** pela rota validada em allowlist e reinicia o
  laço (respeitando `MaxRounds` e a profundidade, ADR-0013 §3). Um reroute
  pós-commit é recusado (ver §3) com `error.internal` — é violação de contrato,
  não erro do cliente.
- O Dispatcher **não** valida a allowlist: quem valida é o Router/Registry
  (ADR-0013). O Dispatcher só executa o plano que recebe; um plano com alvo fora
  do registry nunca deveria existir.

### 6. Esgotamento e erro agregado

Quando o laço termina sem vencedor:

- Todos os candidatos foram filtrados (breaker/cota) sem Executor → o erro
  **preserva a razão do filtro** (cota → `quota.*`, breaker → último estado),
  tipado, `Retryable=true` quando havia alternativa sadia rejeitada por estado
  transiente; `ScopeRequest`/`Retryable=false` quando não há candidato saudável
  e o request não é atendível (**`dispatch.no_attempts`** ou `route.no_candidate`
  da ADR-0009 §7).
- Houve tentativas e todas falharam → **erro agregado (`dispatch.exhausted`)** com
  `params={attempts, last_code}`. O agregado herda a classificação da **última**
  tentativa (o `Scope`/`Retryable` do último `DomainError`), para que o
  chamador/breaker ajam sobre a causa mais recente, e preserva `Cause` da
  última falha. Nunca inventa um `Scope` novo.

### 7. Códigos i18n

Nomeados aqui para o implementador não inventar strings (mesma prática das
ADR-0009 §7 e 0013 §7):

- `dispatch.no_attempts` (503/`ScopeProvider`/`Retryable=true`): nenhum candidato
  executável (todos filtrados) e o request era atendível.
- `dispatch.exhausted` (502/scope herdado/retryable herdado): todas as tentativas
  falharam; `params={attempts,last_code}`.
- `dispatch.max_rounds` (502/`ScopeProvider`/`Retryable=true`): o teto de rodadas
  foi atingido (fusion/pipeline/failover profundo).
- `dispatch.credential_limit` (502/`ScopeCredential`/`Retryable=true`): o teto de
  credenciais distintas por request foi atingido.

Entram no catálogo `pt-BR`/`en` na F3, com placeholders nomeados.

## Consequências

- **F3 entrega** um `Dispatcher` com `Do`/`DoStream` e três dependências
  injetadas: `ExecutorFactory` (por família/credencial), `QuotaFilter` (ADR-0011)
  e `Breaker` (ADR-0012); `Clock`/`IDGen` são os seams de determinismo. O
  `UsageRecorder` é observador opcional (nil = sem accounting) para não acoplar
  o laço a uma implementação.
- **O handler HTTP fica fino:** resolve config/rota no Router, chama
  `GateChain.PreRequest`, chama `Dispatcher`, e escreve a resposta/SSE. Failover,
  cooldown e accounting saem dele.
- **Cota/breaker como filtro** significa que o Dispatcher só tenta candidatos
  pré-filtrados; ele **nunca** decide "esta conta está em cooldown" por conta
  própria — consulta o estado. Isso mantém a política em um só lugar (ADR-0011/0012).
- **`committed` é o pivô de streaming:** a proibição de troca após o 1º byte é
  verificada aqui, e o teste de F3 "failover quando cota esgota" roda com dois
  candidatos e um `UsageRecorder` que prova 2 usos.
- **Testes determinísticos:** com `Clock`/`IDGen` fixos e um `Executor` fake que
  devolve uma sequência de `DomainError` classificados por `Scope`, o laço é
  reproduzível: `400` não avança, `429` usa `RetryAfter`, `5xx` usa exponencial,
  `ctx` cancelado aborta.

## Alternativas consideradas

- **Failover no handler HTTP.** Rejeitada (revisão nº 2): produz handler-god,
  mistura transporte/auth/serialização e torna o laço não testável sem HTTP.
- **Cota como `Gate`.** Rejeitada (ADR-0009; revisão nº 2): um gate de cota no
  `PreRequest` só veria o request, não o resultado da tentativa; e cota precisa
  ser reavaliada **entre** tentativas, o que só o dono do laço pode fazer.
- **Um `Executor` por request, reusado em todos os candidatos.** Rejeitada: o
  Executor é por **família+credencial** (ADR-0001); trocar de candidato é trocar
  de executor e de credencial.
- **Account no Router (Dispatcher só obedece).** Rejeitada: o Dispatcher precisa
  escolher a credencial sadia **no momento da tentativa** (o estado de cota/
  breaker muda entre candidatos); forçar essa escolha no resolve tornaria o plano
  obsoleto sob concorrência. O plano indica a conta quando a estratégia é
  account-aware; senão, o Dispatcher escolhe.
- **Retry interno dentro do `Executor`.** Rejeitada: o Executor é transporte+auth
  (ADR-0002/SEC-05) e não conhece o plano; retry é do Dispatcher, guiado pela
  taxonomia.
