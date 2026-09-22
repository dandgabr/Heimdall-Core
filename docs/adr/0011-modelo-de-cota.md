# ADR-0011 — Modelo de cota e `UsageRecorder`

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F3 (Router, Combos e Cotas)
- **Relaciona-se com:** ADR-0009 (`RoutePlan`/`QuotaFilter` no preflight), ADR-0001 (cota por `Credential`), ADR-0002 (`Scope`/`RetryAfter`), ADR-0010 (`Dispatcher` reporta `Usage`), ADR-0012 (`Breaker`)

## Contexto

A revisão de arquitetura (`notes/revisao-plano-arq-sec.md`, mudança estrutural nº 2)
decidiu que **cota não é gate**: um `QuotaGate` no `PreRequest` veria só o request
e não o resultado da tentativa, e cota precisa ser reavaliada **entre** tentativas.
A ADR-0009 fixou `QuotaFilter.Filter` no preflight e o `UsageRecorder` como
observador; a ADR-0010 fixou que o `Dispatcher` **reporta** `Usage` por tentativa e
**consulta** o filtro, sem decidir política. Esta ADR congela **o modelo de cota**
— onde o estado vive, o que é durável, qual é a unidade e como o `% restante`
vira decisão.

O contexto de provedores é concreto: assinaturas e planos com limite por
**janela** (ex.: uma janela curta de ~5h e uma longa de ~7d), sinalizados por
headers passivos do upstream (`x-ratelimit-*`, `resets_at`) quando existem, e sem
contador confiável quando não existem. A cota é **da conta** (`CredentialID`,
ADR-0001), não do provider: duas contas da mesma família têm cotas independentes.

O repo já tem a base: SQLite WAL single-writer (`internal/store`, migrações
numeradas), `contracts.Clock` (janelas) e `contracts.IDGen` (chaves idempotentes).

## Decisão

### 1. `QuotaFilter` e observadores — onde cada um age

```go
// QuotaFilter roda no PREFLIGHT (o Router o consome ao montar o RoutePlan, e o
// Dispatcher o consulta antes de cada tentativa). Ele NÃO é gate de conteúdo.
type QuotaFilter interface {
    // Filter recebe o plano e devolve o plano com candidatos sem cota removidos
    // (ou rebaixados, conforme a estratégia da ADR-0009 §2) e a lista de Skips
    // (explicabilidade: por que cada um saiu). É PURO sobre o estado lido.
    Filter(ctx context.Context, plan RoutePlan) (RoutePlan, []Skip)
}

// Skip explica por que um candidato foi filtrado; vira observabilidade e
// Reason.Notes. Nunca é instrução.
type Skip struct {
    Candidate Candidate
    Reason    string // "quota_remaining_below_cutoff", "breaker_open", ...
    Code      string // i18n: quota.* ou o code do último Record
}

// UsageRecorder é OBSERVADOR: recebe Usage por tentativa e mantém o estado que
// o QuotaFilter lê. Nunca bloqueia o caminho do request.
type UsageRecorder interface {
    // Record aplica um Usage e atualiza o estado de cota. IDEMPOTENTE pela
    // chave de tentativa (ver §4).
    Record(ctx context.Context, u Usage) error
    // Snapshot devolve o estado atual de uma credencial (o QuotaFilter lê daqui).
    Snapshot(ctx context.Context, cred domain.CredentialID) (QuotaState, bool)
}
```

`QuotaFilter` e `Breaker` (ADR-0012) formam o **preflight**; `UsageRecorder` é o
observador que atualiza o estado. Nenhum deles é `contracts.Gate`.

### 2. Unidade: por CREDENCIAL e por JANELA

O estado de cota é uma **coleção de janelas** por credencial. Cada janela:

```go
// QuotaWindow é uma janela de limite de UMA credencial.
type QuotaWindow struct {
    Kind      WindowKind // WindowShort (~5h) | WindowLong (~7d) | WindowCost (cap de custo)
    Limit     float64    // teto (tokens, requests ou micros de custo); 0 = desconhecido
    Used      float64    // consumido na janela
    Remaining float64    // 0..1 (fração restante), quando Limit conhecido
    ResetsAt  time.Time  // quando a janela reinicia (zero = desconhecido)
    Source    QuotaSource // Header | LocalCounter | RetryHint
    UpdatedAt time.Time
}

// QuotaState é o estado por credencial: as janelas + procedência.
type QuotaState struct {
    Credential domain.CredentialID
    Windows    []QuotaWindow
    // Terminal marca um estado que NÃO é recuperável por esperar a janela
    // (ex.: cota de plano cancelado). Distinto de "janela esgotada".
    Terminal   Code
}
```

Regras:

1. **Unidade é a credencial.** `QuotaState` é indexado por `CredentialID`; a chave
   do breaker de cota também é a credencial (ADR-0012 §2), nunca o provider.
2. **`% restante`, não "usado > X".** A decisão de preflight é:
   `Remaining <= cutoff` ⇒ bloqueia. O `cutoff` é configurável por janela
   (ex.: 0.05 = reserva os últimos 5%); é uma **fração**, então funciona mesmo
   quando o limite é desconhecido e a janela é estimada. Comparar
   `Used > X` quebraria quando `X` muda entre planos e não deixa margem.
3. **A janela mais restritiva manda.** Um candidato é elegível só se **todas**
   as suas janelas não-terminais estão acima do cutoff. A janela `Cost` (cap de
   custo) é uma janela como as outras.
4. **Sem limite conhecido ⇒ fail-open com contador local.** Se o upstream não
   informa limite, a janela tem `Limit=0` e o filtro **não bloqueia por ela**;
   o contador local (tokens/requests observados) existe para observabilidade e
   para o caso em que o operador declara um teto no config.
5. **Terminal ≠ esgotado.** Uma janela pode reiniciar (`ResetsAt`); um estado
   `Terminal` (plano cancelado, saldo zerado sem reset) **não** reabre por tempo
   e deve ser tratado como credencial inválida (ADR-0002 §2), não como cooldown.

### 3. Fontes de verdade, por ordem de confiança

1. **Headers passivos do upstream** (mais confiável, custo zero): quando a
   resposta traz `x-ratelimit-remaining` / `x-ratelimit-reset[-after]` /
   `resets_at`, o Dispatcher converte em `Usage.Window` e/ou `DomainError.RetryAfter`
   (ADR-0002 §7) e o `UsageRecorder` grava `Source=Header`. **Não** se faz uma
   chamada extra só para ler cota.
2. **Contadores locais** (fallback): tokens/requests/custo observados no
   `Usage` acumulados por janela. São a única fonte quando o provider não expõe
   cota; sujeitos a deriva (o upstream pode contar diferente), então servem para
   **estimativa**, com margem via `cutoff`.
3. **`Retry-After`/reset como hint**: um `429` com `RetryAfter` (ADR-0002 §7)
   **reancora** `ResetsAt` da janela correspondente; é o sinal mais direto de
   "esgotou até aqui".

Conflito entre fontes: **header > RetryHint > contador local**, e a fonte fica
registrada em `Source` para auditoria.

### 4. Persistência: o que é durável vs efêmero

- **Contadores locais e `ResetsAt` de janela são DURÁVEIS** (SQLite WAL): um
  reinício do daemon não pode "esquecer" que a cota curta foi gasta — isso é
  exatamente o que causaria um estouro do plano do operador. Gravados em migração
  `000N_quota.sql`.
- **In-flight por credencial (contagem de tentativas concorrentes) é EFÊMERO**
  (memória, por processo): é telemetria de pressão do `p2c` (ADR-0009 §5), reinicia
  no boot como o cursor de round-robin (ADR-0009 §4/ADR-0013 §5).
- **Escrita fora do caminho do request.** O `UsageRecorder` é um observador: a
  gravação acontece em um `AsyncSink` (canal limitado + goroutine), nunca
  bloqueando o `Dispatcher`. Pressão alta derruba o `Usage` **mais antigo**
  (último valor vence por janela) em vez de bloquear; o estado de cota é
  reconstruível do próximo header e tolera perder uma amostra.
- **Precisão.** Contadores são `float64` (tokens/micros) com janela de reset
  explícita; `Remaining` é uma fração `[0,1]`. Não se armazena o corpo da
  resposta — só números.
- **Idempotência.** Cada `Usage` carrega uma `AttemptKey` determinística
  (`{request_id}:{candidate}:{seq}`, gerada com `IDGen`); o `UsageRecorder` é
  idempotente por essa chave. Reentrega não duplica (o `Dispatcher` pode
  reportar em retry do sink). Um **uso parcial** (stream abortado, §5) usa a
  mesma chave com `Outcome=aborted`, portanto **substitui**, não soma.

```sql
CREATE TABLE IF NOT EXISTS quota_windows (
    credential_id TEXT NOT NULL,
    kind          INTEGER NOT NULL,   -- short|long|cost
    used          REAL NOT NULL,
    limit_value   REAL NOT NULL,      -- 0 = desconhecido
    resets_at     TEXT,               -- RFC3339, NULL = desconhecido
    source        INTEGER NOT NULL,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (credential_id, kind)
);
CREATE TABLE IF NOT EXISTS usage_attempts (
    attempt_key   TEXT PRIMARY KEY,   -- idempotência
    credential_id TEXT NOT NULL,
    provider_id   TEXT NOT NULL,
    model         TEXT NOT NULL,
    tokens        INTEGER NOT NULL,
    requests      INTEGER NOT NULL,
    cost_micros   INTEGER NOT NULL,
    outcome       TEXT NOT NULL,      -- ok|error|aborted
    created_at    TEXT NOT NULL
);
```

Single-writer (ADR-010): `upsert` da janela e do `usage_attempt` passam pela
writer connection; `Snapshot` (lido no preflight) usa o read pool.

### 5. Uso parcial e abort

Um stream que aborta no meio (cliente desconectou, idle estourou) **já gastou
cota** no upstream. O `Dispatcher` reporta `Usage{Outcome: aborted, Tokens: <os
observados até o abort>}` com a mesma `AttemptKey` da tentativa; o recorder
**substitui** o registro (idempotente). Isso evita a mentira de "uso zero" para
um stream que consumiu tokens.

### 6. Relação com o `Breaker` (ADR-0012)

- **Cota esgotada é `ScopeCredential`** (ADR-0002 §3): cooldowna a **credencial**
  até `ResetsAt`; **não** abre o circuito do **provider**. Um provider inteiro
  não é punido porque uma conta bateu no plano.
- O cooldown de cota usa **`RetryAfter`** (que o recorder derivou de
  `Remaining`/`ResetsAt`); só cai em backoff exponencial quando não há reset
  conhecido (ADR-0002 §3).
- **A cota é um FILTRO, o breaker é outro.** Ambos rodam no preflight (ADR-0010
  §2, passo 1), mas com estados distintos; um `Skip` de cota não é um `Record` de
  falha de provider.

### 7. Códigos i18n

- `quota.exhausted` (429/`ScopeCredential`/`Retryable=true`/`RetryAfter=ResetsAt`)
- `quota.rate_limited` (429/`ScopeCredential`/`Retryable=true`/`RetryAfter` do header)
- `quota.cost_cap` (429/`ScopeCredential`/`Retryable=true`/`RetryAfter` da janela de custo)
- `quota.invalid_credential` (400/`ScopeRequest`/`Retryable=false`)

Todos já tabelados na ADR-0002 §"quota.*"; esta ADR fixa **como** `Remaining`,
`ResetsAt` e `RetryAfter` são produzidos.

## Consequências

- **F3 entrega:** migração `000N_quota.sql` (`quota_windows`, `usage_attempts`);
  um `StoreQuotaRecorder` (SQLite) e um `MemoryQuotaRecorder` (testes); o
  `QuotaFilter` como leitura pura do `Snapshot`; e o `Usage` reportado pelo
  `Dispatcher` (ADR-0010 §4).
- **Estado durável de cota** evita o estouro silencioso após reinício; o custo é
  uma escrita fora do caminho do request (AsyncSink), aceitável pela baseline
  (`reviews/f1-performance-baseline.md` §6: `Upsert` 34 µs, fora do TTFT).
- **`% restante` + `cutoff`** dá uma decisão única, testável, que não depende de
  "usado > X" nem do limite ser conhecido.
- **Testes:** com `Clock`/`IDGen` fixos, um `UsageRecorder` in-memory e um
  `QuotaFilter`, os casos são reproduzíveis — "cota esgotada filtra o candidato e
  o Dispatcher tenta o próximo" (validação de F3), "uso parcial em abort
  substitui", "duas tentativas = dois `Usage`", "`429` reancora `ResetsAt`".

## Alternativas consideradas

- **Cota como `Gate` (`QuotaGate`).** Rejeitada (ADR-0009; revisão nº 2): não vê o
  resultado da tentativa e não pode reavaliar entre tentativas.
- **Bloquear por `Used > X` (limiar absoluto).** Rejeitada: `X` varia por plano,
  não dá margem para deriva do contador local e quebra quando o limite é
  desconhecido. A decisão é `Remaining <= cutoff`.
- **Só contadores locais (sem headers).** Rejeitada: deriva do contador local
  causa estouro; o header passivo é grátis e autoritativo quando existe.
- **Só headers (sem contador local).** Rejeitada: muitos provedores não expõem
  cota; sem fallback o filtro é cego.
- **Estado de cota só em memória.** Rejeitada: um reinício esqueceria a janela
  curta gasta e estouraria o plano do operador. Durable pela razão oposta à do
  cursor de round-robin (esse é ordenação; este é limite).
- **`UsageRecorder` síncrono no caminho do request.** Rejeitada (revisão nº 2):
  escrita SQLite no TTFT; o observador é assíncrono.
- **Contar cota por provider.** Rejeitada: a cota é da conta (ADR-0001); contar
  por provider fundiria contas de planos diferentes.
