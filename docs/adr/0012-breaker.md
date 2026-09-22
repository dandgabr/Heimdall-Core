# ADR-0012 — `Breaker`: escopos, cooldown e half-open

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F3 (Router, Combos e Cotas)
- **Relaciona-se com:** ADR-0002 (taxonomia/`Scope`), ADR-0009 (`Breaker.State` no preflight), ADR-0010 (`Dispatcher` faz `Record`), ADR-0011 (cota ≠ breaker), ADR-0001 (`ProviderFamily` × `Credential`)

## Contexto

Sem um circuito, um provider em outage é martelado: cada request paga TTFT e
queima tentativas antes de falhar, e um `400` de payload inválido cooldownaria uma
conta sadia (defeito apontado na revisão, `notes/revisao-plano-arq-sec.md`,
mudança estrutural nº 4). A ADR-0002 congelou a **classificação** de erro
(`Scope`/`Retryable`/`RetryAfter`) e o que cada `Scope` significa para o breaker;
a ADR-0009 fixou que `Breaker.State` é consultado no **preflight** (o Router
filtra, o Dispatcher consulta); a ADR-0010 fixou que o **Dispatcher** faz os
`Record`s. Esta ADR congela **a máquina de estados**: os três escopos, o cooldown
e o half-open.

O repo já tem `contracts.Clock` (tempo determinístico) e SQLite WAL single-writer
(`internal/store`); a decisão aqui é **onde** o estado vive e **como** transita.

## Decisão

### 1. Três escopos

O estado de circuito é mantido por **três chaves** independentes:

| Escopo | Chave | Punido por | Efeito do aberto |
| --- | --- | --- | --- |
| **Provider** | `{ProviderID}` | `ScopeProvider` (5xx/408/502/503/504, rede/TLS/DNS) | filtra **todos** os candidatos daquele provider |
| **Connection/Credential** | `{ProviderID, CredentialID}` | `ScopeCredential` (401/403, cota/429) | filtra **aquela conta**; outras contas da família seguem |
| **Model** | `{ProviderID, ModelID}` | `ScopeProvider` quando o erro é específico do modelo (ex.: `bad_upstream_response` recorrente de um modelo) | filtra **aquele modelo**; os demais do provider seguem |

Regras:

1. **Um `ScopeProvider` abre os escopos Provider E Model** (o modelo é um recorte
   fino do mesmo sinal). Um `ScopeCredential` abre **só** o escopo Connection.
2. **Erro do cliente (`ScopeRequest`) NUNCA faz `Record`** — nenhum escopo abre
   (ADR-0002 §1). É a regra que impede um `400` de derrubar uma conta sadia.
3. **A cota é `ScopeCredential`, mas o breaker de cota é o da credencial com
   cooldown = `RetryAfter`/`ResetsAt`** (ADR-0011 §6). Cota esgotada **não** abre
   o escopo Provider.

### 2. Classificação por ADR-0002 (tabela de decisão)

O Dispatcher entrega ao breaker um `Record{Scope, Retryable, RetryAfter, Code}` já
extraído do `DomainError`. O breaker decide **somente** por esses campos
tipados — é proibido classificar por `Code` ou `HTTPStatus` (ADR-0002).

| Origem | Scope | Retryable | Ação do breaker |
| --- | --- | --- | --- |
| `400`/`404`/`405`/`413`/`415`/`422` (cliente) | Request | não | **nenhum** `Record` |
| `401`/`403` de credencial upstream | Credential | não | 1 falha; após **N=3** (config) → credencial inválida (terminal) |
| `429`/cota com `RetryAfter`/`resets_at` | Credential | sim | cooldown **até o reset**, não exponencial |
| `429`/rate sem hint | Credential | sim | cooldown = backoff exponencial + jitter |
| `408`/`5xx`/`502`/`503`/`504` | Provider | sim | abre Provider+Model; cooldown exponencial |
| rede/DNS/TLS | Provider | sim | idem |
| `error.internal` (bug do núcleo) | Request | não | **nenhum** `Record` |
| `auth.token_expired` | Credential | sim | **não** cooldowna; dispara refresh (ADR-0002 §6) |
| `auth.credential_invalid`/`scope_insufficient` | Credential | não | marca inválida (terminal) |

### 3. Cooldown: exponencial com base e teto, anti-thundering-herd

- **Fórmula:** `cooldown = min(Base * 2^(failures-1), MaxCooldown)`, com **jitter**
  em `[0.5x, 1.0x]` do valor (evita sincronia entre processos). `Base` e
  `MaxCooldown` são configuráveis; defaults documentados em F3.
- **`RetryAfter` vence:** quando o `Record` traz `RetryAfter > 0` (cota/`429`), o
  cooldown é **exatamente** esse valor — não se aplica exponencial (ADR-0002 §3).
- **Anti-thundering-herd (mutex por chave):** o `Record` e o cálculo de `OpenUntil`
  acontecem sob um **lock por chave de escopo**. Dois `Record`s concorrentes da
  mesma chave **não estendem** o cooldown duas vezes: o segundo observa o estado
  já atualizado e, se `OpenUntil` já está no futuro, **não empilha** — no máximo
  conserva o maior `OpenUntil`. Isso impede que N requests simultâneos ao mesmo
  provider empurrem o cooldown para o infinito ("extensão duplicada").
- **Contador de falhas** por chave: incrementa no `Record` de falha; zera no
  `Record` de **sucesso** da mesma chave (§4).

### 4. Estados terminais NÃO são sobrescritos por cooldown transiente

O estado de cada chave é **uma** de:

```
Closed      — saudável.
Open        — em cooldown até OpenUntil.
HalfOpen    — cooldown expirou; permite UMA sonda.
Terminal    — inválido até ação humana: banned | credits_exhausted | expired.
```

Regras:

1. **`Terminal` é absorvente.** Um estado terminal (`auth.credential_invalid`,
   `scope_insufficient`, plano cancelado/cota sem reset da ADR-0011 §2.5) **não é
   reaberto** por um cooldown transiente nem por tempo. Só uma ação explícita
   (reautenticar, trocar a chave) o limpa. Um `Record` transiente em chave
   terminal é **ignorado** para transição de estado (mas ainda é observável).
2. **Tipo terminal:** `banned` (conta banida), `credits_exhausted` (saldo
   zerado sem reset), `expired` (credencial expirada/revogada). O tipo fica no
   estado para a GUI/CLI explicarem o porquê.
3. **N falhas consecutivas de credencial não-retryable** (padrão 3, ADR-0002 §2)
   promovem a credencial a `Terminal{banned}` **sem** passar por `Open`.

### 5. Half-open: quando e como sondar

- **Transição `Open → HalfOpen` por tempo:** quando `Clock.Now() >= OpenUntil`, a
  chave passa a HalfOpen **na leitura** (lazy, sem goroutine de timer).
- **Uma sonda por vez:** em HalfOpen, o **primeiro** `Allow` que chega é liberado
  (sonda); os demais veem `Open` até a sonda resolver. Um lock por chave garante
  a exclusividade da sonda (anti-herd na reabertura).
- **Resultado da sonda:**
  - **sucesso** → `Close` (falhas=0, `OpenUntil` limpo);
  - **falha retryable** → volta a `Open` com cooldown **dobrado** (o expoente
    continua de onde parou), até o teto.
- **Reset por sinal de sucesso:** qualquer **sucesso** de um escopo fecha aquele
  escopo imediatamente — não se espera o cooldown expirar se um caminho saudável
  já provou que o serviço respondeu (o sucesso é o sinal mais forte).
- **Cota:** não há half-open de cota enquanto `Remaining <= cutoff`; a sonda de
  cota é o próprio reset (`ResetsAt`), pois tentar antes só gastaria a chamada.
  Quando `ResetsAt` passa, a janela reabre na leitura (ADR-0011 §2).

### 6. Interface e onde o estado vive

```go
// Breaker é consultado no PREFLIGHT e atualizado pelo Dispatcher (Record).
type Breaker interface {
    // State devolve o estado atual de um escopo sem alterar o contador de
    // falhas. A transição Open->HalfOpen por tempo acontece aqui (lazy).
    State(ctx context.Context, key ScopeKey) State
    // Allow combina State + a reserva da sonda em HalfOpen (uma sonda por vez).
    Allow(ctx context.Context, key ScopeKey) (bool, State)
    // Record aplica o resultado de UMA tentativa. É o único mutador; recebe
    // campos TIPADOS (ADR-0002), nunca Code/HTTPStatus.
    Record(ctx context.Context, key ScopeKey, r Outcome) error
}

type ScopeKey struct {
    Kind       ScopeKind // Provider | Connection | Model
    Provider   domain.ProviderID
    Credential domain.CredentialID // só em Connection
    Model      domain.ModelID      // só em Model
}

type Outcome struct {
    Scope      domain.ErrScope
    Retryable  bool
    RetryAfter time.Duration // >0 vence o exponencial
    Terminal   Code          // não-vazio promove a terminal (§4)
}
```

- **Estado vive em MEMÓRIA (por processo)**, com um `sync.Mutex` por chave (mapa
  de chaves → estado). É **efêmero**: reiniciar o daemon reinicia os circuitos —
  mesma postura do cursor de round-robin (ADR-0009 §4/ADR-0013 §5) e oposta à
  cota durável (ADR-0011 §4). A diferença é intencional: cota esquecida causa
  estouro de plano; circuito esquecido apenas custa algumas tentativas até
  reabrir, e um provider saudável se recupera de imediato.
- **Consulta no Router (preflight):** `QuotaFilter.Filter` (ADR-0011) e
  `Breaker.State`/`Allow` são o preflight que remove/rebaixa candidatos (ADR-0009
  §1.3, ADR-0010 §2 passo 1). O Router chama sem mutar; o Dispatcher chama
  `Allow` por candidato e `Record` por tentativa.
- **Persistência de terminal (opcional, F3):** um estado terminal de **credencial**
  pode ser espelhado durável (`credentials` já existe) para sobreviver ao
  reinício; circuitos transientes (Provider/Model) ficam só em memória.

### 7. Códigos i18n

- `breaker.open` (`Reason`/observabilidade: `params={scope,retry_after}`) — um Skip
  de preflight quando o circuito está aberto; não é erro devolvido ao cliente por
  si, mas acompanha o agregado (ADR-0010 §6).
- `breaker.terminal` (`ScopeCredential`/`Retryable=false`, `params={provider,credential,reason}`)
  — credencial terminal (`banned|credits_exhausted|expired`).

Entram no catálogo `pt-BR`/`en` na F3.

## Consequências

- **F3 entrega:** um `Breaker` in-memory com lock por chave, a tabela de decisão
  da §2, o cooldown §3, os estados terminais §4 e o half-open §5; um `FakeBreaker`
  determinístico (com `Clock`) para os testes do Dispatcher.
- **O breaker nunca classifica por string:** ele só lê `Scope`/`Retryable`/
  `RetryAfter`/`Terminal`, então um novo `Code` (ADR-0002) entra sem mudar código.
- **Cota e falha são estados separados:** uma credencial pode ter a janela gasta
  (ADR-0011) e o circuito fechado, ou vice-versa — os dois preflight checks são
  independentes.
- **Anti-thundering-herd e anti-extensão de cooldown** são o ponto de corretude
  sob concorrência; o teste de F3 "breaker não cooldowna por erro de cliente"
  roda com um `400` e prova **zero** transições.
- **Estado efêmero documentado:** reiniciar o daemon reabre circuitos transientes;
  aceito no v1 (mesma classe do cursor de rotação).

## Alternativas consideradas

- **Classificar o escopo pelo `Code`/`HTTPStatus`.** Rejeitada (ADR-0002,
  "Alternativas"): `401` pode ser auth do cliente ou credencial upstream; a tabela
  tipada é o contrato.
- **Um breaker por provider apenas.** Rejeitada: um `401` de UMA conta derrubaria
  todas as contas da família; a cota é por conta (ADR-0001/ADR-0011).
- **Um breaker global.** Rejeitada: um provider em outage pararia o roteamento
  inteiro; o escopo Provider já é o grão certo.
- **Persistir todo o estado do breaker.** Rejeitada no v1: escrever em SQLite a
  cada falha no caminho do request é caro (baseline `Upsert` 34 µs, mas fora do
  TTFT); circuitos transientes recuperam rápido e a memória basta. Só o terminal
  de credencial pode ser espelhado.
- **Half-open com N sondas concorrentes.** Rejeitada: N sondas simultâneas
  re-martelam um provider que ainda está caído; uma sonda por vez é o ponto do
  padrão.
- **Reabrir terminal por tempo.** Rejeitada: mascararia banimento/cota zerada e
  faria o Dispatcher queimar chamadas contra um estado que não muda.
- **Goroutine de timer para fechar o circuito.** Rejeitada: um timer por chave é
  custo e ciclo de vida desnecessários; a transição é lazy na leitura (`Clock`
  injetável mantém o teste determinístico).
