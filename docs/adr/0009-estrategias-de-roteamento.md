# ADR-0009 — Semântica das estratégias de roteamento

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F3 (Router, Combos e Cotas)
- **Relaciona-se com:** ADR-0013 (combos como DAG), ADR-0001 (ProviderFamily × Credential), ADR-0002 (taxonomia de erro)

## Contexto

O `Router` é o componente que transforma um pedido em um **plano de tentativas
ordenado**. A revisão de arquitetura (`notes/revisao-plano-arq-sec.md`, mudança
estrutural nº 2) separou três responsabilidades que o plano v1 confundia:

- o **`Router`** decide *quem tentar e em que ordem* — não chama upstream;
- o **`Dispatcher`** é o dono do laço de tentativas/failover/accounting — é quem
  fala com o `Executor`;
- **cota não é gate**: `QuotaFilter` + `Breaker` (preflight, consumidos pelo
  Router) e `UsageRecorder` (observador).

O plano v2 lista dez estratégias (`fallback`, `priority`, `round-robin`,
`weighted`, `fill-first`, `cost`, `p2c`, `fusion`, `pipeline`, `auto`) sem
definir a semântica de cada uma. Sem essa definição, cada estratégia é
implementada por intuição e duas delas divergem no que "estado" significa (ex.:
`round-robin` precisa de um cursor que sobrevive a requests; `auto` precisa não
ter estado nenhum). Esta ADR congela a semântica **antes** de a F3 começar.

O repo já tem as peças que o Router consome: `contracts.Capabilities` (bitset de
`CapStream`/`CapTools`/…), `contracts.ModalitySet`, `ProviderFamily.Capabilities(model)`,
`providers.OpenAICompat.Models()`, e o registry determinístico (`providers.Registry.All()`).
O Router é uma camada NOVA sobre essas peças.

## Decisão

### 1. Contrato de saída do Router

O Router produz um **`RoutePlan`** — uma lista de `Candidate`s com uma política de
laço. Ele **não** executa, **não** abre credencial e **não** persiste.

```go
// RoutePlan é o resultado de Router.Resolve. Attempts é ordenada: o Dispatcher
// tenta na ordem. MaxRounds limita o laço do Dispatcher (fusion/pipeline/failover)
// para impedir retry infinito.
type RoutePlan struct {
    Combo     domain.ComboID   // zero = resolução automática implícita
    Attempts  []Candidate
    MaxRounds int              // teto de rodadas do Dispatcher (>=1)
    Strategy  StrategyKind
}

// Candidate é UMA tentativa possível: família, modelo e (quando escolhida) a
// conta concreta. Score é a pontuação que a estratégia usou; Reason é a
// explicabilidade — por que ESTE candidato e nesta posição.
type Candidate struct {
    Provider  domain.ProviderID
    Model     domain.ModelID
    // Credential zero = "qualquer credencial sadia da família"; o Dispatcher
    // escolhe. Preenchida quando a estratégia é account-aware (fill-first,
    // round-robin de contas).
    Credential domain.CredentialID
    Score      float64
    Reason     CandidateReason
}

// CandidateReason é dado de observabilidade (logs/audit/GUI), nunca decisão.
type CandidateReason struct {
    Strategy StrategyKind
    // Notes são os fatores legíveis: "priority=10", "quota_remaining=0.8",
    // "capability_fit=vision", "round_robin_cursor=3".
    Notes []string
}
```

Invariantes do plano:

1. `Attempts` **nunca** é vazia com erro nil: lista vazia + erro nil é impossível;
   esgotamento é `DomainError` com `Scope=ScopeRequest` (ver §7).
2. `Attempts` é **determinística** para a mesma entrada, estado e seed (ver §4).
3. `Attempts` já passou pelo **preflight** (`QuotaFilter.Allow` + `Breaker.State`):
   candidato com cota esgotada ou circuito aberto não entra (ou entra rebaixado —
   ver a estratégia).
4. `MaxRounds` é sempre finito e `>= 1`. Nenhuma estratégia produz plano sem teto.

### 2. Tabela de estratégias

| Estratégia | Ordena por | Estado | Determinismo | Notas |
| --- | --- | --- | --- | --- |
| `priority` | `priority` declarada no passo (maior primeiro); empate por nome | **nenhum** (a prioridade vive no combo/config) | **total** (sem seed) | Desempate estável: `provider`, depois `model`, lexicográfico. É a base do `fallback`. |
| `fallback` | ordem declarada dos passos (índice do passo) | **nenhum** | **total** | Não reordena por saúde; tenta na ordem, `MaxRounds` = nº de passos. |
| `round-robin` | cursor rotativo entre candidatos de **mesma prioridade** | **in-memory** (cursor por `(combo, tier)`), **não persiste** | **total dado o cursor**; a 1ª escolha de um processo novo depende do cursor inicial | O estado é do processo: reinício reinicia o cursor (documentado na ADR-0013 §5). |
| `weighted` | **sorteio proporcional ao `weight` do passo, POR REQUEST** | **nenhum** (peso é dado; RNG é o estado) | **total com seed injetada** (TDD); não determinístico sem seed, por definição | Não é rotação: cada request sorteia independentemente. Se `weight` for 0/ausente, trata como 1. |
| `fill-first` | esgota a **credencial corrente** de um provider/passo antes de passar à próxima | **in-memory** (ponteiro de credencial corrente por provider) | **total dado o ponteiro** | Usa `QuotaFilter` para saber quando "esgotou". Ordena as contas, não os providers. |
| `cost` | custo estimado **crescente** (`CostMicros`/token do catálogo) | **nenhum** (catálogo é dado) | **total** (custos iguais → desempate por nome) | Estima por `Usage`/modelo; sem preço conhecido, o candidato vai para o fim. |
| `p2c` | "power of two choices": sorteia **2** candidatos e escolhe o de **menor pressão** (cota restante ↑, latência ↓, in-flight ↓) | **nenhum** persistido; usa contadores in-flight do processo | **total com seed injetada**; não determinístico sem seed | Sorteio precisa de RNG injetável (`Seed`). Empate → desempate estável por nome. |
| `fusion` | fan-out **paralelo** com juiz (§3) | efêmero por request | determinístico dado o conjunto e o juiz; as respostas paralelas são não-determinísticas em ordem | Custo N×. `MaxRounds` cobre a reentrância do juiz (§3). |
| `pipeline` | passos **sequenciais**: saída N vira entrada N+1 | efêmero por request | **total** | Só a resposta do ÚLTIMO passo volta ao cliente. Passos intermediários não commitam. |
| `auto` | pontuação ponderada por fatores (§5) | **nenhum** (fatores são dados do processo) | **total** (determinístico e explicável; **não aprende**) | É a estratégia default quando o combo não declara política. |

### 3. `fusion` — fan-out paralelo + juiz

`fusion` envia a **mesma** request a N candidatos em paralelo, coleta as
respostas e um **juiz** escolhe/sintetiza. É a única estratégia com custo
multiplicativo.

- **Cap de fan-out:** `N <= MaxFanout` (configurável, teto rígido no binário).
  Um combo que peça fan-out acima do cap é recusado no save (ADR-0013 §3).
- **Quorum e graça:** dispara os N; aceita como "completos" os que responderem
  dentro da **graça** (`grace`, um `Clock.After`). Não espera o mais lento além da
  graça; um candidato que estoure o prazo é abandonado (cota já gasta, custo
  aceito — documentado).
- **Timeout:** a fusão inteira é limitada pelo `ctx` do cliente; cada ramo tem o
  TTFT/idle do seu executor.
- **Juiz e REENTRÂNCIA:** o juiz é uma **request normal** que volta a entrar pela
  pipeline (`GateChain` → `Router` → `Dispatcher`). Por isso:
  - o juiz é resolvido por um **combo/rota próprio** e o plano de rota do juiz
    NÃO pode ser `fusion` (senão recursão infinita);
  - o plano carrega **profundidade** (`depth`); `depth > MaxDepth` é recusado
    (ADR-0013 §3 valida o DAG);
  - a reentrância é limitada por `MaxRounds`.
- **Custo N×:** fan-out de N chamadas paga N× de cota/custo; `Reason` registra
  `fanout=N` para auditoria.
- **Pós-commit:** cada ramo é uma tentativa pré-commit; a fusão só commita quando
  o juiz decide. Nenhum ramo commita downstream antes disso (invariante de
  streaming herdado).

### 4. Determinismo e seed

- **Seed injetável:** estratégias com sorteio (`weighted`, `p2c`) recebem um
  `*rand.Rand` (ou `Seed int64`) por `Clock`/DI. Em produção a seed é o relógio;
  em teste é fixa. Sem seed injetada, o comportamento é explicitamente
  não-determinístico — e isso é uma propriedade declarada, não um bug.
- **Desempate estável sempre:** qualquer empate de score é resolvido por
  `(Provider, Model, Credential)` lexicográfico. Isso garante que o plano seja
  reproduzível mesmo quando dois candidatos têm o mesmo score.
- **Estado in-memory nunca muda a VALIDADE**, só a ordem: uma estratégia com
  estado (round-robin, fill-first) sempre produz um plano válido; seu cursor só
  decide qual dos equivalentes vem primeiro.

### 5. `auto` — pontuação por fatores (determinístico, sem aprendizado)

`auto` soma fatores normalizados em `[0,1]`, com **pesos que somam 1.0**:

```
score = w_quota   * quota_remaining
      + w_health  * breaker_health          // 1.0 fechado, 0.0 aberto
      + w_cost    * (1 - normalized_cost)   // custo inverso
      + w_latency * (1 - normalized_latency)// latência inversa (média móvel)
      + w_tier    * tier_rank               // plano/preferência do operador
      + w_capfit  * capability_fit          // 1.0 se atende a modalidade/caps do request
```

- Pesos default somam `1.0` e são **configuráveis**, sempre renormalizados para
  somar `1.0` se o operador mexer.
- **NÃO aprende.** Não há feedback de resultado alterando pesos; é uma função
  pura dos dados do processo + catálogo. A "inteligência" é o preflight, não um
  modelo. Isso é deliberado: uma pontuação explicável é auditável; um peso
  aprendido não é.
- `Reason.Notes` carrega cada fator, tornando a decisão reproduzível no log.

### 6. `pipeline` — passos sequenciais

- Cada passo recebe a **saída do passo anterior** como entrada (N → N+1).
- Somente a resposta do **último** passo retorna ao cliente; os intermediários
  não commitam e não são observáveis pelo cliente.
- Um passo que falha é erro terminal (a menos que o combo declare `fallback_only_on_quota_exhaustion`,
  ADR-0013 §2, que troca o passo por outro da mesma posição).
- `MaxRounds` = nº de passos (sem retry implícito; failover é por posição).

### 7. Falha e esgotamento

- `RoutePlan` vazio é sempre erro tipado: `route.no_candidate`
  (`ScopeRequest`, `Retryable=false` — o request não é atendível, não cooldowna).
- Cota esgotada / circuito aberto **filtram** antes de gerar o plano. Um candidato
  filtrado não aparece (a menos que a estratégia o rebaixe, como `cost`/`auto`
  com score baixo — mas nunca é escolhido enquanto houver alternativa sadia).
- O Router **nunca** retenta: retentativa é do Dispatcher, guiada pelo plano e
  pela taxonomia de erro (ADR-0002).

## Consequências

- **F3 implementa uma única interface `Router.Resolve(ctx, RouteRequest) (RoutePlan, error)`
  e um `StrategyKind` por estratégia em `internal/router/strategies/`.** Cada
  estratégia é testável isoladamente com `Clock`/seed/estado injetados.
- **`Reason` é obrigatório em todo candidato**: a GUI/CLI pode explicar por que
  uma rota foi escolhida, e a auditoria sabe qual fator pesou.
- **Estado in-memory é explícito** (round-robin, fill-first) e **não persiste**:
  reiniciar o daemon reinicia cursores. Isso é aceito no v1 (documentado).
- O **custo N×** de `fusion` e o fan-out capado são pré-requisitos da validação
  de F3 ("fusion não recursiona").
- Novas estratégias são aditivas: um novo `StrategyKind` não muda as existentes.
- Os códigos i18n novos (`route.no_candidate`, `route.invalid_combo`,
  `route.cyclic_combo`, `route.depth_exceeded`, `route.fanout_exceeded`,
  `route.unknown_provider`) entram no catálogo `pt-BR`/`en` quando a F3
  implementar; esta ADR os nomeia para o implementador não inventar strings.

## Alternativas consideradas

- **Uma estratégia só, com pesos.** Rejeitada: os casos de uso (barato vs. rápido
  vs. cota esgotada vs. fusão) têm semânticas incompatíveis; unificá-los produz um
  score que ninguém entende nem audita.
- **Persistir o cursor de round-robin.** Rejeitada no v1: escrever em SQLite no
  caminho do request por causa de ordenação é caro e desnecessário; o cursor é
  efêmero por processo. Reavaliar se houver requisito de continuidade entre reinícios.
- **`auto` com aprendizado (pesos ajustados por resultado).** Rejeitada: perde
  explicabilidade e auditabilidade; a decisão tem de ser reconstruível a partir
  do log. Pode entrar como estratégia separada no futuro, nunca substituindo `auto`.
- **`weighted` como rotação ponderada com estado.** Rejeitada: `weighted` é
  sorteio por request (sem estado); quem quer rotação ponderada usa `round-robin`
  com pesos, que é outro nome e outro estado.
- **`p2c` com três escolhas.** Rejeitada: "power of two" é o algoritmo nomeado;
  adicionar terceiros muda o nome e o comportamento sem ganho comprovado.
- **Fusion sem juiz (só vencedor "primeiro a responder").** Rejeitada: o juiz é o
  ponto da fusão (sintetizar/escolher com contexto); "primeiro a responder" é um
  fan-out sem valor e já é coberto por `p2c`/`fallback`.
