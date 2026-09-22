# ADR-0013 — Combos nomeados como DAG validado

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F3 (Router, Combos e Cotas)
- **Relaciona-se com:** ADR-0009 (estratégias de roteamento), ADR-0001 (ProviderFamily × Credential), ADR-0002 (taxonomia de erro)

## Contexto

Um **combo** é uma rota nomeada e reutilizável: o operador declara "para este nome,
tente estes modelos/provedores nesta política" e passa a referenciá-lo pelo nome
(`model: <combo>` na request). O plano v2 (F3) exige que um combo seja:

- **nomeado e persistido** (sobrevive a reinícios);
- composto por **passos** de três tipos (`model | combo-ref | provider-wildcard`);
- um **DAG validado**: sem ciclos, com cap de profundidade, capability-aware;
- **allowlistado**: só aponta para provedores conhecidos (alinhado ao `reroute`
  em allowlist da ADR-003/SEC-10, já refletido em `provider.reroute_unsupported`).

O plano v1 tratava combo como uma lista simples. Isso não suporta dois casos reais:
um combo que **referencia outro** (reuso/composição) e uma política que precise
**reordenar por capacidade** sem descartar modelos. Referência mútua irrestrita,
por outro lado, permitiria ciclos e recursão infinita — o mesmo risco de
reentrância que a ADR-0009 trata para o juiz do `fusion`.

O repo já tem a base de persistência (`internal/store`, migrações numeradas
`000N_*.sql`, `schema_version` em `meta`) e o registry de provedores
(`providers.Registry`, determinístico). O combo é uma camada NOVA sobre esses.

## Decisão

### 1. Modelo do combo

```go
// Combo é uma rota nomeada e persistida.
type Combo struct {
    Name       string       // ^[a-zA-Z0-9_.-]+$ ; único, case-sensitive
    Policy     StrategyKind // uma das estratégias da ADR-0009
    Steps      []ComboStep  // ordenados
    SchemaVer  int          // versão do formato persistido (ver §4)
    // Depth é derivado no save: a profundidade máxima de referência.
    Depth      int
}

// ComboStep é um passo. Exatamente um dos alvos é não-vazio.
type ComboStep struct {
    // Alvos (mutuamente exclusivos):
    Model    domain.ModelID    // passo concreto
    ComboRef string            // referência a outro combo (DAG)
    ProviderWildcard string    // "provider/*" — todos os modelos do provider
    // Modificadores:
    Weight    int              // peso p/ weighted; 0/ausente = 1
    Prompt    string           // prompt opcional injetado neste passo (pipeline)
    AllowedConnectionIDs []string // restringe às credenciais listadas
    FallbackOnlyOnQuotaExhaustion bool // só troca o passo se a falha for cota
}
```

Nome: **`^[a-zA-Z0-9_.-]+$`** e **único**. Um nome fora do padrão ou duplicado é
recusado no save (`route.invalid_combo`). A restrição de charset evita nomes que
quebram URLs, JSON ou o parser de `model:`.

### 2. Tipos de passo

- **`model`** — um modelo concreto de um provider conhecido.
- **`combo-ref`** — referência a outro combo pelo nome. É o que torna o conjunto
  um **DAG**: A pode referenciar B, mas o grafo tem de ser acíclico.
- **`provider-wildcard`** — todos os modelos declarados do provider (via
  `ProviderFamily.Capabilities`/`Models()`), expandidos no resolve.

`Weight` alimenta `weighted`; `Prompt` injeta texto quando o passo participa de
um `pipeline`; `AllowedConnectionIDs` restringe as credenciais elegíveis (cota
por conta); `FallbackOnlyOnQuotaExhaustion` faz o failover só ocorrer por cota
(ADR-0002: `ScopeCredential`/429), não por erro de cliente.

### 3. Validação no SAVE (não no request)

Toda validação é feita **ao salvar** o combo, não no caminho do request — o
request deve custar apenas o `Resolve`. O save recusa com erro tipado:

1. **Nome válido e único** (`route.invalid_combo`).
2. **Referências resolvem:** todo `combo-ref` existe (`route.invalid_combo`).
3. **DAG sem ciclo:** detecção de ciclo por DFS (cores branco/cinza/preto) sobre
   o grafo de referências; ciclo → `route.cyclic_combo`. Um combo não pode
   referenciar a si mesmo nem fechar um laço.
4. **Cap de profundidade:** `Depth <= MaxComboDepth` (`route.depth_exceeded`);
   a profundidade é a maior cadeia de `combo-ref` a partir do nó.
5. **Cap de fan-out:** um passo `fusion` com fan-out acima de `MaxFanout` é
   recusado (`route.fanout_exceeded`), coerente com a ADR-0009 §3 — evita que a
   reentrância do juiz exploda.
6. **Allowlist de provedores:** todo `model`/`provider-wildcard` aponta para um
   provider conhecido no registry (`route.unknown_provider`). Alinhado ao
   `reroute` em allowlist (SEC-10); o combo **não** pode introduzir um destino
   fora do registry.
7. **Capability-aware (no resolve, não no save):** o Router pode **reordenar** os
   modelos por capacidade/modalidade do request (`Capabilities`/`ModalitySet`)
   **sem descartar** os que não casam — um modelo sem a modalidade pedida vai para
   o fim, não é removido, caso um fallback o atenda parcialmente. O save só
   garante que os modelos existem; o fit é avaliado por request.

### 4. Versão do schema e migração

O formato persistido é **versionado** (`SchemaVer`, começando em **2** — o v1 foi
a lista simples do plano antigo). A tabela guarda o combo serializado (JSON/TOML)
+ a versão; um `schema_version` global do banco já existe em `meta`. Regras:

- Um combo com versão **menor** que a atual passa por **upgrade** no load
  (`internal/store` já tem o padrão de upgrader do config; o mesmo vale aqui).
- Um combo com versão **maior** que a suportada é **recusado fail-closed**
  (`route.invalid_combo`), nunca "adivinhado" — a mesma postura do
  `config_version`.
- Upgrade é função pura: `upgradeCombo(old) (Combo, error)`, testável com
  goldens, sem I/O.

**Persistência:** migração `000N_combos.sql` cria a tabela

```sql
CREATE TABLE IF NOT EXISTS combos (
    name        TEXT PRIMARY KEY,
    schema_ver  INTEGER NOT NULL,
    policy      TEXT NOT NULL,
    body        TEXT NOT NULL,     -- passos serializados
    depth       INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
```

Single-writer (ADR-010): o save/delete passa pelo writer connection; o load pelo
read pool. Sem escrita no caminho do request.

### 5. Estado de rotação

O estado de rotação (`round-robin`) e o ponteiro de `fill-first` são
**in-memory**, por processo, e **NÃO persistem entre reinícios** (ADR-0009 §4,
§2). O combo persistido é a **política** (declaração); o cursor é **execução**.
Reiniciar o daemon reinicia os cursores — consequência aceita no v1. Não se
escreve em SQLite no caminho do request por ordenação.

### 6. Reroute / allowlist

Um gate pode pedir `reroute` (ADR de gates, `DecisionReroute`); o alvo é validado
contra a **allowlist de provedores do registry**. Um combo é a forma declarativa
da mesma regra: ele só referencia o que está no registry. `provider.reroute_unsupported`
já existe para o caso "dispatcher de validação ainda não existe" (F3 o implementa);
`route.unknown_provider` cobre o combo apontando fora do registry no save.

### 7. Códigos i18n

Nomeados aqui para o implementador não inventar strings: `route.invalid_combo`,
`route.cyclic_combo`, `route.depth_exceeded`, `route.fanout_exceeded`,
`route.unknown_provider`, `route.no_candidate` (ADR-0009 §7). Entram no catálogo
`pt-BR`/`en` na F3.

## Consequências

- **F3 entrega:** tabela `combos` + migração; `ComboStore` (save/load/delete);
  validador de DAG (DFS) + depth/fanout/allowlist; upgrade de schema; e o
  `Router.Resolve` que expande `combo-ref`/`provider-wildcard` em `Candidate`s.
- **Erro tipado no save** (`route.*`, `ScopeRequest`, `Retryable=false`): um
  combo inválido/cíclico falha na gravação, nunca no request.
- **`fusion` e `pipeline` são políticas do combo**, e a reentrância do juiz do
  `fusion` respeita o DAG: o combo do juiz não pode ser `fusion` e a profundidade
  é capada — a validação de DAG é o que impede recursão infinita.
- **Estado de rotação é efêmero** (documentado): comportamento reproduzível só
  dentro de um processo.
- O schema é versionado desde o primeiro dia, evitando a migração dolorosa que a
  ADR-SEC-01 evitou para o cofre.
- A allowlist reaproveita o registry de providers: nenhuma fonte de verdade nova.

## Alternativas consideradas

- **Combo como lista simples (v1).** Rejeitada: não compõe (`combo-ref`) nem
  reordena por capacidade; força o operador a duplicar rotas.
- **Combo como código (Go).** Rejeitada: o operador não recompila o binário para
  ajustar uma rota; e uma rota em código não é auditável nem editável pela GUI.
- **Combo recursivo irrestrito.** Rejeitada explicitamente: ciclos e recursão
  infinita; a profundidade seria imprevisível. O DAG com cap é o ponto da ADR.
- **Validar no request em vez de no save.** Rejeitada: paga-se a validação de
  grafo em todo request e o erro chega tarde (produção, sob carga) em vez de no
  momento da edição.
- **Persistir o cursor de rotação.** Rejeitada no v1: custo de I/O no caminho do
  request; ver ADR-0009.
- **Permitir `provider-wildcard` fora do registry.** Rejeitada: furaria a
  allowlist de `reroute` (SEC-10) e abriria destino não validado.
