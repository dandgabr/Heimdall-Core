# ADR-0015 — Preservação de prompt cache (`cacheImpact`, prefix-freeze)

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F4 (Gates: Token → Memória → Segurança)
- **Relaciona-se com:** ADR-0014 (DAG de gates), ADR-SEC-04 (ordem: token engine após cache/memória), ADR-0009 (`auto`/capability), ADR-0011 (cota)

## Contexto

O plano v2 (F4) define um **gate de token** com engines de compressão e
deduplicação, para reduzir custo e latência em prompts longos e repetitivos. O
problema: os provedores cobram **prompt cache** — o prefixo idêntico de um prompt
repetido é reutilizado upstream a uma fração do preço (e com TTFT menor). Uma
compressão que reescreva o **início** do prompt invalida o cache: o gateway
"economiza" tokens e, na mesma request, perde o desconto do cache — ou seja,
pode **custar mais** e responder mais devagar, além de inflar a contagem de
tokens faturados a full price.

O efeito é silencioso: nada falha, nenhuma métrica de erro sobe; só a fatura
cresce e o p95 degrada. Sem uma regra explícita, cada engine de compressão decide
por conta própria o que pode tocar — e a decisão errada é a mais barata de
implementar (comprimir tudo).

A ADR-SEC-04 já posiciona o token engine **depois** do cache semântico e do
retriever de memória; esta ADR define **o que ele pode tocar**, como declara o
efeito sobre o cache (`cacheImpact`) e como a economia é medida **líquida** do
cache perdido.

## Decisão

### 1. `lossy` e `cacheImpact` são metadados obrigatórios do engine

Todo engine do gate de token declara, junto ao registro:

```go
// CacheImpact qualifica o efeito de um engine sobre o prompt cache upstream.
// É declaração do engine, não inferida: quem escreve o engine sabe o que ele
// toca, e a ADR torna essa declaração vinculante.
type CacheImpact uint8

const (
    // ImpactNone: o engine não altera texto que compõe o prompt (ex.: só conta
    // tokens, só deduplica blocos idênticos PRESERVANDO a ordem e o prefixo).
    ImpactNone CacheImpact = iota
    // ImpactLow: altera texto apenas FORA do prefixo cacheável, e de forma
    // preservadora de offset (ex.: comprimir o sufixo).
    ImpactLow
    // ImpactModerate: altera o sufixo de forma que pode mudar a borda do
    // cache (a delimiter móvel), mas nunca o prefixo congelado.
    ImpactModerate
    // ImpactHigh: pode alterar o próprio prefixo cacheável. SÓ é executável com
    // opt-in explícito por engine (§3).
    ImpactHigh
)
```

- **`lossy bool`:** o engine pode descartar informação (resumo, poda, truncamento).
  Um engine `lossy=true` não pode ser `ImpactNone` por definição — declarar os dois
  é recusado no registro (a declaração é autocontraditória).
- **O registro recusa** um engine sem esses metadados, com `ImpactHigh` sem
  opt-in, ou com a combinação impossível `lossy && ImpactNone`.
- O par `(lossy, cacheImpact)` é **dado de auditoria**: aparece no log de boot
  junto à cadeia de gates (ADR-0014 §4) e na GUI/CLI, para que a escolha de um
  engine seja uma decisão vista, não implícita.

### 2. Prefix-freeze: o prefixo cacheável é CONGELADO

- O **prefixo cacheável** é o intervalo inicial do prompt que o provedor consegue
  reutilizar entre requests da mesma sessão. O gate de token calcula a **borda do
  prefixo** por request e a publica como `FieldPrefixRange` (ADR-0014 §1) — é o
  que `prefix-freeze` significa operacionalmente: um intervalo declarado que os
  demais engines **não podem tocar**.
- **Regra:** um engine só pode alterar texto **fora** do prefixo congelado,
  salvo opt-in explícito (§3). `ImpactNone` não altera nada; `ImpactLow`/
  `ImpactModerate` atuam no sufixo; `ImpactHigh` pode atuar no prefixo **somente
  com opt-in**.
- **Borda móvel, nunca decrescente dentro da sessão:** enquanto a sessão mantém
  afinidade (§4), a borda só cresce — encolher o prefixo congelado entre requests
  da mesma sessão invalida o cache tantas vezes quanto uma reescrita.
- **A deduplicação preserva ordem e offsets:** remover um bloco repetido desloca
  tudo depois dele; se o bloco está dentro do prefixo, é proibido (a menos que o
  engine seja `ImpactHigh` com opt-in). Deduplicar **no sufixo** é permitido.
- **O que está fora do escopo do freeze:** o prompt do usuário corrente, a
  resposta em construção e os blocos de conversa do turno atual — o cache
  upstream não os reutiliza; são exatamente o alvo legítimo da compressão.
- **Session sem prefixo estável:** quando não há borda calculável (primeira
  request da sessão, prompt sem bloco de sistema reutilizável), o engine trata o
  **prompt inteiro como sufixo** e pode comprimir livremente dentro da sua
  política `lossy`.

### 3. Opt-in explícito para engines `ImpactHigh`

- Um engine `ImpactHigh` **não roda por default**. Ele exige opt-in no config,
  **por engine** (`features.gates.token.engines.<name>.allow_prefix_rewrite`), e o
  opt-in é **recusado** se o engine não declarar `ImpactHigh` (opt-in sem efeito
  é configuração mentirosa).
- O opt-in é **registrado no boot** e visível: reescrever prefixo é abrir mão do
  cache upstream, e a ADR trata isso como decisão do operador, nunca do engine.
- Mesmo com opt-in, o engine **marca o efeito** na contabilidade (§5), para que o
  operador veja o custo real.

### 4. Interação com session-affinity / `prompt_cache_key`

- Quando o provedor expõe uma chave de afinidade (`prompt_cache_key` / cache
  namespace), o **router garante a mesma chave** para requests da mesma sessão —
  caso contrário a reutilização nem é tentada e todo o freeze é inútil. A chave
  é derivada da sessão do cliente (não do conteúdo), para não vazar prompt.
- **Affinity e roteamento interagem:** o cache é **por provedor e por conta**
  (ADR-0001/ADR-0011). Um failover para outro provedor (ou outra credencial) muda
  o cache. Por isso: quando a request declara afinidade de sessão e o plano tem
  mais de um candidato, o Router **prefere manter o candidato da sessão** (sinal
  em `Reason`: `session_affinity`), e só troca quando o corrente está
  indisponível (breaker/cota). Isso é um **peso no `auto`/`p2c`**, não uma
  estratégia nova — e nunca sobrepõe o breaker (um circuito aberto não é
  "mantido por afinidade").
- **Sticky ≠ isolated:** manter afinidade não cria estado mutável por sessão no
  core; o sinal é derivado da request (`user`/chave de sessão) e do histórico de
  `Usage`, sem guardar prompt.
- **Sem chave e sem prefixo estável:** o freeze degrada para "não reescrever
  prefixo" (ImpactLow comporta-se como ImpactNone), que é a postura segura.

### 5. Como o efeito é medido: economia LÍQUIDA

A métrica de economia **não** é "bytes removidos". É:

```
economia_liquida = (tokens_de_full_price_evitados_pela_compressão)
                 − (tokens_de_full_price_pagos_por_perder_cache)
```

Concretamente, por request, o gate de token registra:

- `tokens_raw` (antes) e `tokens_after` (depois) — a economia bruta;
- `cache_hits` / `cache_misses` observados na resposta do upstream (quando o
  provedor reporta `cached_tokens`/equivalente), e o **delta** contra a janela
  anterior da mesma sessão;
- `prefix_invalidated bool` — `true` quando a request tocou o prefixo congelado
  (opt-in `ImpactHigh`) ou quando a borda mudou para trás;
- `savings_net = (tokens_after_com_cache) − (tokens_raw_sem_cache)` na forma
  **custo**: o que interessa é `CostMicros` estimado (ADR-0009 §2 `cost`), usando
  o preço full vs. preço com cache do provedor.

Regras normativas:

1. **Nenhuma economia é reivindicada sem o termo de cache.** Um engine que
   comprime 30% e invalida o cache de um prefixo de 80% tem economia **negativa**;
   a métrica tem de mostrar isso, não o bruto.
2. **A métrica alimenta o próprio gate:** se a economia líquida acumulada da
   sessão for negativa, o gate **desativa a compressão para aquela sessão**
   (fail-safe de custo) e registra o motivo. Compressão que perde dinheiro desliga
   a si mesma.
3. **O contador é por sessão/provedor/conta**, consistente com onde o cache vive
   (§4), e é observabilidade — nunca entrada de decisão de segurança.
4. **Sem sinal de cache do provedor**, a contagem cai para o modelo conservador:
   assume-se que tocar o prefixo invalida o cache inteiro, e `ImpactHigh` sem
   opt-in é simplesmente proibido (já coberto em §3).

### 6. O gate de token é desligável

- O gate inteiro tem feature flag (`features.gates.token`), **e** cada engine tem
  a sua; desligar o gate remove o nó do grafo (ADR-0014 §4) e a cadeia recalcula.
- Desligar o gate de token **nunca** quebra o pipeline: ele é `FailOpen` por
  definição (otimização, não contenção), e a request segue com o prompt original.
- Desligado, **nenhum** campo do prompt é alterado: o caminho sem gate de token é
  byte-a-byte o passthrough — é o teste de aceite.

## Consequências

- **F4 entrega:** `lossy`/`CacheImpact` por engine (com validação no registro);
  o cálculo e a publicação da borda do prefixo (`prefix-freeze`); o opt-in por
  engine para `ImpactHigh`; a afinidade de sessão como peso do Router; e a
  métrica de economia **líquida** com desativação automática por sessão.
- **Compressão é uma decisão econômica auditável**, não um detalhe de
  implementação: a métrica mostra o custo real (bruto − cache perdido) e o gate
  se auto-desliga quando perde dinheiro.
- **O prefixo congelado é a invariante central:** respeitá-lo é o que separa
  "economizar tokens" de "pagar mais caro".
- **O gate é desligável em três níveis** (gate inteiro, por engine, auto-off por
  sessão) sem tocar o core, e o caminho desligado é byte-a-byte o original.
- **Afinidade vira um fator de roteamento**, não um estado novo: mantém o
  candidato da sessão quando possível, cede ao breaker/cota sempre.
- **Custo de implementação:** o gate precisa calcular a borda do prefixo e ler o
  sinal de cache do upstream; onde o provedor não reporta cache, a postura é
  conservadora (não tocar prefixo).

## Alternativas consideradas

- **Comprimir o prompt inteiro, sem noção de prefixo.** Rejeitada: é exatamente a
  falha que invalida o cache; a economia bruta vira custo líquido negativo.
- **Deixar o engine decidir sozinho o que tocar.** Rejeitada: sem declaração
  vinculante (`lossy`/`cacheImpact`) não há como o registro validar, nem como o
  operador auditar o efeito.
- **`cacheImpact` booleano (`affects_cache` sim/não).** Rejeitada: perde a
  distinção operacional entre "não toca nada", "toca só sufixo" e "pode tocar
  prefixo", que é exatamente a fronteira do freeze.
- **Freeze configurável pelo operador (tamanho do prefixo em bytes/percentual).**
  Rejeitada como default: a borda correta depende do provedor e do bloco de
  sistema; um número fixo errado derruba o cache. Fica como ajuste fino futuro
  por provedor, nunca como mecanismo.
- **Pin de sessão rígido (nunca trocar de candidato).** Rejeitada: criaria
  indisponibilidade artificial; a afinidade é **peso**, e breaker/cota mandam.
- **Aprender a política de compressão por sessão (ML).** Rejeitada no v1: a
  decisão tem de ser explicável e determinística (mesma postura do `auto` da
  ADR-0009 §5, que não aprende). A regra "economia líquida negativa desliga por
  sessão" captura o essencial sem um modelo.
- **Só medir bytes economizados.** Rejeitada: é a métrica que esconde o custo
  real e premia o engine errado.
