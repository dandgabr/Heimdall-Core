# ADR-0014 — DAG de gates e política de falha por gate

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F4 (Gates: Token → Memória → Segurança)
- **Relaciona-se com:** ADR-SEC-03 (invariante de confiança de gates), ADR-SEC-04 (ordem e semântica do pipeline), ADR-0002 (taxonomia de erro), ADR-0003 (ocultação)

## Contexto

A ADR-SEC-04 fixou **que ordem** importa (fases de contenção → cache → memória →
otimização → verificação → observabilidade) e que o desempate é lexicográfico por
`ID()`. A ADR-SEC-03 fixou **quem** pode ser gate nativo (só built-in) e **o que**
um gate recebe (mínimo necessário). O contrato `contracts.Gate` está congelado
(`Stages()`, `RequiredCaps()`, `FailurePolicy()`, `PreRequest`/`OnResponseChunk`/
`PostResponse`) e o `contracts.GateRegistry` existe com `RegisterGate(name, factory)`.

O que falta congelar é **o mecanismo**: como o registry produz a ordem executável,
o que exatamente cada gate declara sobre seus dados para o grafo ser derivável
(em vez de uma tabela hardcoded de fases), como o motor aplica a `FailurePolicy`
por gate e como um gate é ligado/desligado por config sem tocar o core.

Há também um custo medido a honrar: o baseline de F1 (`reviews/f1-performance-baseline.md`
§3.4) mediu o caminho por chunk com 10 gates em **4 398 ns / 50 allocs por chunk**,
com `gates.metadata` respondendo por **87,5% das alocações** — os metadados de
request são recalculados **por gate, por chunk**, quando só dependem do request.
Uma resposta de 200 chunks gera ~0,9 ms de CPU e ~184 KB de lixo por cadeia. A
ADR tem de exigir que o cálculo por chunk seja **uma vez por request** sem violar
o contrato "o gate recebe o mínimo necessário".

## Decisão

### 1. O grafo é derivado de declarações do gate, não de uma tabela

Cada gate declara, além do que o contrato congelado já exige, um **conjunto de
leitura e escrita** sobre os dados do request. A ordem do `PreRequest` é a
ordenação topológica sobre as arestas **"escreve X → lê X"**: um gate que lê um
dado roda depois de todo gate que o escreve.

```go
// DataField é o vocabulário fechado dos dados do request que um gate lê ou
// escreve. Fechado de propósito: um campo novo é uma mudança de contrato, não
// uma string solta, senão o grafo não é verificável.
type DataField string

const (
    FieldModality      DataField = "modality"       // modalidade/requisitos
    FieldCacheLookup   DataField = "cache_lookup"   // hit/cache key
    FieldContext       DataField = "context"        // memória recuperada
    FieldPromptText    DataField = "prompt_text"    // corpo do system/user
    FieldPrefixRange   DataField = "prefix_range"   // intervalo congelado do cache
    FieldPII           DataField = "pii"            // mascaramento de PII
    FieldInjectionFlag DataField = "injection_flag" // veredito de injeção
    FieldBudget        DataField = "token_budget"   // orçamento/contagem
    FieldRoute         DataField = "route"          // reroute/modelo alvo
)

// Declared is o que um gate declara sobre seus dados, por estágio.
type Declared struct {
    // Stages em que o gate atua (já congelado no contrato: Stages()).
    Stages GateStageSet
    // Reads são os campos que o gate OBSERVA (a ordem dele depende deles).
    Reads []DataField
    // Writes são os campos que o gate ALTERA (produzem arestas para os leitores).
    Writes []DataField
    // After é uma dependência EXPLÍCITA por nome, para o caso em que a relação
    // não é expressável por campo de dados (ex.: "sempre depois do rate limit").
    // É exceção documentada, não o mecanismo padrão.
    After []string
}
```

**Algoritmo de ordenação (determinístico):**

1. Nós = gates habilitados que declaram o estágio.
2. Arestas: para cada campo `X` escrito por `A` e lido por `B`, aresta `A → B`.
   Uma aresta `After[B] = A` adiciona `A → B` também. Um gate não lê nem escreve
   nada ⇒ sem aresta de dados; fica na fase pela ordem alfabética.
3. **Kahn** com uma **fila ordenada por `ID()`**: em cada passo escolhe-se, entre
   os nós de grau de entrada zero, o de menor `ID()`. É o desempate que a
   ADR-SEC-04 exige, e torna a saída estável entre execuções e máquinas.
4. **Ciclo é rejeitado na inicialização** (`route.cyclic_combo` não serve aqui; o
   código é `error.internal` + nome dos gates do ciclo, pois é um erro de wiring,
   não do operador). Um ciclo entre gates é sempre um bug: nenhuma ordem
   legítima exige que A dependa de B e B de A.
5. **Cada estágio é ordenado separadamente** (`PreRequest`, `OnResponseChunk`,
   `PostResponse`), com o MESMO algoritmo e as declarações por estágio. `PreRequest`
   roda antes de `OnResponseChunk` por definição (o contrato obriga), não por
   aresta.

O resultado é **computado uma vez** no boot (após o registro) e **congelado**;
nenhuma ordenação acontece no caminho do request.

### 2. Fases e o `committed`

| Fase | Quando | Vocabulário | Regra de erro (§3) |
| --- | --- | --- | --- |
| `PreRequest` | antes do roteamento/upstream | `Continue`/`Modify`/`Block`/`Reroute` | por `FailurePolicy` do gate |
| `OnResponseChunk` | após o 1º byte downstream (`Committed == true`) | **apenas** `PassThrough`/`Replace`/`Drop` | por `FailurePolicy` do gate |
| `PostResponse` | uma vez após a troca (inclusive em erro) | sem decisão; observação/escrita assíncrona | **sempre FailOpen** |

- **`committed` no chunk:** a flag entra `true` em `ChunkInput` por construção; o
  motor **recusa** um `Decision{Reroute}` vindo de um gate pós-commit como
  violação de contrato (`error.internal`, não erro do cliente).
- **Erro pós-200 vira evento terminal:** um gate `FailClosed` que falha após o
  commit não pode mudar o status HTTP. O motor converte a falha no **evento SSE
  terminal** `event: error` (mesmo caminho de `passthrough`), encerra o stream e
  garante **exatamente um** terminal.
- **`PostResponse` é sempre FailOpen:** roda fora do caminho do 1º byte; sua
  falha é logada, nunca aborta. É a única fase sem política escolhível — e isso é
  do contrato (o gate nem declara política para ela).
- **`Block` com `SyntheticResponse`:** um cache hit é **sucesso** (Status 200
  sintético); uma negação de política é entregue como resposta com o status de
  intenção. Ambos terminam a cadeia e não chamam upstream.
- **Reroute:** só pré-commit e só para destino na allowlist do registry
  (`RerouteTarget`), alinhado à SEC-10; destino fora da allowlist é falha fechada.

### 3. Política de falha POR GATE

A `FailurePolicy()` é declarada pelo gate e o motor a aplica assim:

| Fase | `FailClosed` | `FailOpen` |
| --- | --- | --- |
| `PreRequest` | aborta a request com o erro do gate (tipo `DomainError`, redigido) | loga (estruturado, com request ID) e **continua com o input não modificado** |
| `OnResponseChunk` | termina o stream com o evento de erro terminal | loga e **encaminha o chunk original** (`PassThrough`) |
| `PostResponse` | — (sempre FailOpen) | loga e segue |

Regras normativas:

1. **Não há default silencioso.** Um gate sem política é recusado no registro.
2. **Timeout é falha.** Um gate que estoura seu orçamento de tempo é tratado pela
   própria `FailurePolicy` (FailOpen degrada; FailClosed aborta). O orçamento é
   por gate, config, com teto rígido no binário.
3. **O input nunca fica pela metade.** Um `Modify` que falha no meio (ex.: erro
   ao reescrever) NÃO publica a modificação parcial: no FailOpen o pipeline segue
   com o input **original**, nunca com um corpo truncado.
4. **FailOpen não mascara segurança.** Um gate de segurança é FailClosed por
   definição; declarar FailOpen num gate cujo `Writes` inclui `pii` ou
   `injection_flag` é **recusado no registro** (a política contradiz o efeito).

### 4. Liga/desliga por config sem tocar o core

- Cada gate é registrado no binário (built-in, ADR-SEC-03) e **habilitado por
  feature flag no config** (`features.gates.<name>`, mesmo padrão dos switches já
  existentes). O config NÃO declara ordem, nem implementação, nem parâmetros de
  grafo — só o **ligado/desligado** (a ordem é derivada, §1; parâmetros vivem no
  próprio gate).
- O wiring (composition root) monta a lista de gates habilitados, registra no
  `GateRegistry`, ordena (§1) e constrói a `Chain` **uma vez**. Um gate desligado
  não entra no grafo: a ordem dos demais é recalculada, e a cadeia resultante é
  equivalente a um mundo sem ele.
- **Desligar um gate FailClosed pode mudar a postura de segurança** — então a
  mudança é visível: o boot registra (`log`) a cadeia efetiva com a política de
  cada gate, e a GUI/CLI mostra o estado. Nada é desligado silenciosamente.
- **Sem reload a quente no v1:** trocar gates exige reiniciar (mesma postura do
  config, que não tem reload). Evita o estado intermediário "cadeia mudando sob
  tráfego".

### 5. Registry e ABI

- `RegisterGate(name string, factory GateFactory)` é a única porta de registro:
  rejeita **duplicata**, **nil factory** e **nome vazio**; a ordenação é
  determinística (§1) e a validação acontece no boot, antes de servir.
- O registry valida também: `Stages()` não vazio, `FailurePolicy` coerente com os
  campos escritos (§3.4) e `RequiredCaps` conhecido. Uma violação é erro de boot.
- **ABI nativa no v1.** Gates nativos são exclusivamente built-in
  (ADR-SEC-03 §1); sem `plugin`, sem `.so`, sem FFI. O contrato congelado só cruza
  a fronteira com valores puros (`[]byte`, string, int, map), então um **adapter
  WASM** pós-v1 implementa `contracts.Gate` sem mudar o contrato nem este ADR:
  muda apenas quem produz o gate no registry (um `GateFactory` que cria o adapter).
  Granularidade de gate de terceiros: **request/response**, não por chunk
  (marshalling por delta destrói a latência).

### 6. Performance: metadados calculados UMA vez por request

O baseline mediu 50 allocs/chunk com 10 gates, 87,5% em `gates.metadata`: os
campos derivados do request (método/path, nomes de header, id, provider/model)
foram reconstruídos **por gate, por chunk**. A ADR exige:

- O **pipeline** (não o gate) monta os metadados derivados **uma vez por request**,
  no `PreRequest`, e os **reusa** em `OnResponseChunk`/`PostResponse`. O que
  depende só do request nunca é recalculado por chunk.
- O `ChunkInput` passa a carregar a **referência** desses metadados já calculados
  (campo novo no contrato, aditivo), e o gate deixa de derivá-los. Isso **não
  viola** o "mínimo necessário" (ADR-SEC-03 §2): os metadados são exatamente o que
  o gate já recebia, só que sem recalcular; os valores de header sensíveis
  continuam fora (nomes apenas).
- **Meta explícita de F4** (herdada da baseline): a cadeia de 10 gates no caminho
  por chunk desce de **50 allocs/chunk para ≤ 5**, e o custo do chunk deixa de
  crescer com o número de gates pelos metadados. A re-medição usa o mesmo método
  da baseline (`-benchmem -count=5`, mediana).
- Nada aqui autoriza o gate a receber mais conteúdo: quem precisa do corpo declara
  em `RequiredCaps`, como hoje.

## Consequências

- **F4 entrega:** o `Declared` por gate; a ordenação topológica determinística com
  rejeição de ciclo no boot; a aplicação da `FailurePolicy` por fase (com erro
  pós-200 como evento terminal); as feature flags de gate; e a otimização de
  metadados por request com re-medição da baseline.
- **Ordem é derivada e auditável:** a cadeia efetiva é logada no boot com a
  política de cada gate; um operador consegue explicar por que um gate roda antes
  de outro (aresta de dados ou empate por ID).
- **Ciclo é erro de boot**, nunca descoberto em produção sob tráfego.
- **Um gate desligado não deixa buraco silencioso:** a cadeia resultante é
  recalculada e visível; mas desligar um FailClosed muda a postura e fica
  registrado.
- **O contrato não muda** para caber WASM: um terceiro entra como `GateFactory`
  de um adapter, request/response.
- **Performance é critério de aceite**, não aspiração: 50 → ≤5 allocs/chunk.

## Alternativas consideradas

- **Ordem hardcoded por fase (a tabela da ADR-SEC-04 no código).** Rejeitada como
  *mecanismo*: ela descreve o resultado esperado, mas amarrá-la no código impede
  adicionar um gate sem editar o core e esconde o porquê da ordem. A tabela vira
  **teste de aceitação** do grafo derivado (os gates built-in declarados devem
  produzir exatamente aquela ordem).
- **Grafo derivado de `After`-listas apenas.** Rejeitada como mecanismo padrão:
  listas explícitas não escalam e não expressam "quem lê o que"; ficam como
  exceção pontual dentro do modelo de leitura/escrita.
- **Política de falha global configurável.** Rejeitada (ADR-SEC-04): a política é
  do gate; uma global deixaria um retriever de memória derrubar o roteador ou um
  guard de injeção falhar aberto.
- **FailOpen para todos, com log.** Rejeitada: mascararia falha de contenção
  (injeção/PII) como aviso.
- **Iterar um map de gates.** Rejeitada terminantemente (ADR-SEC-04 §1): iteração
  de map em Go é randomizada; a ordem da cadeia mudaria entre execuções.
- **Registrar gates por reflexo/scan de pacote.** Rejeitada: registro explícito no
  composition root é auditável e é o que impede um gate aparecer sem revisão.
- **Recalcular a ordem por request.** Rejeitada: a ordem não depende do request,
  e o custo por request é puro desperdício. Calculada uma vez no boot.
- **Gate de terceiros por chunk via WASM.** Rejeitada: o marshalling por delta
  destrói a latência (ADR-SEC-03); granularidade request/response.
