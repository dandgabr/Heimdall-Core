# ADR-SEC-04 — Ordem e Semântica do GateChain

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F4 (Gates: Token → Memória → Segurança)

## Contexto

O pipeline de gates do Heimdall-Core é executado pelo `GateChain` (`internal/pipeline/chain.go`). No plano v1 inicial, a ordenação dos gates era descrita informalmente sob a perspectiva de valor de produto ("Token → Memória → Segurança").

No entanto, em uma arquitetura de segurança rigorosa, **a ordem de execução é uma propriedade crítica de segurança governada por um grafo de dependência de dados**, e não uma mera preferência funcional:
1. **Mascaramento e Contenção Prévia:** Gates que filtram credenciais (`Credential Masker`), validam regras de contenção de SSRF ou impõem limites de taxa (`Rate-Limit`) precisam rodar antes de qualquer busca de rede ou processamento semântico.
2. **Ciclo de Contexto vs Compressão:** O retrieval de memória de contexto precisa injetar memórias relevantes **antes** que os motores de compressão e deduplicação de tokens (`Token Engine`) analisem o tamanho total da janela de contexto e congelem prefixos de cache (`prefix-freeze`).
3. **Cache Lookup vs Compressão:** A consulta ao cache semântico precisa avaliar o prompt original do cliente **antes** de compressões com perda, e se houver hit (`CacheHit = true`), deve interromper o fluxo com uma resposta sintética sem acionar inferência nem retrieval subsequente.
4. **Verificação de Injeção após Montagem Completa:** O filtro de injeção de prompt (`Prompt Injection Guard`) precisa inspecionar o corpo final da mensagem **após** a montagem das memórias e reescritas de prompt, garantindo que nem o usuário nem dados recuperados de fontes externas contenham payloads hostis.

Além disso, a semântica de execução exige regras inequívocas quanto aos pontos de corte pré-commit versus pós-commit e quanto à governança de falhas por gate.

## Decisão

**1. A Ordem de Execução é Propriedade de Segurança (Grafo de Dependência)**
A ordem dos gates é estritamente definida pelas dependências de dados e pré-condições de segurança no pipeline. A cadeia de execução linear do `GateChain` em `StagePreRequest` é estruturada nas seguintes fases sequenciais:

```
[Entrada HTTP]
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Contenção e Sanitização Inicial                          │
│    • Rate Limit (DoD / Proteção de Cota)                    │
│    • Credential Masker (Supressão de Segredos no Input)     │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Cache Semântico Preflight                                │
│    • Semantic Cache Lookup (Se Hit -> Block c/ Synthetic)   │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Enriquecimento de Contexto                               │
│    • Memory Retriever (Busca de Memória / Vetorial / FTS5)  │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Otimização e Preservação de Cache                        │
│    • Token Engine (Compressão, Deduplicação, Prefix-Freeze) │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Verificação Final de Segurança                           │
│    • PII Masker (Anonimização de Dados Sensíveis)           │
│    • Prompt Injection Guard (Detecção de Jailbreak no corpo)│
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Observabilidade Pre-Execution                            │
│    • Logger / Trace Gate (Metadata-Only)                    │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
                    [Roteamento e Upstream]
```

- **Critério de Desempate Determinístico:** Em caso de empates ou ausência de dependência explícita, a ordenação é feita de forma estritamente lexicográfica pelo `ID()` do gate. É **terminantemente proibida a iteração de maps não-ordenados** para definir a ordem da cadeia.

**2. Vocabulário Formal: Pré-Commit vs Pós-Commit**
O pipeline adota o vocabulário dual congelado em `contracts.Gate`:

- **Fase Pré-Commit (`PreRequest`):** Acontece antes de qualquer conexão ou primeiro byte downstream emitido (`Committed == false`).
  - `DecisionContinue`: Segue para o próximo gate sem alterações.
  - `DecisionModify`: Reescreve o corpo (`Body`) ou cabeçalhos (`Headers`) e propaga o payload modificado para os gates subsequentes.
  - `DecisionBlock`: Interrompe a cadeia imediatamente e retorna um `SyntheticResponse`. Em caso de cache hit (`CacheHit == true`), Status 200 é retornado como caminho de sucesso; se for bloqueio de segurança, Status 4xx/5xx é emitido.
  - `DecisionReroute`: Reencaminha a requisição para outro provedor/modelo. Só é permitido se o destino constar na allowlist estrita do roteador (`RerouteTarget`), caso contrário falha fechado.

- **Fase Pós-Commit (`OnResponseChunk`):** Ocorre após o primeiro byte downstream ser enviado (`Committed == true`).
  - É **expressamente proibido** realizar reroute, troca de modelo ou emissão de respostas sintéticas que alterem status HTTP.
  - Vocabulário restrito a chunks de stream:
    - `ChunkPassThrough`: Encaminha o chunk original downstream.
    - `ChunkReplace`: Substitui o conteúdo do chunk por novo payload gerado pelo gate.
    - `ChunkDrop`: Suprime e descarta o chunk do stream em andamento.
  - Em caso de falha irreversível pós-commit (200 já emitido), o erro não pode mudar o cabeçalho HTTP; ele é codificado compulsoriamente como um evento terminal SSE (`event: error\ndata: {"error":{"code":"..."}}\n\n`).

**3. Política de Falha Individualizada por Gate (`FailurePolicy`)**
- A política de falha é uma propriedade explícita de **cada gate** e nunca uma diretiva global do roteador.
- **`FailClosed` (Padrão para Gates de Segurança):** Se um gate de segurança (ex.: `Prompt Injection Guard`, `Credential Masker`, `PII Masker`) emitir erro ou entrar em timeout, o pipeline aborta a requisição imediatamente, protegendo o sistema contra evasão.
- **`FailOpen` (Padrão para Gates de Disponibilidade/Otimização):** Se um gate auxiliar (ex.: `Memory Retriever`, `Token Engine`, `Logger`) falhar, o erro é registrado estruturadamente e o pipeline continua sem interromper a inferência do usuário.

## Consequências

- **Defesa em Profundidade:** Garante que dados de memória recuperados e prompts de usuário passem pela esteira de validação antes de alcançarem o provedor externo.
- **Preservação de Desempenho e Custo:** Consultas ao cache semântico ocorrem antes de operações onerosas de compressão ou retrieval de banco de dados vetorial.
- **Prevenção de Regressões em Streaming:** Elimina race conditions e estados inconsistentes garantindo que o downstream nunca receba mutações de cabeçalho após o commit do primeiro byte.
- **Resiliência Controlada:** Falhas parciais em subsistemas secundários (como timeout na busca de memória) não indisponibilizam o gateway.

## Alternativas Consideradas

- **Ordem declarada livremente pelo usuário via arquivo de configuração:** Rejeitada. A ordem dos gates define limites de segurança. Permitir que o operador inverta a ordem poderia levar à execução de compressão com perda antes do cache semântico ou validação de injeção de prompt antes da injeção de memórias, abrindo brechas graves de segurança.
- **Tratar falha de qualquer gate como `FailClosed`:** Rejeitada. Indisponibilizaria o roteador inteiro se uma busca de memória de contexto em SQLite falhar ou demorar, punindo a disponibilidade de inferência desnecessariamente.
- **Permitir Reroute pós-commit com encerramento de conexão:** Rejeitada. Violar o protocolo HTTP emitindo 200 seguido de RST do socket gera instabilidade extrema em clientes e SDKs de LLM.
