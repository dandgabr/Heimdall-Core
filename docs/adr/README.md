# Registros de Decisão Arquitetural (ADRs)

Este diretório guarda as decisões arquiteturais do Heimdall-Core no formato
**MADR** (Markdown Architectural Decision Records). Uma ADR descreve *por que*
uma decisão foi tomada, não *como* implementá-la — o código e os testes mostram
o como.

## Convenção

Cada ADR é um arquivo Markdown com a primeira linha em `#` e as seções, nesta
ordem:

```markdown
# <Título>

- **Status:** Aceita | Proposta | Substituída por ADR-XXXX | Obsoleta
- **Data:** AAAA-MM-DD
- **Fase / bloqueia:** F0 | F1 | F2 | F3 | F4 | F5 | F6

## Contexto
## Decisão
## Consequências
## Alternativas consideradas
```

Regras de numeração e nomes:

- **Arquitetura:** `NNNN-slug-curto.md`, com `NNNN` começando em `0001` e
  sequencial. É esta a numeração canônica desta pasta.
- **Segurança:** prefixo `SEC-NN` (`sec-NN-slug.md`), alinhado ao identificador
  `ADR-SEC-NN` já usado no ai-memory e em `docs/SECURITY-DEBT.md`. A numeração de
  segurança é **independente** da de arquitetura: `ADR-SEC-01` não é o `0001`.
  Foi uma decisão explícita para não deslocar números quando uma ADR de segurança
  entra entre duas de arquitetura.
- **Status:** uma decisão aceita só muda por substituição. A ADR antiga passa a
  `Substituída por ADR-XXXX` em vez de ser apagada, para preservar o histórico.
- **Escopo:** uma ADR por decisão. Contexto e alternativas curtos; o detalhe
  normativo (tabelas, catálogos) fica na própria ADR quando é a fonte de verdade.

## Fonte de verdade

As decisões de **planejamento** (linguagem, interfaces/GUI/i18n, escopo de
segurança do v1) vivem no ai-memory do projeto `router` e são consultadas antes
de qualquer fase. As decisões **executáveis no repositório** — as que os
implementadores citam no código — são registradas aqui.

| AI-memory (`workspace=router`) | Tema |
| --- | --- |
| `decisions/adr-001-linguagem-go.md` | Linguagem do núcleo: Go |
| `decisions/adr-002-interfaces-i18n.md` | Interfaces, GUI web embutida e i18n por `code` |
| `decisions/adr-003-escopo-seguranca-v1.md` | Escopo de segurança do v1 |
| `decisions/adr-sec-01-custodia-chave.md` | Custódia da chave mestra e cifra de credenciais |

## Índice

### Bloqueiam a F1

| ADR | Título | Status | Data | Arquivo |
| --- | --- | --- | --- | --- |
| **0001** | Identidade: `ProviderFamily` × `Credential` | Aceita | 2026-09-22 | [`0001-identidade-providerfamily-credential.md`](0001-identidade-providerfamily-credential.md) |
| **0002** | Taxonomia de erro (`DomainError`) | Aceita | 2026-09-22 | [`0002-taxonomia-de-erro.md`](0002-taxonomia-de-erro.md) |
| **SEC-01** | Custódia da chave mestra e cifra de credenciais | Aceita | 2026-09-22 | [`sec-01-custodia-chave-cifra.md`](sec-01-custodia-chave-cifra.md) |

### Bloqueiam a F2

| ADR | Título | Status | Data | Arquivo |
| --- | --- | --- | --- | --- |
| **SEC-05** | Política de egress e prevenção de SSRF | Aceita | 2026-09-22 | [`sec-05-politica-de-egress.md`](sec-05-politica-de-egress.md) |

### Conectores OAuth

| ADR | Título | Status | Data | Arquivo |
| --- | --- | --- | --- | --- |
| **0003** | Ocultação (obfuscação) por provedor OAuth | Aceita | 2026-09-22 | [`0003-obfuscacao-provider-oauth.md`](0003-obfuscacao-provider-oauth.md) |

> **ADR-0003 substitui** a cláusula *"sem cloaking/fingerprint"* da ADR-003 (ai-memory) e o
> entendimento correlato em `notes/revisao-plano-arq-sec.md`. O risco de banimento ativo é
> aceito explicitamente pelo dono do projeto.

### Bloqueiam a F3

| ADR | Título | Status | Data | Arquivo |
| --- | --- | --- | --- | --- |
| **0009** | Semântica das estratégias de roteamento | Aceita | 2026-09-22 | [`0009-estrategias-de-roteamento.md`](0009-estrategias-de-roteamento.md) |
| **0010** | `Dispatcher`: tentativa, failover e accounting | Aceita | 2026-09-22 | [`0010-dispatcher.md`](0010-dispatcher.md) |
| **0011** | Modelo de cota e `UsageRecorder` | Aceita | 2026-09-22 | [`0011-modelo-de-cota.md`](0011-modelo-de-cota.md) |
| **0012** | `Breaker`: escopos, cooldown e half-open | Aceita | 2026-09-22 | [`0012-breaker.md`](0012-breaker.md) |
| **0013** | Combos nomeados como DAG validado | Aceita | 2026-09-22 | [`0013-combos-como-dag.md`](0013-combos-como-dag.md) |

> **ADR-0010/0011/0012 são o trio de execução da F3.** A ADR-0010 dá **dono** ao laço
> de tentativas/failover/accounting (`Dispatcher`); a ADR-0011 congela o modelo de
> **cota** por credencial/janela (`QuotaFilter` + `UsageRecorder`, preflight/observador,
> não gate); a ADR-0012 congela a **máquina de estados do `Breaker`** (3 escopos,
> cooldown, terminal, half-open). As três consomem a taxonomia tipada da ADR-0002 e o
> `RoutePlan` da ADR-0009; a validação de F3 ("failover quando cota esgota; breaker não
> cooldowna por erro de cliente") é o critério de aceite do conjunto.

> As ADRs que bloqueiam fases estão registradas nesta pasta. A referência
> normativa é o arquivo da ADR; as páginas correspondentes no ai-memory
> continuam como contexto de planejamento.

### Bloqueiam a F4

| ADR | Título | Status | Data | Arquivo |
| --- | --- | --- | --- | --- |
| **SEC-03** | Invariante de confiança de gates | Aceita | 2026-09-22 | [`sec-03-invariante-de-gates.md`](sec-03-invariante-de-gates.md) |
| **SEC-04** | Ordem e semântica do `GateChain` | Aceita | 2026-09-22 | [`sec-04-ordem-e-pipeline.md`](sec-04-ordem-e-pipeline.md) |
| **SEC-07** | Memória: conteúdo, TTL, namespace e governança de privacidade | Aceita | 2026-09-22 | [`sec-07-memoria-conteudo-e-politica.md`](sec-07-memoria-conteudo-e-politica.md) |

> **ADR-SEC-03/04/07 são a base de segurança da F4.** A ADR-SEC-03 formaliza a
> invariante de que gates nativos são exclusivamente built-in (terceiros só WASM)
> e o princípio do menor conteúdo necessário (SEC-13); a ADR-SEC-04 fixa a ordem
> de execução como dependência estrita de dados e segurança (não ordem de valor)
> e a semântica de pré/pós commit; e a ADR-SEC-07 rege a governança de memória,
> com isolamento por namespace, proveniência anti-envenenamento e desacoplamento
> de escrita via `AsyncSink`.

### Bloqueiam a F4 (arquitetura)

| ADR | Título | Status | Data | Arquivo |
| --- | --- | --- | --- | --- |
| **0014** | DAG de gates e política de falha por gate | Aceita | 2026-09-22 | [`0014-dag-de-gates-e-politica-de-falha.md`](0014-dag-de-gates-e-politica-de-falha.md) |
| **0015** | Preservação de prompt cache (`cacheImpact`, prefix-freeze) | Aceita | 2026-09-22 | [`0015-preservacao-de-prompt-cache.md`](0015-preservacao-de-prompt-cache.md) |

> **ADR-0014/0015 são o mecanismo e a economia da F4.** A ADR-0014 define **como**
> a ordem da ADR-SEC-04 é derivada (grafo de leitura/escrita sobre o request, Kahn
> com desempate por `ID()`, ciclo rejeitado no boot), como a `FailurePolicy` é
> aplicada por fase (erro pós-200 → evento SSE terminal) e como um gate é
> ligado/desligado por feature flag sem tocar o core — exigindo que os metadados
> por chunk sejam calculados **uma vez por request** (baseline F1: 50 allocs/chunk
> com 10 gates). A ADR-0015 define **o que o gate de token pode tocar**: `lossy` +
> `cacheImpact` obrigatórios, prefixo cacheável congelado (`prefix-freeze`), opt-in
> explícito para `ImpactHigh`, afinidade de sessão como peso do Router e métrica de
> economia **líquida** do cache perdido.

> As ADRs que bloqueiam fases estão registradas nesta pasta. A referência
> normativa é o arquivo da ADR; as páginas correspondentes no ai-memory
> continuam como contexto de planejamento.

### Bloqueiam a F5

| ADR | Título | Status | Data | Arquivo |
| --- | --- | --- | --- | --- |
| **SEC-06** | Modelo de confiança da Management API | Aceita | 2026-09-23 | [`sec-06-management-api-trust.md`](sec-06-management-api-trust.md) |

> **ADR-SEC-06 é a base de segurança e confiança da F5.** Ela fecha a dívida P1-6 e o
> backlog BD-01, estabelecendo o modelo de classes de rota (leitura, mutação e execução
> sob catch-all `LOCAL_ONLY`-antes-de-auth), autenticação de cliente em `/v1/*` segregada
> do token de gestão (ambos hash-only, constant-time compare), defesas contra DNS rebinding
> (validação de `Host`) e anti-CSRF (validação de `Origin`/`Referer`, CORS fechado).

### Bloqueiam a F6

| ADR | Título | Status | Data | Arquivo |
| --- | --- | --- | --- | --- |
| **SEC-09** | Cadeia de suprimentos e release | Aceita | 2026-09-23 | [`sec-09-supply-chain-release.md`](sec-09-supply-chain-release.md) |

> **ADR-SEC-09 é a base de integridade e empacotamento da F6.** Ela rege a compilação
> estática determinística (`CGO_ENABLED=0`, `-trimpath`), auditoria de vulnerabilidades
> via `govulncheck`, geração de SBOM no padrão CycloneDX, manifestos de integridade SHA-256
> e assinatura digital via `cosign` (com fallback SLSA documentado).

### Aceitas por fase

| ADR | Título | Bloqueia | Status |
| --- | --- | --- | --- |
| 0001 | Identidade: `ProviderFamily` × `Credential` | F1 | Aceita |
| 0002 | Taxonomia de erro | F1 | Aceita |
| SEC-01 | Custódia da chave mestra e cifra de credenciais | F1 | Aceita |
| SEC-05 | [Política de egress e prevenção de SSRF](sec-05-politica-de-egress.md) | F2 | Aceita |
| 0003 | [Ocultação por provedor OAuth](0003-obfuscacao-provider-oauth.md) | Conectores OAuth | Aceita |
| 0009 | [Semântica das estratégias de roteamento](0009-estrategias-de-roteamento.md) | F3 | Aceita |
| 0010 | [`Dispatcher`: tentativa, failover e accounting](0010-dispatcher.md) | F3 | Aceita |
| 0011 | [Modelo de cota e `UsageRecorder`](0011-modelo-de-cota.md) | F3 | Aceita |
| 0012 | [`Breaker`: escopos, cooldown e half-open](0012-breaker.md) | F3 | Aceita |
| 0013 | [Combos nomeados como DAG validado](0013-combos-como-dag.md) | F3 | Aceita |
| SEC-03 | [Invariante de confiança de gates](sec-03-invariante-de-gates.md) | F4 | Aceita |
| SEC-04 | [Ordem e semântica do `GateChain`](sec-04-ordem-e-pipeline.md) | F4 | Aceita |
| SEC-07 | [Memória: conteúdo, TTL, namespace e governança de privacidade](sec-07-memoria-conteudo-e-politica.md) | F4 | Aceita |
| 0014 | [DAG de gates e política de falha por gate](0014-dag-de-gates-e-politica-de-falha.md) | F4 | Aceita |
| 0015 | [Preservação de prompt cache (`cacheImpact`, prefix-freeze)](0015-preservacao-de-prompt-cache.md) | F4 | Aceita |
| SEC-06 | [Modelo de confiança da Management API](sec-06-management-api-trust.md) | F5 | Aceita |
| SEC-09 | [Cadeia de suprimentos e release](sec-09-supply-chain-release.md) | F6 | Aceita |

### Números reservados (ainda não escritos)

Mantidos aqui para reservar o número e evitar colisão. Cada um deve existir
**antes** da fase correspondente começar (ver `plans/implementation-plan-v2.md`).
Os temas abaixo são decisões **hoje materializadas no código e nos contratos**
(ex.: `config_version` e precedência em `internal/config`; refresh single-flight
em `CredentialStore.RefreshLock`; o contrato i18n em `internal/i18n`; o subset
OpenAI em [`../openai-compat.md`](../openai-compat.md)), mas que **ainda não têm
arquivo de ADR** nesta pasta. Registrá-los como ADR é backlog de documentação.

| Reservado | Tema | Fase |
| --- | --- | --- |
| 0004 | `config_version`, precedência, reload e segredos nunca por flag | F1 |
| 0005 | Refresh single-flight (semântica do `CredentialStore.RefreshLock`) | F1 |
| 0006 | Contrato i18n: convenção de `code`, params, fallback | F1 |
| 0007 | Protocolo de streaming/SSE canônico | F2 |
| 0008 | Compatibilidade OpenAI (subset explícito) | F2 |
| — | Orçamentos de timeout e retry | F2 |
| SEC-02 | Esquema de cifra/envelope (referenciado pela ADR-0002; o núcleo vive na ADR-SEC-01) | F1 |
| SEC-08 | Reservado (não escrito) | — |

### Cobertura do índice

Todas as ADRs **escritas** estão listadas acima: arquitetura **0001–0003** e
**0009–0015** (0004–0008 reservados, não escritos) e segurança **SEC-01,
SEC-03–SEC-07 e SEC-09** (SEC-02 e SEC-08 reservados, não escritos). Esta
página é a fonte única do índice; os arquivos vivem ao lado dela.


