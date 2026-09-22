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

> As ADRs que bloqueiam fases estão registradas nesta pasta. A referência
> normativa é o arquivo da ADR; as páginas correspondentes no ai-memory
> continuam como contexto de planejamento.

### Aceitas por fase

| ADR | Título | Bloqueia | Status |
| --- | --- | --- | --- |
| 0001 | Identidade: `ProviderFamily` × `Credential` | F1 | Aceita |
| 0002 | Taxonomia de erro | F1 | Aceita |
| SEC-01 | Custódia da chave mestra e cifra de credenciais | F1 | Aceita |
| SEC-05 | [Política de egress e prevenção de SSRF](sec-05-politica-de-egress.md) | F2 | Aceita |
| 0003 | [Ocultação por provedor OAuth](0003-obfuscacao-provider-oauth.md) | Conectores OAuth | Aceita |

### Previstas (ainda não escritas)

Mantidas aqui para reservar o número e evitar colisão. Cada uma deve existir
**antes** de a fase correspondente começar (ver `plans/implementation-plan-v2.md`).

| Prevista | Tema | Fase |
| --- | --- | --- |
| 0003 | `config_version`, precedência e reload; segredos nunca por flag | F1 |
| 0004 | Refresh single-flight (semântica do `CredentialStore.RefreshLock`) | F1 |
| 0005 | Contrato i18n: convenção de `code`, params, fallback | F1 |
| SEC-05 | [Política de egress / SSRF](sec-05-politica-de-egress.md) (Aceita) | F2 |
| 0006 | Protocolo de streaming/SSE canônico | F2 |
| 0007 | Compatibilidade OpenAI (subset explícito) | F2 |
| 0008 | Orçamentos de timeout e retry | F2 |
| 0009 | Semântica das estratégias de roteamento | F3 |
| 0010 | `Dispatcher`: tentativa, failover e accounting | F3 |
| 0011 | Modelo de cota e `UsageRecorder` | F3 |
| 0012 | `Breaker`: escopos, cooldown e half-open | F3 |
| 0013 | Combos como DAG validado | F3 |
| SEC-03 | Invariante de confiança de gates | F4 |
| SEC-04 | Ordem e semântica do `GateChain` | F4 |
| SEC-07 | Conteúdo, TTL e namespace da memória | F4 |
| 0014 | DAG de gates e política de falha por gate | F4 |
| 0015 | Preservação de prompt cache (`cacheImpact`, prefix-freeze) | F4 |
| SEC-06 | Modelo de confiança da Management API | F5 |
| SEC-09 | Supply chain e release | F6 |
