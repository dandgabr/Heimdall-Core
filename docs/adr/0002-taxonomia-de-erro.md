# ADR-0002 — Taxonomia de erro (`DomainError`)

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F1 (Auth), F3 (Breaker/Dispatcher)
- **Nota de numeração:** esta é uma ADR de **arquitetura** (`0002`). Não confundir
  com `ADR-SEC-02` (esquema de cifra/envelope), que é de **segurança** e tem
  numeração própria (`sec-02-*`). As duas são referenciadas por nome completo.

## Contexto

`internal/domain/errors.go` já define a **forma** do erro:

```go
type DomainError struct {
    Code       string            // chave i18n
    Params     map[string]string // placeholders nomeados
    HTTPStatus int
    Retryable  bool
    Scope      ErrScope          // ScopeRequest | ScopeCredential | ScopeProvider
    RetryAfter time.Duration
    Cause      error
}
```

O que **não** está definido são os **valores** e a **regra de classificação**:
quais `Code` existem, com que `HTTPStatus`, `Retryable`, `Scope` e `RetryAfter`
cada um nasce. Sem essa tabela congelada, o defeito apontado na revisão
(`notes/revisao-plano-arq-sec.md`, mudança estrutural nº 4) acontece:

- o breaker esfria a credencial por **erro do cliente** (um `400` de payload
  inválido abriria o circuito de uma conta sadia);
- o Dispatcher **retenta `400` indefinidamente**, queimando tentativas e cota;
- um `429` de cota não distingue de um `429` de rate-limit transitório, então o
  cooldown usado é sempre o mesmo (exponencial, quando deveria ser "até o
  `resets_at`");
- erros de OAuth se misturam com erros de transporte e o refresh não é acionado.

O código já tem a semente: `internal/domain/codes.go` lista 29 `Code` (todos com
prefixo por domínio) e `internal/api/middleware/errors.go` os serializa como
`{error:{code,params}}`. O que falta é a **classificação operacional** de cada
um.

### Alinhamento com o código existente

- `ErrScope` e `DomainError` já estão implementados e não mudam.
- Os `Code` atuais em `codes.go` entram nesta tabela **com os nomes atuais**; a
  tarefa não renomeia nenhum, para não quebrar catálogos nem testes.
- Os erros de origem upstream hoje se chamam `error.upstream_*`. A tabela os
  classifica no eixo `ScopeProvider` e registra que o prefixo `provider.*` fica
  **reservado** (ver Alternativas) — renomear em F1 seria churn sem ganho.

## Decisão

**Congelar a taxonomia abaixo. A classificação é por campos tipados
(`Scope`, `Retryable`, `RetryAfter`) definidos no ponto do erro — é proibido
inferir escopo/retentativa parseando a string do `Code` ou o `HTTPStatus`.**

### Regras de classificação (a regra, não o caso)

1. **Erro do cliente** (`400`, `404`, `405`, `413`, `415`, `422`): `ScopeRequest`,
   `Retryable=false`. **Nunca** cooldowna. Se `Code` for de payload, o Dispatcher
   não tenta o próximo passo.
2. **`401`/`403` de credencial upstream**: `ScopeCredential`, `Retryable=false`.
   Conta como falha de credencial; após **N falhas consecutivas** (N
   configurável, padrão `3`) a credencial é marcada **inválida** e retirada do
   roteamento até reautenticar.
3. **`429` / cota**: `ScopeCredential`, `Retryable=true`. O cooldown é
   **`RetryAfter`** — nunca exponencial genérico. `Retry-After` do header ou
   `resets_at` do corpo viram `RetryAfter`; sem nenhum dos dois, cai no backoff
   exponencial com jitter.
4. **`5xx` / `408` / `502` / `503` / `504` de upstream**: `ScopeProvider`,
   `Retryable=true`. Erro de rede, DNS ou TLS também é `ScopeProvider` retryable.
5. **Erro interno do próprio núcleo** (`error.internal`, panic recuperado):
   `ScopeRequest`, `Retryable=false`. Bug do servidor não pode cooldownar
   credencial alheia.
6. **OAuth**:
   - token expirado → `auth.token_expired`, `Retryable=true`,
     `ScopeCredential`. **Não** cooldowna por si: dispara o **refresh
     single-flight** e, em caso de sucesso, retenta a chamada **uma vez**.
   - refresh inválido/revogado → `auth.credential_invalid`, `Retryable=false`,
     `ScopeCredential`. Cooldown longo / desabilita até reautenticar.
   - refresh transitório (rede/5xx do endpoint de token) → `auth.refresh_failed`,
     `Retryable=true`, `ScopeCredential`, cooldown curto com backoff.
   - negação do usuário, `state` inválido ou TTL do device code expirado →
     `ScopeRequest` (é o fluxo local que falhou, não a conta).
7. **`Retry-After`**: quando o upstream informa `Retry-After` (delta ou data) ou
   `resets_at`, o valor é convertido para `DomainError.RetryAfter` no ponto de
   decodificação. É a única fonte aceita para o cooldown de cota.

### Catálogo

#### `error.*` — genéricos e de origem upstream

| Code | HTTP | Retryable | Scope | RetryAfter | Ação no breaker |
| --- | --- | --- | --- | --- | --- |
| `error.internal` | 500 | não | Request | — | nenhuma |
| `error.invalid_request` | 400 | não | Request | — | nenhuma |
| `error.not_found` | 404 | não | Request | — | nenhuma |
| `error.unauthorized` | 401 | não | Request | — | nenhuma (auth do cliente) |
| `error.forbidden_local_only` | 403 | não | Request | — | nenhuma |
| `error.method_not_allowed` | 405 | não | Request | — | nenhuma |
| `error.upstream_unavailable` | 502 | sim | Provider | header `Retry-After` | abre/agrava circuito do provider |
| `error.upstream_timeout` | 504 | sim | Provider | — | `Record` como falha de provider |
| `error.bad_upstream_response` | 502 | sim | Provider | — | `Record` como falha de provider |
| `error.upstream_response_too_large` | 502 | **não** | Provider | — | não cooldowna (determinístico) |
| `error.upstream_insecure_url` | 502 | não | Request | — | nenhuma (misconfig de egress) |
| `error.upstream_destination_denied` | 403 | não | Request | — | nenhuma (política de egress) |

#### `auth.*` — credencial e OAuth (novos)

| Code | HTTP | Retryable | Scope | RetryAfter | Ação no breaker |
| --- | --- | --- | --- | --- | --- |
| `auth.token_expired` | 401 | sim | Credential | — | **não** cooldowna; dispara refresh single-flight, retenta 1× |
| `auth.refresh_failed` | 502 | sim | Credential | backoff | cooldown curto com jitter |
| `auth.credential_invalid` | 401 | não | Credential | — | marca inválida / cooldown longo; retira do roteamento |
| `auth.scope_insufficient` | 403 | não | Credential | — | idem inválida (escopo não atende) |
| `auth.oauth_denied` | 400 | não | Request | — | nenhuma |
| `auth.oauth_state_mismatch` | 400 | não | Request | — | nenhuma (replay/CSRF) |
| `auth.oauth_flow_expired` | 408 | não | Request | — | nenhuma (TTL do device code) |
| `auth.secret_missing` | 500 | não | Credential | — | fail-closed; não roteia a credencial |

#### `quota.*` — cota e limite (novos)

| Code | HTTP | Retryable | Scope | RetryAfter | Ação no breaker |
| --- | --- | --- | --- | --- | --- |
| `quota.exhausted` | 429 | sim | Credential | `resets_at` | cooldown **até o reset**, não exponencial |
| `quota.rate_limited` | 429 | sim | Credential | header `Retry-After` | cooldown = `RetryAfter`; sem header → backoff+jitter |
| `quota.cost_cap` | 429 | sim | Credential | `resets_at` | cooldown até o reset da janela de custo |
| `quota.invalid_credential` | 400 | não | Request | — | nenhuma |

#### `config.*` / `store.*` / `api.*` / `startup.*` — boot e gestão

Estes não entram no laço de roteamento; são fatais no boot ou exclusivos da
Management API. Ficam classificados para não ficarem implícitos.

| Code | HTTP | Retryable | Scope | Observação |
| --- | --- | --- | --- | --- |
| `config.load_failed` | 500 | não | Request | fatal no boot |
| `config.invalid_version` | 500 | não | Request | fail-closed; versão futura recusada |
| `config.bind_not_loopback` | 500 | não | Request | invariante SEC-04 |
| `config.invalid_port` | 500 | não | Request | fatal no boot |
| `config.secret_missing` | 500 | não | Request | fail-closed (ADR-SEC-01) |
| `store.open_failed` | 500 | não | Request | fatal no boot |
| `store.migrate_failed` | 500 | não | Request | fatal no boot |
| `store.token_failed` | 500 | não | Request | gestão |
| `store.vault_permissions` | 500 | não | Request | fail-closed (ADR-SEC-01) |
| `api.mgmt.token_invalid` | 401 | não | Request | Management API |

*(`api.health_ok`, `api.ping_ok`, `api.models_ok`, `startup.*` e
`api.mgmt.token_rotated` são mensagens de sucesso, não erros; permanecem em
`codes.go` sem classificação de falha.)*

### Como o breaker consome isto

- `ScopeRequest` → **nenhum** `Record` de falha. O breaker ignora.
- `ScopeCredential` → `Record` na chave `{Provider, Credential}`; `RetryAfter`
  vindo de cota define o cooldown diretamente.
- `ScopeProvider` → `Record` na chave `{Provider}` (ou `{Provider, Model}`);
  cooldown exponencial com jitter quando não há `RetryAfter`.
- `Retryable=false` de credencial é o gatilho de invalidação após N, não de
  retry.

## Consequências

- **F1 (`AuthFlow`)** produz `auth.token_expired` / `auth.credential_invalid` /
  `auth.refresh_failed` exatamente como na tabela; o refresh single-flight é
  acionado por `auth.token_expired`, nunca por string.
- **F3 (`Breaker`/`Dispatcher`)** consome `Scope`/`Retryable`/`RetryAfter` e é
  proibido a classificar por `Code` ou `HTTPStatus`.
- **`codes.go` cresce** com os blocos `auth.*` e `quota.*`; os catálogos
  `pt-BR.json` e `en.json` ganham as entradas correspondentes, com `params`
  nomeados (sem interpolação anônima).
- **Testes de contrato:** uma tabela de teste percorre cada `Code` e afirma
  `HTTPStatus`/`Retryable`/`Scope`, travando a decisão. Um teste dedicado afirma
  que um `400` **não** abre o breaker e que um `429` com `resets_at` usa o
  `RetryAfter` do corpo.
- Nada em `errors.go` muda na forma; só os valores passam a ser normativos.

## Alternativas consideradas

- **Classificar por `HTTPStatus` apenas** (derivar `Scope` do status). Rejeitada:
  `401` pode ser auth do cliente (`ScopeRequest`) ou credencial upstream
  (`ScopeCredential`); o status não distingue os dois e o mesmo `429` cobre cota
  e rate-limit com cooldowns diferentes.
- **Classificar por prefixo da string do `Code`** (`auth.` ⇒ credencial).
  Rejeitada explicitamente pela revisão: frágil a typo, não sobrevive a um code
  que mude de prefixo e esconde a regra do leitor. A tabela é o contrato.
- **Um `Scope` novo por categoria** (ex.: `ScopeQuota`). Rejeitada: multiplica o
  vocabulário do breaker sem mudar a política — cota já é `ScopeCredential` com
  `RetryAfter`.
- **Renomear `error.upstream_*` para `provider.*` agora.** Adiada (não
  rejeitada): o prefixo `provider.*` fica reservado para uma migração futura que
  preserve os nomes antigos como aliases. Renomear em F1 quebraria catálogos,
  testes e a dívida `SECURITY-DEBT.md` sem ganho funcional.
- **Sem `Cause` tipado** (só `Code`). Rejeitada: `errors.As`/`Unwrap` já são
  usados em `middleware/errors.go:55`; remover a causa impediria inspecionar
  `net.Error`, `tls` e o erro do driver SQLite.
