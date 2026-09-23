# Modelo de ameaças — Heimdall-Core

Documento vivo e consolidado. Reúne as fronteiras de confiança, os ativos, as
ameaças STRIDE principais e suas mitigações, o risco explicitamente aceito e as
dívidas abertas. Cada mitigação referencia a ADR normativa correspondente em
[`adr/`](adr/README.md); onde há dívida, o ID aponta para
[`SECURITY-DEBT.md`](SECURITY-DEBT.md).

O modelo é para o **v1**: daemon local, bind loopback por padrão, hardening
completo do escopo aplicável (ADR-003). Gates de terceiros, código nativo e
plugins dinâmicos estão **fora** do v1 (ADR-SEC-03).

## 1. Fronteiras de confiança

```
[Cliente OpenAI-compatible] --- client key ---┐
[Navegador (SPA)] ------------ management token ┤
[CLI / operador] ------------------------------┼──> [Heimdall daemon, loopback]
                                               │      ├─ cofre (secret.Store)
                                               │      ├─ SQLite WAL
                                               │      └─ Management API / GUI
[Provedores upstream] <--- HTTPS + egress ---- ┘
```

| Fronteira | O que cruza | Controle de entrada |
| --- | --- | --- |
| **Cliente → gateway `/v1/*`** | Corpo de inferência, chave de cliente | `ClientAuth` (chave hash-only, não aceita na query), limite de corpo, `HostGuard` |
| **Navegador → Management API/GUI** | Token de gestão no header | `ManagementAuth` (hash-only, tempo constante), `OriginGuard`/`CORS`, throttle de login, `HostGuard` |
| **Operador → CLI** | Flags, stdin do `add-key` | Chave lida do stdin (sem eco), nunca argv; config redigida |
| **Heimdall → upstream** | Credencial injetada, prompt | Política de egress (ADR-SEC-05), TLS verificado, credential-masker |
| **Processo → disco** | Cofre cifrado, banco, token a 0600 | AES-256-GCM envelope DEK/KEK, permissões `0600/0700` |

O bind não-loopback é uma fronteira que só se abre por opt-in explícito
(`server.allow_remote = true`) e **nunca em silêncio**: o boot emite aviso, e com
`require_client_key = false` avisa que o gateway fica sem autenticação na rede.

## 2. Ativos

| Ativo | Por que importa | Onde vive |
| --- | --- | --- |
| **Credenciais de provedor** (API keys, tokens OAuth, refresh tokens) | Dão acesso pago à conta do usuário; um vazamento é gasto e banimento | Cofre cifrado (`credentials.secret_blob` = `enc:v1:`), KEK fora do banco |
| **Token de gestão** | Controla a Management API (credenciais, combos, cotas, rotação) | Só o **hash** no banco; texto puro em arquivo `0600` |
| **Chaves de cliente** | Autenticam consumidores do gateway | Só o **hash** (`client_keys.key_hash`); texto puro mostrado uma vez |
| **KEK / chave mestra** | Desbloqueia o cofre | Custódia ADR-SEC-01 (systemd cred, keyring, key file `0600`+Argon2id) |
| **PII na memória** | Conteúdo de turnos do usuário armazenado para retrieval | `memories` (redigido antes de persistir; namespace por cliente; TTL obrigatório) |
| **Assinaturas / contas de sessão** | Uso como proxy pode violar ToS | Descriptors + `RiskNotice`; ocultação por provedor (ADR-0003) |
| **A máquina do usuário** | O daemon roda com os privilégios do operador | Menor privilégio, sem cgo, sem execução de código de terceiros |

## 3. Ameaças STRIDE e mitigações

### S — Spoofing (falsificação de identidade)

| Ameaça | Mitigação | Ref |
| --- | --- | --- |
| Falsificar o operador na Management API | Token de gestão hash-only, comparado em tempo constante; `Authorization` header (nunca cookie/query); throttle de login por IP (5 falhas/min, cooldown 60 s). | ADR-SEC-06 §2, §4.2 |
| Falsificar um cliente de inferência | Chave de cliente (classe separada do token de gestão, ambos hash-only, constant-time); chave nunca aceita na query (400). | ADR-SEC-06 §2 |
| Cliente declarar uma identidade arbitrária para escapar do rate-limit/namespace de memória | A identidade vem da **chave autenticada** injetada no contexto (`ClientKeyFromContext`), nunca de header do cliente (correção do achado G-1). Sem chave, balde compartilhado explícito e namespace de memória inerte. | ADR-SEC-06 §2.5, ADR-SEC-07 §3 |
| DNS rebinding para fazer o daemon atender a um `Host` malicioso | `HostGuard` valida o `Host` contra loopback + allowlist; catch-all antes de auth. | ADR-SEC-06 §3.1 |

### T — Tampering (adulteração)

| Ameaça | Mitigação | Ref |
| --- | --- | --- |
| Ler/alterar credenciais no banco | Cifra AES-256-GCM com envelope DEK/KEK, IV 12 B, tag 16 B; sem a KEK o banco vazado é ilegível. | ADR-SEC-01 |
| Adulterar a requisição para injetar credencial/segredo no upstream | `credential-masker` remove credenciais do corpo antes do egress (`FailClosed`). | ADR-SEC-03, ADR-SEC-04 |
| Envenenar a memória com instruções | Memórias são injetadas delimitadas e marcadas como **dados** consultivos, nunca sistema; a decisão do gate é função pura, nenhum texto vira instrução; proveniência e `content_hash` (dedup idempotente). | ADR-SEC-07 §2, ADR-SEC-03 §3 |
| Adulterar o artefato de release | Build reprodutível bit-a-bit, SBOM CycloneDX, manifesto SHA-256, assinatura cosign (ou fallback SLSA). | ADR-SEC-09 §2–§4 |
| Forçar downgrade de TLS / SSRF | Política de egress: HTTPS obrigatório, denylist de ranges privados, revalidação de redirect, TLS verificado. | ADR-SEC-05 |

### R — Repudiation (repúdio)

| Ameaça | Mitigação | Ref |
| --- | --- | --- |
| Negar uma ação de gestão | Uso idempotente por `attempt_key` (`usage_attempts`), `X-Request-ID` em toda resposta, `revoked_at` preserva a trilha de revogação de chave. | ADR-0011 §4, ADR-SEC-06 §2 |
| Negar uma tentativa de inferência | Accounting idempotente por tentativa no `Dispatcher`/`UsageRecorder`. | ADR-0010, ADR-0011 |

### I — Information disclosure (vazamento)

| Ameaça | Mitigação | Ref |
| --- | --- | --- |
| Segredo em log ou erro | **Redator central obrigatório**; corpo de requisição nunca logado; gates só recebem o mínimo (nomes de header, nunca valores). | ADR-0002, ADR-SEC-03 §2 |
| Segredo em `ps`/histórico | `provider add-key` lê a chave do **stdin**, nunca de argv. | CLI (`add-key`) |
| Chave de cliente na URL (vaza em logs/proxies) | Query recusada com `error.invalid_request` (400) em todo `/v1/*`. | ADR-SEC-06 §2.2, §7.4 |
| Vazamento cross-client na memória | Namespace obrigatório `sha256(clientKey)` em toda query; sem chave identificável, o gate é inerte. | ADR-SEC-07 §3 |
| PII em memória ou no upstream | PII masker; TTL obrigatório; redação antes de persistir e antes do egress de embeddings. | ADR-SEC-07 §4/§5 |
| Exposição além do loopback | Default loopback + `allow_remote` opt-in + avisos de boot; `LocalOnly` catch-all. | ADR-003, ADR-SEC-06 §6 |

### D — Denial of service

| Ameaça | Mitigação | Ref |
| --- | --- | --- |
| Sobrecarregar o gateway | Rate-limit por chave de cliente; limite de corpo (32 MiB no gateway, 1 MiB na Management API). | ADR-SEC-04, ADR-SEC-06 |
| Esgotar a cota paga | `QuotaFilter` no preflight + `Breaker`; cota durável (não esquece janela no restart). | ADR-0011, ADR-0012 |
| Estourar fila de escrita de memória | `AsyncSink` limitado; transbordo **descarta** (backpressure), não trava o caminho da resposta. | ADR-SEC-07 §1 |
| Travar o pipeline por gate falho | Política de falha por gate (`FailOpen`/`FailClosed`), aplicada pelo motor; post sempre `FailOpen`. | ADR-0014 §3 |
| Throttle de inferência derrubar a superfície de controle | O observer roda a cadeia **só** em `/v1/*`; Management/health/GUI não são observados. | ADR-SEC-06 (F5-2) |

### E — Elevation of privilege

| Ameaça | Mitigação | Ref |
| --- | --- | --- |
| Executar código de terceiros no processo | v1 não aceita gates dinâmicos nem código nativo; extras só WASM pós-v1, assinados e verificados. | ADR-003, ADR-SEC-03 §4, ADR-SEC-09 §6 |
| Usar a chave de cliente como token de gestão | Classes de credencial **separadas**; o token de gestão não valida como chave de cliente e vice-versa. | ADR-SEC-06 §2.1 |
| Escalar via um gate `FailOpen` que mascara um efeito de segurança | Registry recusa no boot um gate `FailOpen` que escreve `pii`/`injection_flag` ou um post-only `FailClosed`. | ADR-0014 §3.4 |
| Comprometer a cadeia de suprimentos | Dependências pinadas, `govulncheck` bloqueante para alcançável, sem cgo, SBOM auditável. | ADR-SEC-09 §1 |

## 4. Risco explicitamente aceito

**ToS / banimento por ocultação (ADR-0003).** Provedores que restringem o
harness (ex.: Antigravity) exigem uma camada de ocultação de fingerprint para o
backend aceitar a requisição. Isso **pode violar termos de uso e causar
suspensão ou banimento** da conta. O dono do projeto aceitou esse risco
conscientemente; a ADR-0003 revoga a cláusula "sem cloaking" da ADR-003. A
ocultação é **do harness**, nunca da identidade do usuário, é por provedor e é
sinalizada por `RISK_NOTICE` na CLI e na GUI. Estado: Antigravity é `future`,
então a ocultação **não está em uso ativo** nesta build.

## 5. Dívidas abertas

Consulte [`SECURITY-DEBT.md`](SECURITY-DEBT.md) para status, impacto, gatilho e
dono. Resumo do estado atual:

| ID | Título | Status | Impacto | Ref |
| --- | --- | --- | --- | --- |
| **M-1** | Busca vetorial `vec0` não implementada | **Aberta** (não bloqueia fase) | Memória é FTS5-only (retrieval lexical, sem similaridade semântica). O driver não expõe `vec0`; degrada para FTS5 sem falhar o boot; embeddings externos são opt-in e pseudonimizados. | ADR-SEC-07 |
| **S-1** | Advisory de módulo `GO-2026-5932` (`x/crypto/openpgp`) | **Falso-positivo aceito** | `govulncheck` reporta 0 vulnerabilidades **alcançáveis**; o pacote `openpgp` não é importado (usamos `x/crypto/argon2`). Sem caminho de chamada, sem risco. | ADR-SEC-09 §1.3 |
| **D-SEC-09-01** | Assinatura cosign keyless e fallback offline | **Aceita** (parte offline implementada) | Assinatura real exige `cosign` + conectividade Fulcio/Rekor/OIDC, indisponível no ambiente; o fallback é checksums SHA-256 + proveniência SLSA preparada. | ADR-SEC-09 §3.3 |

**Resolvidas** (histórico relevante): **P1-6** — anti-DNS-rebinding/CSRF da
Management API e autenticação de cliente em `/v1/*` — foi **resolvida** pela
ADR-SEC-06 (2026-09-23), com a implementação técnica na F5. Ver o detalhamento
em [`SECURITY-DEBT.md`](SECURITY-DEBT.md).

## 6. Fora de escopo (v1) — e o risco residual

Estão deliberadamente fora da v1: gates de terceiros/WASM, código nativo,
modelos/embeddings embutidos, TUI, ocultação genérica. O risco residual
correspondente é o de um **binário local de usuário único** cuja principal
defesa é o bind loopback: expor o gateway a uma rede (túnel/LAN) transfere o
risco ao operador, que deve ligar `security.require_client_key` e a allowlist de
`Host`/`Origin` — a ADR-SEC-06 §6.4 registra isso explicitamente.
