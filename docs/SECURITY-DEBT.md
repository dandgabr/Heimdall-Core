# Heimdall Core — Registro de Dívida de Segurança

Registro vivo das dívidas de segurança conhecidas, com status, impacto e gatilho de
resolução. Toda dívida que bloqueia uma fase deve aparecer aqui **antes** de a fase começar,
referenciando a ADR que a fecha (ver `decisions/`).

Referências normativas: **ADR-003** (escopo de segurança do v1) e **ADR-002**
(Management API em loopback + token).

## Aberta

| ID | Título | Status | Impacto | Bloqueia | Mitigação atual | Gatilho / dono |
| --- | --- | --- | --- | --- | --- | --- |
| **M-1** | Busca vetorial `vec0` da memória não implementada | **ABERTA** | O gate de memória é **FTS5-only**: o retrieval é lexical, sem similaridade semântica. O `modernc.org/sqlite v1.59.0` não expõe a extensão `vec0`. A ADR-SEC-07 prevê o tier vetorial. | Não bloqueia fase | Degrada para FTS5 sem falhar o boot; embeddings externos são opt-in e pseudonimizados (SEC-07 §4) | Quando o driver expuser `vec0` ou se adotarmos uma extensão/wasm vetorial; ADR-SEC-07 |
| **S-1** | Advisory de módulo `GO-2026-5932` (`golang.org/x/crypto/openpgp`) | **FALSO-POSITIVO ACEITO** | `govulncheck` reporta 0 vulnerabilidades **alcançáveis** no código. O advisory é do pacote `openpgp` de `x/crypto`, que **não é importado** pelo produto (usamos apenas `x/crypto/argon2`). Sem caminho de chamada, sem risco. | Não bloqueia release | `govulncheck` bloqueia apenas por vulnerabilidade alcançável; o report de módulo é ruído | Reavaliar se `x/crypto` for atualizado/removido (ADR-SEC-09 §1.3) |

## Resolvidas

| ID | Título | Status | Correção | Data |
| --- | --- | --- | --- | --- |
| **P1-6** | Anti-DNS-rebinding/CSRF da Management API e autenticação de cliente em `/v1/*` ausentes | **RESOLVIDA** | Arquitetura e modelo de confiança normatizados pela **ADR-SEC-06**; critérios de aceite, classes de rota, anti-rebinding (`Host`), anti-CSRF (`Origin`/`Referer`), CORS fechado, segregação de tokens e auth de cliente por hash definidos. Implementação técnica vinculada à entrega da Fase F5. | 2026-09-23 |
| N1 | Bind IPv6 literal sem colchetes (`host = "::1"` → `::1:porta`, `net.Listen` falha) | **CORRIGIDA** | `config.Addr()` usa `net.JoinHostPort` sobre host canonicalizado (strip de `[]`); `IsLoopback` aceita `::1`, `[::1]`, `0:0:0:0:0:0:0:1` e rejeita `127.evil.com` | 2026-09-22 |
| R1 | Redactor não mascarava `<campo> <espaço> <valor>` (`refresh_token abc123`) | **CORRIGIDA** | Regra `space-separated-field` com guarda `looksLikeCredential`, que exige sinal de entropia e não mascara prosa (`token expirado`, `session iniciada`) | 2026-09-22 |
| R2 | 404/405 do mux respondiam `text/plain`, fora do envelope i18n | **CORRIGIDA** | Middleware `ErrorEnvelope` reescreve os status do mux para `{error:{code}}` JSON (`error.not_found`, `error.method_not_allowed`), preservando `X-Request-Id` | 2026-09-22 |
| R3 | Doc drift: README citava cobertura 63,7% | **CORRIGIDA** | README atualizado para o valor medido (74,3%) e a frase do piso revisada | 2026-09-22 |
| R4 | Cobertura 0% em `api/mgmt`, `api/openai`, `domain` | **CORRIGIDA** | Suítes de comportamento adicionadas; pacotes em 100%, 100% e 87,2% (total 74,3%). Achou e corrigiu um panic latente em `(*DomainError).Unwrap()` com receiver nil | 2026-09-22 |
| P1-7 | CI não bloqueava (`SOFT_FAIL: "true"`, sem limiar) | **CORRIGIDO** | Gate eliminado: `continue-on-error` removido e nenhuma variável de bootstrap restou; `make cover-check` falha abaixo de `COVER_MIN=70` (medido 74,3%) | 2026-09-22 |

## Backlog vinculado

### D-SEC-09-01 — Assinatura Cosign Keyless e Fallback de Proveniência em Builds Offline

**Decisão: Aceita como dívida de infraestrutura pela ADR-SEC-09.**
**Estado em F6.1 (2026-09-23): implementada a parte offline; assinatura segue pendente.**

Entregue nesta fase (caminho local sem cosign, que é o de hoje):
- Compilação reprodutível bit-a-bit (`-trimpath -buildvcs=false`, `-s -w`,
  `CGO_ENABLED=0`), provada por `make dist-verify` — dois builds limpos com
  SHA-256 idêntico.
- Manifesto de integridade `dist/SHA256SUMS` (binários + SBOM) com verificação
  por `make checksums-verify` / `sha256sum -c`.
- SBOM CycloneDX 1.6 determinístico em `dist/sbom.cdx.json` (`make sbom`).
- Alvo `make sign` preparado: assina o manifesto com cosign keyless quando o
  binário existe e, quando não existe, **não falha o build** — imprime os
  comandos de assinatura e verificação.
- Passo de proveniência SLSA (`actions/attest-build-provenance`) preparado e
  comentado no job `release` do CI, condicionado a tag.

Pendente (permanece como dívida):
- Executar a assinatura de fato. Exige o binário `cosign` e conectividade com
  Fulcio/Rekor com OIDC — indisponível neste ambiente, por isso não há `.sig`/
  `.pem` publicados ainda.

Justificativa:
- A assinatura keyless com Sigstore Cosign depende de conectividade com a infraestrutura pública Fulcio/Rekor e tokens OIDC emitidos pelo ambiente de execução (ex.: GitHub Actions).
- Em compilações locais isoladas ou sem acesso à Internet, o release adota o fallback estrito documentado na ADR-SEC-09: geração de manifesto de integridade SHA-256 (`checksums.txt`) e atestação de proveniência de build SLSA.

### BD-01 — Autenticação de cliente em `/v1/*`

**Decisão: entra na F5, com o contrato mínimo já preparado na F1.**

Justificativa:

- **F1 é o lugar do contrato, não da política.** A F1 entrega autenticação de *upstream*
  (OAuth/API key por credencial) e congela o `Gate`/`CredentialStore`. O gancho para
  autenticar o *cliente* que chama o gateway pertence ao mesmo eixo de identidade, então a
  F1 deve reservar o campo e a interface — sem impor a política, que ainda não tem caso de
  uso.
- **F5 é o lugar da política.** A Management API + GUI (e o token de gestão a ela associado)
  entram na F5, junto com a ADR-SEC-06. É a fase em que a distinção "operador local autenticado
  pelo token de gestão" vs "cliente de API autenticado por chave de cliente" precisa existir
  de fato, e em que o CORS/CSRF é fechado.
- **A ordem protege o escopo.** Colocar a auth de cliente já na F1 criaria um requisito de
  provisionamento de chaves sem superfície que o consuma; adiá-la inteiramente para depois da
  F5 deixaria `/v1/*` exposto por mais tempo. F1 (contrato) + F5 (política) é o ponto de
  equilíbrio.

Critérios de aceite para fechar BD-01/P1-6:

1. `/v1/*` exige uma chave de cliente (não o token de gestão) em `Authorization`, nunca em query.
2. `Origin`/`Referer` externos são rejeitados na Management API (anti-CSRF) e o
   `Host` é validado contra rebinding.
3. Rate-limit por chave de cliente.
4. ADR-SEC-06 aceita documentando o modelo de confiança.
