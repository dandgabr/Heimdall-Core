# ADR-SEC-06 — Modelo de Confiança da Management API

- **Status:** Aceita
- **Data:** 2026-09-23
- **Fase / bloqueia:** F5 (GUI web + CLI completa)

## Contexto

O Heimdall-Core expõe duas superfícies HTTP distintas no mesmo processo:
1. **Gateway de Inferência (`/v1/*`):** API compatível com OpenAI consumida por clientes downstream (editores de código, agentes locais, SDKs, scripts do usuário) para inferência de LLM (`/v1/chat/completions`, `/v1/models`).
2. **Management API & GUI Web (`/api/mgmt/*`, `/web/*` ou asset root):** Superfície administrativa para inspeção, controle de quotas, rotação de chaves, gestão de credenciais e configuração de combos.

Sem um modelo formal de confiança e controles rigorosos entre essas superfícies, o roteador fica vulnerável a vetores críticos de exploração:
1. **Precedente Crítico CVE-2026-46339 (CVSS 10.0, vulnerabilidade análoga observada no 9router):** Rotas de gerenciamento ou de spawn/execução de processos expostas sem barreira incondicional de peer ou dependentes de checagens tardias de autorização permitiram que atacantes remotos em redes adjacentes ou na Internet explorassem endpoints administrativos antes de qualquer autenticação.
2. **DNS Rebinding & Cross-Site Request Forgery (CSRF):** Mesmo com o daemon ouvindo em loopback (`127.0.0.1`), um navegador de uma vítima navegando em um site malicioso (`evil.com`) pode ser induzido pelo atacante a enviar requisições contra `127.0.0.1:8787` manipulando resolução de DNS (TTL baixo apontando para 127.0.0.1) ou disparando chamadas cross-origin via `fetch`/`XMLHttpRequest`/formulários. Como o peer IP para o socket local é legitimamente `127.0.0.1`, a proteção ingênua de IP (`LocalOnly`) sozinha não impede a invasão.
3. **Consumo Abusivo de Upstream por Processos Locais (Ausência de Auth de Cliente em `/v1/*`):** Qualquer processo ou script sem privilégios rodando na mesma máquina poderia disparar requisições em `/v1/chat/completions` consumindo cotas caras e credenciais pagas de LLM associadas ao roteador se o gateway não autenticar os clientes locais.
4. **Confusão de Identidade e Privilégio (Token de Gestão vs Chave de Cliente):** A utilização do token de gestão (operador) para chamar inferência em `/v1/*` ou o uso de chaves de cliente em endpoints administrativos violaria a separação de privilégios e aumentaria a superfície de roubo de credenciais mestras.

Esta ADR resolve a dívida de segurança **P1-6** e o item de backlog **BD-01** registrados em `docs/SECURITY-DEBT.md`, definindo normativamente o modelo de confiança, classes de rotas, autenticação, anti-rebinding/CSRF e salvaguardas de execução do Heimdall-Core.

## Decisão

**Adotar um modelo de confiança em profundidade com separação estrita de domínios, middleware catch-all `LOCAL_ONLY` antes de qualquer autenticação para rotas de execução e gestão, chaves de cliente isoladas e com hash para `/v1/*`, validação rígida de `Host` e `Origin`/`Referer` (anti-rebinding/CSRF), CORS fechado, rate-limits dedicados e proibição de comandos arbitrários.**

---

### 1. Classes de Rota e Trust Model

Toda rota do Heimdall-Core pertence obrigatoriamente a uma das três classes fundamentais:

| Classe | Descrição | Exemplos Atuais | Política de Acesso e Peer | Autenticação Exigida |
|---|---|---|---|---|
| **Leitura (Read)** | Endpoints de telemetria pública, healthcheck, probes e listagem segura de capacidades/modelos sem efeitos colaterais. | `GET /health`<br>`GET /v1/models` | Regida por `allow-remote` no servidor geral. Se `allow-remote=false`, restrito a loopback. | Nenhuma (público / não autenticado). |
| **Mutação (Mutate)** | Endpoints que alteram estado, criam registros, adicionam chaves de API, manipulam combos, alteram configurações ou consomem cotas/crédito upstream. | `POST /v1/chat/completions`<br>`POST /api/mgmt/credentials`<br>`POST /api/mgmt/combos`<br>`POST /api/mgmt/token/rotate` | Restrito a loopback por padrão. Rotas administrativas `/api/mgmt/*` são **sempre** `LOCAL_ONLY`. | `/v1/*`: Chave de Cliente (`client_key`).<br>`/api/mgmt/*`: Token de Gestão (`management_token`). |
| **Execução (`spawn` / capable)** | Endpoints capazes de disparar processos do sistema operacional, invocar binários locais, recarregar daemons ou orquestrar subprocessos. | Nenhum na v1 (superfície congelada sem spawn/exec). | **Regra Dura:** `LOCAL_ONLY` compulsório **ANTES** de qualquer camada de autenticação. | Token de Gestão + Validação de canal local seguro. |

#### Regras Mandatórias de Classes de Rotas:
1. **Regra de Defesa em Profundidade contra CVE-2026-46339 (CVSS 10.0):**
   - **Toda e qualquer rota da classe Execução (`spawn`/capable) ou de Gestão (`/api/mgmt/*`) DEVE aplicar o middleware `LocalOnly` ANTES de qualquer validação de autenticação ou parsing de payload.**
   - O chamador não-loopback é sumariamente rejeitado com status HTTP 403 (`error.forbidden_local_only`) antes de ter oportunidade de apresentar credenciais ou explorar falhas de autenticação.
2. **Middleware Catch-All Obrigatório:**
   - O middleware `LocalOnly` deve ser montado na raiz do roteador (`mux`), envelopando a totalidade das rotas gerenciadas, e **nunca** em uma allowlist de caminhos individuais.
   - Rotas adicionadas no futuro herdam a proteção por construção (`secure by default`), impedindo que rotas novas sejam expostas inadvertidamente.
3. **Regra para Rotas Novas:**
   - Ao adicionar qualquer nova rota ao sistema, ela deve ser explicitamente classificada em Leitura, Mutação ou Execução.
   - Toda rota mutável ou de execução deve ser testada contra chamadas externas no pipeline de CI com asserção explícita de rejeição por `LocalOnly`.

---

### 2. Autenticação de Cliente em `/v1/*` (Gateway de Inferência)

O gateway de inferência (`POST /v1/chat/completions`, etc.) autentica clientes downstream através de **Chaves de Cliente** (`client_key`), com segregação total do token de operador.

1. **Separação Estrita de Identidade e Privilégio:**
   - O **Token de Gestão** (`management_token`) é exclusivo para a Management API (`/api/mgmt/*`). O gateway `/v1/*` **recusa terminantemente** o Token de Gestão como chave de cliente com `auth.credential_invalid` (HTTP 401).
   - A **Chave de Cliente** (`client_key`) é exclusiva para o gateway `/v1/*`. A Management API **recusa terminantemente** qualquer chave de cliente com `api.mgmt.token_invalid` (HTTP 401).
   - É expressamente proibida a interoperabilidade ou equivalência entre essas duas credenciais.
2. **Mecanismo de Transporte da Chave:**
   - A chave de cliente DEVE ser transportada exclusivamente via cabeçalho HTTP:
     - `Authorization: Bearer <client_key>` (padrão OpenAI); ou
     - `x-api-key: <client_key>` (padrão Anthropic/alternativo).
   - **Proibição Absoluta em Query Strings:** É terminantemente vedada a passagem de chave de cliente via parâmetros de query (`?api_key=...` ou `?token=...`). Requisições contendo chaves na URL falham com HTTP 400 (`error.invalid_request`), impedindo vazamentos em logs de acesso, histórico e proxies.
3. **Geração e Entropia:**
   - As chaves de cliente geradas pelo sistema utilizam o CSPRNG do sistema operacional (`crypto/rand`).
   - Entropia mínima de **256 bits** (32 bytes aleatórios), formatadas com prefixo identificador fixo (ex.: `hmd_live_<hex-ou-base64url>`).
4. **Armazenamento e Verificação (Hash Only):**
   - O valor em texto claro da chave de cliente é exibido ao usuário **uma única vez** no momento da emissão e **jamais** persistido em disco ou banco de dados.
   - As chaves são persistidas no SQLite (`store.Store`) exclusivamente em forma de hash criptográfico:
     - **SHA-256** com salt fixo por instalação ou **Argon2id** derivado para chaves corporativas/persistentes.
     - Colunas na tabela `client_keys`: `id` (UUIDv7/text), `name` (text), `key_hash` (text hex), `created_at`, `revoked_at` (nullable), `rate_limit_rate`, `rate_limit_interval`.
   - **Comparação em Tempo Constante:** A validação do hash da chave fornecida contra o hash armazenado DEVE utilizar `crypto/subtle.ConstantTimeCompare`, eliminando vulnerabilidades de timing attack.
5. **Resolução de Chave por Request:**
   - No recebimento da requisição em `/v1/*`, o middleware/guard de auth de cliente extrai o token, calcula o SHA-256 da chave apresentada e busca o registro correspondente no banco SQLite.
   - Chaves revogadas (`revoked_at IS NOT NULL`) ou inexistentes resultam em rejeição imediata com `auth.credential_invalid` (HTTP 401).
   - A chave resolvida injeta no contexto da requisição a identidade do cliente (`domain.ClientID`), utilizada para rate-limiting, accounting de cotas e particionamento de namespace do gate de memória (ADR-SEC-07).

---

### 3. Defesas Anti-DNS-Rebinding e Anti-CSRF (GUI & Management API)

O binding em loopback (`127.0.0.1`) é uma barreira de rede necessária, mas insuficiente contra ameaças baseadas em navegador. As defesas abaixo são compulsórias:

1. **Validação Estrita de Cabeçalho `Host` (Anti-DNS-Rebinding):**
   - O servidor HTTP valida o cabeçalho `Host` de **toda** requisição contra uma allowlist estrita:
     - Formas aceitas: `127.0.0.1`, `127.0.0.1:<port>`, `localhost`, `localhost:<port>`, `[::1]`, `[::1]:<port>`.
     - Se `allow-remote=true` estiver configurado, adiciona-se o hostname ou IP local configurado em `server.host`.
   - Nomes de domínios públicos ou arbitrários (ex.: `Host: evil.com`, `Host: attacker.test`, subdomínios vinculados a IPs locais como `127.0.0.1.nip.io`) são **sumariamente rejeitados** com HTTP 403 (`error.invalid_request` ou `error.forbidden_local_only`).
2. **Validação de `Origin` e `Referer` (Anti-CSRF em Operações Mutáveis):**
   - Para toda requisição HTTP mutável (`POST`, `PUT`, `PATCH`, `DELETE`) direcionada à Management API (`/api/mgmt/*`) ou aos endpoints da GUI:
     - Se o cabeçalho `Origin` estiver presente, ele DEVE coincidir exatamente com a origem local esperada (`http://127.0.0.1:<port>` ou `http://localhost:<port>`).
     - Se `Origin` estiver ausente mas `Referer` estiver presente, o esquema e host do `Referer` devem coincidir com a origem local esperada.
     - Origens externas não autorizadas (ex.: `Origin: https://malicious-site.com`) são sumariamente bloqueadas com HTTP 403 (`error.forbidden_local_only` ou `error.invalid_request`).
3. **CORS Fechado por Padrão:**
   - **Sem Wildcard (`*`):** É terminantemente proibido responder `Access-Control-Allow-Origin: *` em qualquer endpoint administrativo ou de gestão.
   - Endpoints de `/api/mgmt/*` não emitem cabeçalhos CORS permissivos para navegadores de origens externas.
   - Para o gateway `/v1/*`, caso SDKs locais baseados em web demandem CORS (ex.: frontends rodando em localhost), o CORS deve ser restrito exclusivamente a origens locais autorizadas (`http://localhost:*`, `http://127.0.0.1:*`) ou configuráveis de forma restrita via `config.server.cors_allowed_origins`.
4. **Armazenamento e Transporte Seguro de Sessão na GUI:**
   - A GUI SPA autentica-se com o backend transmitindo o Token de Gestão através de cabeçalho customizado (`Authorization: Bearer <token>` ou `X-Management-Token`).
   - Se for utilizado cookie de sessão para a GUI web:
     - O cookie DEVE conter compulsoriamente os atributos: `SameSite=Strict`, `HttpOnly`, e `Path=/`.
     - Cookies de gestão nunca são compartilhados nem aceitos para autorização do gateway `/v1/*`.
   - O token nunca deve ser depositado em `localStorage` de forma que possa ser exfiltrado por origens atacantes via scripts compartilhados.

---

### 4. Rate-Limiting e Throttling

Para prevenir ataques de negação de serviço e tentativas de brute-force:
1. **Rate-Limit por Chave de Cliente (`/v1/*`):**
   - O throughput em `/v1/*` é limitado por chave de cliente autenticada (`client_key`), aplicando o algoritmo Token Bucket com base na configuração do cliente (`RateLimitConfig`).
   - O throttle reutiliza a infraestrutura de segurança estabelecida na ADR-SEC-04 (gate `RateLimit`).
   - Exceder a taxa retorna HTTP 429 com envelope padronizado (`security.rate_limited`, o código do gate `RateLimit`; a classe `quota.*` é reservada à cota por credencial e ao login de gestão), definindo o cabeçalho `Retry-After`.
2. **Rate-Limit por IP para a Management API e Rotação de Tokens:**
   - Tentativas de autenticação administrativa em `/api/mgmt/*` com token inválido sofrem throttling agressivo por IP de origem (mesmo em loopback, para conter processos maliciosos locais automatizados):
     - Máximo de 5 falhas consecutivas por minuto por IP;
     - Após exceder, o IP entra em cooldown de 60 segundos com retorno HTTP 429 (`quota.rate_limited`).
   - Endpoint de rotação de token (`heimdall token rotate` / `/api/mgmt/token/rotate`) possui trava de frequência máxima (ex.: no máximo 1 rotação a cada 5 segundos).

---

### 5. Execução de Comandos do Sistema Operacional

A integridade do sistema operacional do host é protegida pelas seguintes salvaguardas:
1. **Proibição de Comandos Arbitrários:**
   - **Nenhum endpoint de gestão ou API aceita strings de comandos arbitrários do sistema para execução via shell (`/bin/sh`, `bash`, `cmd.exe`, `powershell`).**
2. **Superfície da v1 Congelada sem Spawn:**
   - A versão v1 do Heimdall-Core **não expõe** qualquer endpoint remoto de execução de processos (`spawn`). Toda a orquestração e roteamento de LLMs é executada via transporte de rede estruturado (HTTP/REST/SSE) pelos executores nativos (`internal/executors`).
3. **Requisito para Execuções Futuras (Allowlist Rígida):**
   - Se fases futuras demandarem execução de utilitários locais (ex.: invocação de scripts de diagnóstico ou binários locais como Ollama/Llama.cpp), a execução será estritamente limitada a uma allowlist imutável de binários pré-definidos no código, sem interpolação de shell, e com argumentos passados como slices estruturados de strings (`exec.Command(bin, args...)`), aplicando o middleware `LocalOnly` catch-all antes de qualquer processamento.

---

### 6. Exposição Remota e Conectividade de Rede

1. **Padrão Seguro Loopback (`allow-remote = false`):**
   - O valor padrão de `server.allow_remote` é `false`, e `server.host` é `127.0.0.1`.
   - O processo recusa sumariamente inicializar se `host` não for loopback e `allow_remote` não for explicitamente declarado como `true` no arquivo de configuração ou flag de inicialização (fail-closed, `config.bind_not_loopback`).
2. **Opt-in Explícito e Avisos:**
   - A habilitação de `allow-remote = true` exige ação deliberada do operador.
   - Na inicialização com `allow-remote = true`, o Heimdall-Core emite log estruturado de nível `WARN` (`domain.CodeStartupWarningRemoteAccess`), alertando formalmente que a superfície está exposta à rede.
3. **Ausência de UPnP e NAT Automático:**
   - O Heimdall-Core **não inclui** e **jamais incluirá** suporte a protocolos de abertura automática de portas como UPnP (Universal Plug and Play), NAT-PMP ou PCP. Nenhuma porta será aberta para a Internet sem intervenção manual de infraestrutura do usuário.
4. **Transferência de Risco em Túneis e Redes Compartilhadas:**
   - O uso de túneis reversos (Cloudflare Tunnels, ngrok, tailscale funnel) ou exposição em LANs corporativas/públicas transfere o risco de autenticação inteiramente para o perímetro do operador.
   - Nestes cenários, a autenticação de cliente em `/v1/*`, a validação de `Host` e o isolamento de `LocalOnly` para rotas de gestão permanecem como a última linha de defesa inegociável.

---

### 7. Critérios de Aceite Verificáveis (Normativos para Validação)

A validação da Fase F5 e a auditoria independente de conformidade medirão objetivamente os seguintes critérios:

1. **Exigência de Chave de Cliente em `/v1/*`:** Requisições a endpoints `/v1/*` sem cabeçalho `Authorization: Bearer <key>` ou `x-api-key` são rejeitadas com HTTP 401 (`clientkey.invalid`; `error.unauthorized` é o código genérico equivalente).
2. **Rejeição do Token de Gestão no Gateway:** Uma requisição a `/v1/chat/completions` apresentando o Token de Gestão como bearer token é rejeitada com HTTP 401 (`clientkey.invalid`, o mesmo de chave inválida/revogada — a recusa não revela se a credencial existia; `auth.credential_invalid` descreve a mesma classe de rejeição).
3. **Rejeição da Chave de Cliente na Gestão:** Uma requisição a `/api/mgmt/*` apresentando uma Chave de Cliente é rejeitada com HTTP 401 (`api.mgmt.token_invalid`).
4. **Rejeição de Chaves em Query Strings:** Requisições com chaves passadas via URL query param (`?api_key=...`) são rejeitadas com HTTP 400 (`error.invalid_request`).
5. **Anti-DNS-Rebinding (`Host` Validation):** Requisições com cabeçalho `Host: evil.com` ou hosts não-loopback são rejeitadas com HTTP 403 antes de qualquer processamento de rota.
6. **Anti-CSRF (`Origin`/`Referer` Validation):** Requisições `POST`/`PUT`/`DELETE` em `/api/mgmt/*` com `Origin: https://evil.com` são rejeitadas com HTTP 403.
7. **CORS Fechado:** Nenhuma resposta de `/api/mgmt/*` emite cabeçalho `Access-Control-Allow-Origin: *`.
8. **Catch-All `LocalOnly` para Rotas de Gestão/Execução:** Qualquer endpoint sob `/api/mgmt/*` ou rota nova de execução acessada por peer IP não-loopback é sumariamente bloqueada com HTTP 403 (`error.forbidden_local_only`) antes de verificar autenticação.
9. **Armazenamento Seguro de Chaves (Hash Only):** Chaves de cliente e tokens de gestão são armazenados no banco SQLite estritamente em formato de hash criptográfico (SHA-256), nunca em texto claro.
10. **Comparação em Tempo Constante:** Todas as rotinas de verificação de tokens e hashes utilizam `crypto/subtle.ConstantTimeCompare`.
11. **Rate-Limit por Chave de Cliente:** Disparos contínuos excedendo a cota configurada para a chave de cliente recebem HTTP 429 (`security.rate_limited`, com o cabeçalho `Retry-After`) no gateway de inferência `/v1/*`; a classe de erro `quota.rate_limited` é usada pelo rate-limit do login de gestão. Ambos são 429 com `Retry-After`.
12. **Proibição de RCE/Execução Arbitrária:** A API não disponibiliza nenhum endpoint receptor de strings livres para execução de shell.

## Consequências

- **Fechamento de Dívida de Segurança:** Fecha formalmente a dívida **P1-6** e o backlog **BD-01** de `docs/SECURITY-DEBT.md`.
- **Governança da Fase F5:** A implementação da GUI web (Svelte) e da CLI administrativa na Fase F5 é estritamente vinculada às restrições desta norma.
- **Isolamento de Responsabilidades:** O operador da máquina e os consumidores locais de LLM possuem credenciais e privilégios completamente desacoplados.
- **Proteção contra Vetores Modernos de Navegador:** Ataques de Cross-Site Port Scanning, DNS Rebinding e Cross-Origin Exploitation são anulados pela combinação de validação de `Host`, `Origin` e `LocalOnly`.

## Alternativas Consideradas

- **Permitir o Token de Gestão como fallback no Gateway `/v1/*`:** Rejeitada terminantemente. Quebraria o princípio do menor privilégio e permitiria que editores de código ou plugins locais tivessem acesso indireto ao controle total do roteador.
- **Aceitar chaves de cliente via query params para compatibilidade com ferramentas legadas:** Rejeitada. A conveniência de passar tokens na URL expõe a credencial a vazamentos em logs de proxy, históricos de navegadores e exceções não tratadas.
- **Basear segurança da Management API apenas na checagem de IP `LocalOnly`:** Rejeitada. Deixaria o daemon completamente vulnerável a ataques de DNS Rebinding e CSRF executados a partir do navegador da vítima.
- **Armazenar chaves de cliente em texto claro ou com criptografia reversível no SQLite:** Rejeitada. Chaves de API de clientes devem ser tratadas como senhas (`hash-only`). Apenas o hash SHA-256 é necessário para validação.
