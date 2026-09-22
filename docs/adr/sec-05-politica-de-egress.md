# ADR-SEC-05 — Política de Egress e Prevenção de SSRF

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F2 (Executors, Translators e Streaming)

## Contexto

O Heimdall-Core atua como um gateway e roteador de modelos de linguagem, necessitando
estabelecer conexões de saída de rede para múltiplos destinos:
- Provedores de inferência de LLM (OpenAI, Anthropic, Gemini, Ollama, etc.);
- Endpoints de autenticação OAuth 2.0 (troca de tokens PKCE, polling de device code, refresh single-flight);
- Serviços de geração de embeddings remotos;
- Resolução e download de mídia referenciada por URL (imagens, áudios e vídeos para prompts multimodais);
- Webhooks e notificações externas de eventos operacionais.

Na Fase F0, o esqueleto de saída foi implementado em `internal/passthrough/egress.go`
apenas para validar a passagem direta a um único upstream fixo. A Fase F2 introduz
múltiplos executores dinâmicos (`Executor`), tradução e download de mídias por URL.

Sem uma governança centralizada de transporte e conexão, a expansão de clientes HTTP
no processo abre superfícies críticas de ataque:
1. **Server-Side Request Forgery (SSRF):** requisições forjadas ou URLs de mídia manipuladas
   acessando recursos locais da máquina ou serviços de metadados de nuvem;
2. **DNS Rebinding:** resolução inicial para IP público seguida por resolução maliciosa para IP
   privado durante a conexão;
3. **Bypass por endereçamento especial:** representações IPv4-mapped IPv6 (ex.: `::ffff:169.254.169.254`),
   endereços de loopback alternativos e subredes de link-local;
4. **Vazamento de credenciais via Redirects:** upstream respondendo HTTP 30x redirecionando
   para servidor do atacante e carregando cabeçalhos `Authorization: Bearer <token>`;
5. **MitM e Man-in-the-Middle acidental:** desativação de validação TLS por conveniência
   de desenvolvimento ou ambientes locais;
6. **Denial of Service (DoS):** requisições com timeouts globais mal configurados que abortam streams
   longos, ou payloads e downloads de mídia irrestritos que esgotam a memória do processo.

Esta ADR define a política **normativa, única e obrigatória** para **toda** conexão de saída
originada pelo processo Heimdall-Core.

## Decisão

**Adotar uma política de egress estrita aplicada no nível de transporte HTTP (dial-time hook),
com validação compulsória de TLS, denylist robusta de IPs resolvidos com normalização de IPv4-mapped,
bloqueio padrão de redirecionamentos, saneamento de proxy, orçamentos de timeout por fase e
limites rigorosos de mídia.**

---

### 1. Escopo Universal de Egress

A política de egress governa **toda e qualquer** conexão de rede de saída iniciada pelo executável:
- Chamadas de inferência de LLM e contagem de tokens por `Executor`;
- Chamadas de autenticação OAuth (fluxos de autorização, troca de código e renovação de tokens);
- Resolução e download de conteúdos de mídia referenciados por URL em requisições de clientes;
- Chamadas a APIs de embeddings externas;
- Webhooks e integrações HTTP de saída futuras.

**Invariante:** É expressamente proibida a criação de instâncias de `http.Client` ou `http.Transport`
sem a aplicação da camada central de validação de egress. A política é aplicada na construção do
transporte (`net.Dialer.Control` e `http.Transport`), **nunca** por rota ou por decisão individual de componente.

---

### 2. Política de TLS e Tráfego Cleartext

- **Validação TLS Estrita e Compulsória:** A verificação de certificados x509 da autoridade
  certificadora raiz do sistema operacional é mandatória.
- **Proibição de `InsecureSkipVerify`:** A opção `InsecureSkipVerify: true` em `tls.Config` é
  terminantemente proibida no código-fonte e não pode ser exposta como opção configurável
  para provedores ou usuários.
- **HTTP Cleartext Restrito:** Conexões `http://` não criptografadas são proibidas por padrão.
  A **única** exceção admitida é para hosts loopback declarados como **literal de IP explícito**
  (ex.: `http://127.0.0.1:11434` ou `http://[::1]:11434`), voltados a runtimes locais (como Ollama).
  Esta liberação requer que o provedor esteja expressamente registrado com a permissão de loopback
  habilitada (allowlist formal); ela jamais deve ser concedida a nomes de domínio como `http://localhost`,
  que dependem de resolução DNS externa manipulável.

---

### 3. Denylist de IPs em Dial-Time (Anti-SSRF e Anti DNS-Rebinding)

A validação de segurança não depende do nome de host informado na URL:
1. **Hook de Controle em Dial-Time:** A checagem ocorre via função `Control` de `net.Dialer`,
   executada no momento exato em que o socket conecta, recebendo o endereço `IP:porta` **já resolvido**
   pelo resolver do sistema.
2. **Fail-Closed:** Se o endereço passado ao hook não puder ser parseado como um IP válido,
   a conexão é abortada imediatamente com erro `domain.CodeUpstreamDestinationDenied`.
3. **Normalização Prévia de IPv4-Mapped IPv6:** Antes de qualquer análise de sub-rede,
   o endereço IP deve ser desmapeado através de `netip.Addr.Unmap()`, colapsando representações
   como `::ffff:169.254.169.254` para seu endereço IPv4 canônico (`169.254.169.254`).
4. **Faixas de Endereços Denegadas (Denylist Universal):**
   - **Loopback:** `127.0.0.0/8`, `::1/128` (bloqueado por padrão; liberado unicamente sob flag de política explícita para o upstream);
   - **Link-Local Unicast e Multicast:** `169.254.0.0/16`, `fe80::/10`;
   - **Cloud Metadata Endpoints:**
     * `169.254.169.254` (AWS IMDSv1/v2, GCP, Azure, OCI, DigitalOcean);
     * `fd00:ec2::254` (AWS IMDSv6 IPv6);
     * `100.100.100.200` (Alibaba Cloud Metadata);
     * Hostnames de metadados como `metadata.google.internal` (rejeitados na resolução);
   - **Redes Privadas (RFC 1918):** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`;
   - **Unique Local IPv6 (RFC 4193):** `fc00::/7`;
   - **Origem / Não Especificado / Esta Rede:** `0.0.0.0/8`, `::/128`, `0.0.0.0`;
   - **Multicast e Broadcast:** `224.0.0.0/4`, `ff00::/8`, `255.255.255.255/32`.

A tentativa de conexão a qualquer desses destinos resulta no bloqueio imediato do handshake
de socket com emissão de erro tipado `domain.CodeUpstreamDestinationDenied` (HTTP 502).

---

### 4. Política de Redirecionamentos (HTTP 30x)

- **Comportamento Padrão (Fail-Closed):** O `http.Client` de inferência e de autenticação
  configura `CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }`.
  Redirecionamentos automáticos são **desabilitados**, impedindo que um upstream malicioso
  ou comprometido desvie headers de autenticação (`Authorization: Bearer`) para alvos externos.
- **Redirecionamentos em Mídia (Exceção Controlada):** Caso o subsistema de busca de mídia
  por URL exija seguir redirecionamentos (ex.: CDNs assinadas com URLs temporárias):
  - É imposto um teto máximo de **3 redirecionamentos**;
  - **Cada salto subsequente** é submetido novamente à política completa de egress (revalidação de esquema
    HTTPS e dial-time control contra a denylist de IPs);
  - Nenhum cabeçalho de autenticação do Heimdall é propagado para o destino do redirecionamento.

---

### 5. Governança de Proxies de Saída

- **Validação de Esquema:** Quando configurado via variáveis de ambiente (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`)
  ou configuração local, o proxy deve utilizar exclusivamente os esquemas autorizados: `http`, `https` ou `socks5`.
- **Destino Continua Sujeito a SSRF:** O uso de proxy não isenta o destino final da verificação
  de segurança. Conexões tuneladas (`CONNECT`) para endereços da denylist devem ser recusadas.
- **Sigilo de Credenciais:** As credenciais de proxy (`http://user:password@proxy:port`)
  são tratadas como material sensível, não sendo expostas em logs, traces ou representações de erro.

---

### 6. Orçamentos de Timeout e Streaming

O uso de `http.Client.Timeout` global é **expressamente proibido** para clientes de inferência e streaming,
pois um teto monolítico de relógio abortaria sumariamente gerações de texto extensas ou modelos de raciocínio.
O controle temporal é decomposto em camadas:
- **Dial Timeout (`net.Dialer.Timeout`):** 10 segundos para estabelecimento da conexão TCP;
- **TLS Handshake Timeout (`http.Transport.TLSHandshakeTimeout`):** 10 segundos;
- **Time-to-First-Token / TTFT (`http.Transport.ResponseHeaderTimeout`):** configurável por família
  (padrão de 30s a 60s), medindo o tempo máximo até o recebimento dos primeiros headers HTTP de resposta;
- **Idle / Chunk-to-Chunk Timeout:** monitoramento no relay SSE (`Stream`) garantindo que conexões
  presas sem emissão de pacotes subsequentes sejam interrompidas após um período de inatividade;
- **Deadline Total da Requisição:** governado unicamente pelo `context.Context` originado do cliente downstream,
  garantindo cancelamento em cascata e fechamento dos sockets upstream quando o cliente aborta a chamada.

---

### 7. Limites de Payload e Validação de Mídia

Para prevenir exaustão de memória e ataques de bomba de descompressão:
- **Teto de Resposta Bufferizada:** Limitado a 32 MiB (`DefaultMaxResponseBytes = 32 << 20`) via `io.LimitReader`.
- **Teto de Erro Upstream:** Leitura máxima de 8 KiB (`MaxErrorBodyBytes = 8 << 10`) para extração de mensagens de erro.
- **Teto de Upload:** Requisições de entrada e payloads encaminhados respeitam teto padrão de 8 MiB (`MaxRequestBytes`),
  com teto estrito configurado para uploads multimodais.
- **Fetch de Mídia por URL:**
  - O download de mídias utiliza o cliente de transporte protegido por SSRF;
  - Validação de `Content-Type` estrito para tipos de mídia permitidos (imagens: `image/png`, `image/jpeg`,
    `image/webp`, `image/gif`; áudio: `audio/mpeg`, `audio/wav`, etc.);
  - Validação dos primeiros bytes (**magic bytes**) para impedir ataques de polyglot e interpretação indevida de arquivos executáveis como mídia.

---

### 8. Auditoria, Redação e Taxonomia de Erros

- **Saneamento de URLs:** Nenhuma URL pode ser gravada em log ou erro contendo informações de usuário
  (`user:pass@host`) ou parâmetros de consulta (`query strings`) que possam conter segredos ou chaves.
  O uso de `url.URL.Redacted()` ou do redator central (`contracts.Redactor`) é obrigatório.
- **Taxonomia de Erro (ADR-0002):**
  - Conexão rejeitada pela política de egress em dial-time: `domain.CodeUpstreamDestinationDenied`
    (`error.upstream_destination_denied`, HTTP 502, `ScopeProvider`, `Retryable: false`).
  - URL inválida ou esquema inseguro: `domain.CodeUpstreamInsecureURL`
    (`error.upstream_insecure_url`, HTTP 500, `ScopeRequest`, `Retryable: false`).
  - Falhas de rede de transporte legítimas (ex.: timeout de conexão, reset de socket, falha TLS do provedor):
    `domain.CodeUpstreamUnavailable` (`error.upstream_unavailable`, HTTP 503, `ScopeProvider`, `Retryable: true`),
    permitindo ao `Dispatcher` da F3 acionar failover para a próxima credencial ou provedor disponível.

---

### 9. Reroute e Allowlist de Destinos Lógicos

- O recurso de `reroute` (acionado por gates ou políticas de contingência em combos) só pode apontar
  para provedores e modelos formalmente cadastrados na **Allowlist de Provedores** (`ProviderRegistry`).
- A política de rede de egress (nível de socket/SSRF) opera como barreira de contenção de infraestrutura,
  mas **não substitui** a validação lógica de autorização de destinos definida no roteamento da aplicação.

---

## Consequências

### Critérios de Aceite Verificáveis

1. **Rejeição Dial-time por Padrão:**
   Conexões para `127.0.0.1`, `169.254.169.254`, `::ffff:169.254.169.254`, `fd00:ec2::254`,
   `10.0.0.1`, `172.16.0.1` e `192.168.1.1` falham obrigatoriamente com o código `error.upstream_destination_denied`.
2. **Defesa contra DNS Rebinding:**
   Um nome de host resolúvel para IP público no DNS mas que no dial-time resolve para `127.0.0.1` ou `169.254.169.254`
   é bloqueado no hook `Control` de `net.Dialer`.
3. **Bloqueio de Redirecionamento para Loopback/Privado:**
   Um upstream que responda `302 Found` com cabeçalho `Location: http://127.0.0.1:8080/admin`
   ou `Location: http://169.254.169.254/latest/meta-data` não tem o redirecionamento seguido (`http.ErrUseLastResponse`)
   ou, caso o subsistema de mídia siga redirects, tem a segunda conexão abortada pelo hook dial-time.
4. **Impossibilidade de Desativar TLS:**
   O binário não compila e não oferece opções em que `InsecureSkipVerify` possa ser atribuído como verdadeiro.
5. **Normalização de IPv4-Mapped IPv6:**
   Qualquer variação de notação mapeada IPv6 correspondente a faixas denegadas é interceptada
   pelo desmapeamento (`Unmap()`).
6. **Rejeição de Esquema Inseguro:**
   Qualquer URL configurada como `http://` para destinos remotos não-loopback é rejeitada na inicialização
   com `error.upstream_insecure_url`.

### Dívidas Registradas

- **Connection Coalescing em HTTP/2:** O transporte HTTP/2 padrão de Go pode reutilizar conexões TLS
  abertas para múltiplos domínios caso o certificado TLS seja compartilhado (wildcard ou múltiplos SANs).
  Em ambientes onde diferentes provedores compartilham CDN/IPs e certificados, o pooling deve ser
  monitorado para garantir que não haja bypass lógico entre provedores isolados.
- **Resolver Próprio / DNS-over-HTTPS (DoH):** O runtime utiliza o resolver do sistema operacional
  (`net.DefaultResolver`). Caso o resolver do host seja envenenado, o hook dial-time garante o bloqueio
  do IP privado resultante, mas consultas externas continuam vulneráveis a spoofing no trânsito até o DNS local.
  A implementação de DoH ou verificação DNSSEC é dívida pós-v1.

---

## Alternativas Consideradas

- **(a) Validação apenas de Hostname na URL (Pré-DNS):**
  *Rejeitada.* Deixa o sistema vulnerável a DNS Rebinding: o atacante cadastra um domínio sob seu controle
  com TTL de DNS de 0 segundos, que responde inicialmente um IP público na checagem e em seguida devolve
  `169.254.169.254` na abertura do socket. A única contenção eficaz é validar o IP resolvido no dial-time.
- **(b) Permitir flag `--insecure-skip-tls-verify` para ambientes de desenvolvimento corporativos:**
  *Rejeitada categoricamente.* Essa brecha histórica permite que operadores desativem a segurança em produção,
  expondo tokens de autenticação a ataques de rede locais e ferramentas de inspeção de terceiros.
  Para certificados corporativos internos, o operador deve instalar os certificados no trust store do SO.
- **(c) Seguir redirecionamentos HTTP 30x por padrão:**
  *Rejeitada.* Redirecionamentos automáticos frequentemente vazam cabeçalhos `Authorization` para domínios terceiros
  e constituem o vetor mais comum de contorno de SSRF em gateways de IA.
- **(d) Timeout global via `http.Client.Timeout`:**
  *Rejeitada.* Um timeout global corta chamadas de geração de texto de modelos longos (ex.: 200 segundos de raciocínio).
  O controle deve residir em `ResponseHeaderTimeout` (TTFT), idle timeout no stream e no contexto do chamador.
