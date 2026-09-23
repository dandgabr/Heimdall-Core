# Provedores — catálogo e como adicionar

Um **provedor** no Heimdall é a combinação de duas coisas distintas (ADR-0001):

- **`ProviderFamily`** — a implementação de *protocolo*: imutável, uma por
  dialeto de wire, sem estado de conta. Decide como falar com o provedor.
- **`Credential`** — a *conta*: chave de API ou tokens OAuth, selados no cofre.
  É o que permite multi-conta, cota por credencial e breaker isolado.

O mesmo dialeto (`WireOpenAI`) serve vários provedores; a diferença entre eles é
o *descriptor* e a tabela de modelos, não código novo.

## Catálogo atual

Os quatro provedores registrados vivem em `internal/auth/descriptors.go`
(`auth.Descriptors()`) e são construídos no composition root
(`internal/app/app.go`, `buildFamily`), que escolhe a família **pelo protocolo**:
`cloudcode` → `providers.CloudCode`, todo o resto → `providers.OpenAICompat`.

| ID | Protocolo | Auth | AuthFlow | Modelos | Estado |
| --- | --- | --- | --- | --- | --- |
| `z.ai` | `openai` | `api_key` | `NewAPIKeyFlow` | declarados por config | Utilizável |
| `ollama-cloud` | `openai` | `api_key` | `NewAPIKeyFlow` | declarados por config | Utilizável |
| `command-code` | `openai` | `api_key` | `NewAPIKeyFlow` | declarados por config | Utilizável |
| `antigravity` | `cloudcode` | `oauth` | `NewAntigravityFlow` | declarados por config | **`future`** — sem login/wiring |

Notas de fidelidade ao código:

- **Antigravity** é `Future: true` com `FutureNote` "cloudcode connector;
  requires OAuth login and router wiring — planned". Ele tem os endpoints, o
  client público do CLI, a ocultação e o `RiskNotice` declarados; o conector
  CloudCode existe e é testado com `httptest`, mas não há superfície de login
  interativo nem wiring no Router. O estado reportado é `provider.future`, não
  um "blocked" corrigível pelo usuário.
- **`PendingEndpoints()` está vazio.** Nenhum provedor tem endpoint placeholder;
  Antigravity é `future` por *feature*, não por endpoint não confirmado.
- Os três provedores de API key **não têm `base_url` embutida**: ela vem do
  bloco `[[providers]]` da config. Sem `base_url`, a família registra e é
  listável, mas `BuildExecutor` recusa (um executor sem destino não roda).
- **Todos os quatro** aceitam `models` declarados na config; a partir deles o
  Router expande passo de modelo e wildcard. Um modelo que a família não declara
  retorna `Capabilities` `ok=false` e o Router pula o provedor (ADR-0001).

## Como adicionar um provedor por API key (declarativo)

Não requer código novo: um provedor OpenAI-compatible é **dado**. O caminho é
declará-lo num descriptor e configurar o transporte.

1. **Registre o ID e o descriptor** em `internal/auth/descriptors.go`:
   adicione a constante `Provider<X>` e uma entrada em `Descriptors()` com
   `Protocol: contracts.WireOpenAI` (o default do `OpenAICompat`). Se o provedor
   exigir um `AuthHeader` diferente do `Bearer`, o transporte cuida disso via
   config (`x-api-key`).
2. **Declare o modo de auth** em `AuthModesFor` (`internal/auth/factory.go`):
   `{contracts.AuthAPIKey}`. O `FlowFactory` deriva o fluxo daí.
3. **Configure o transporte** em `[[providers]]` (não há código):

   ```toml
   [[providers]]
   id           = "meu-provedor"
   base_url     = "https://api.exemplo.com/v1"
   auth_header  = "bearer"        # ou "x-api-key"
   enabled      = true
   models       = ["modelo-a", "modelo-b"]
   # ttft       = "60s"           # TTFT; default do executor
   # idle       = "0s"            # gap entre chunks; 0 desabilita
   # allow_loopback = false       # só para runtime local
   ```

4. **Cadastre a credencial** e teste:

   ```sh
   printf '%s' "$KEY" | heimdall provider add-key meu-provedor --label work
   heimdall provider status
   heimdall provider test meu-provedor    # monta o executor e chama GET {base}/models
   ```

O `buildFamily` escolhe a família pelo `Protocol`; `OpenAICompat.BuildExecutor`
recusa uma credencial de outra família, uma `base_url` vazia ou um modo de auth
que a família não declara — falhas tipadas, nunca silenciosas.

**Se o protocolo não for OpenAI-compatible**, você precisa de uma família nova
(ver abaixo).

## Como adicionar um provedor OAuth (com ocultação por provedor)

OAuth é mais delicado porque a credencial precisa ser obtida por um fluxo
interativo e, em provedores que restringem o harness, **pode exigir ocultação**
(ADR-0003).

### 1. Descriptor e fluxo

Em `internal/auth/descriptors.go`, declare o descriptor com:

- `Protocol` (o dialeto de wire, ex.: `WireCloudCode` para Google),
- `AuthEndpoint`/`TokenEndpoint` (ou `DeviceAuthEndpoint`),
- `DefaultScopes`, `RedirectAllowlist` (match exato; a porta efêmera é validada
  à parte),
- `ClientID` e, se o cliente público exigir, `RequiresClientSecret: true`.
  **O `ClientSecret` NÃO é embutido no descriptor**: o valor em claro em código
  é um risco de secret scanning (bloqueia o push no GitHub) e nunca deve ir para
  o repositório. Quem o fornece é o **operador**, pela config do provedor
  (`client_secret` ou, preferencialmente, `client_secret_env`) — ver a seção
  "Segredo de cliente OAuth" abaixo. Sem ele, o fluxo falha fechado com
  `auth.provider_client_secret_missing`.

O `FlowFactory.Build` escolhe o fluxo:

- `RequiresClientSecret` → `oauth.NewAntigravityFlow` (authorization_code com
  client_secret + descoberta de projeto/tier + onboarding), **exigindo** que o
  segredo tenha sido injetado pelo composition root a partir da config;
- com `DeviceAuthEndpoint` → `oauth.NewDeviceCodeFlow`;
- senão → `oauth.NewPKCEFlow`.

E declare o modo `AuthOAuth` em `AuthModesFor`.

### Segredo de cliente OAuth (Antigravity) — fornecido pelo operador

O cliente do CLI do Antigravity é do tipo *confidential*: o token exchange exige
um `client_secret` além do `client_id`. Esse valor **não acompanha o binário nem
o repositório**; o operador o obtém do próprio harness oficial (o `client_secret`
público do CLI, no binário `agy`/no bundle do plugin) e o informa por config. Há
duas formas, com a **mesma precedência** do resto da config
(`env > flag > arquivo > default`):

```toml
[[providers]]
id            = "antigravity"
# Opção recomendada: só o NOME da variável vai para o arquivo.
client_secret_env = "ANTIGRAVITY_CLIENT_SECRET"
# Alternativa: o valor direto no arquivo (fica legível em disco; prefira o env).
# client_secret = "<o client secret público do CLI>"
```

```sh
# O valor nunca entra no repositório nem no `ps`/histórico:
export ANTIGRAVITY_CLIENT_SECRET='<o client secret público do CLI>'
```

Regras:

- **Nunca commitar o valor.** O teste `TestNoCommittedClientSecret`
  (`internal/auth/secret_scan_test.go`) varre `internal/` e `docs/` e **falha** se
  encontrar um padrão de client secret (`GOCSPX-`, `ClientSecret: "<literal>"`,
  `sk-...`) — é o guard que impede a reincidência.
- **`config show` redige** `providers.<i>.client_secret` (mostra `[REDACTED]`);
  o `client_secret_env` (nome da variável) é exibido, pois não é segredo. O
  valor nunca aparece em log.
- **Sem segredo → falha fechada**: `heimdall login` (próxima fase) e qualquer uso
  do fluxo falham com `auth.provider_client_secret_missing`, nunca com um
  placeholder.


### 2. Ocultação por provedor (`Obfuscation`)

Se o backend do provedor recusar clientes não-oficiais (*fingerprint* de
harness), o descriptor declara uma camada `contracts.Obfuscation`, aplicada
**pelo executor daquela família**, nunca globalmente:

```go
Obfuscation: contracts.Obfuscation{
    UserAgent:         "antigravity/ide/2.11.0 darwin/arm64", // UA oficial, pinado
    RequiresUserAgent: true,
    PromptRewrites:    []contracts.PromptRewrite{ /* remove branding concorrente */ },
    ToolCloaking:      &contracts.ToolCloaking{ NameSuffix: "_ide", DecoyTools: ... },
    SyntheticProject:  true, // gera project sintético se o loadCodeAssist não der um
},
RiskNotice: "provider.risk_notice.<provider>",
```

Regras (ADR-0003):

1. **Por provedor, explícita e versionada.** A ocultação vive no descriptor e no
   executor da família; não existe camada genérica.
2. **Separada do protocolo.** O envelope de wire é independente do fingerprint;
   `ProviderDescriptor.Protocol` continua sendo só o dialeto.
3. **Reversível e testável.** A camada é pura e determinística (entrada→saída),
   com golden files em `internal/obfuscate/testdata/`.
4. **`RiskNotice` obrigatório** quando há ocultação. É um `code` i18n exibido em
   `provider list`/`status`, na GUI e na CLI. Uso de sessão de assinatura como
   proxy pode causar **suspensão ou banimento** — risco aceito pelo dono do
   projeto (ADR-0003).
5. **Nunca ocultação da identidade do usuário.** A ocultação é do harness, nunca
   de quem o usuário é.

### 3. Família e executor

Se o protocolo for novo, crie uma família (modelo: `providers.CloudCode` +
`internal/executors/cloudcode`):

- a família implementa `contracts.ProviderFamily` (`ID`, `AuthModes`,
  `Protocol`, `Descriptor`, `Capabilities`, `BuildExecutor`);
- `BuildExecutor` monta o executor do dialeto, passando o `Descriptor` (para a
  ocultação) e a política de egress;
- registre em `buildFamily` (`internal/app/app.go`) sob o `WireFormat`
  correspondente.

Por fim, ligue o modo no `FlowFactory.modes` e em `AuthModesFor`, e faça
`heimdall provider status` reportar `ready` só quando houver credencial
utilizável.

## Estados de readiness

`provider list` e `provider status` compartilham a **mesma** regra
(`providerReadiness`), então não podem divergir:

- **`future`** — a feature não está entregue; não é corrigível pelo usuário
  (`provider.future`).
- **`blocked(auth.provider_pending_endpoints)`** — endpoint placeholder. Hoje
  nenhum provedor cai aqui.
- **`blocked(provider.login_required)`** — provedor OAuth sem credencial no
  cofre.
- **`blocked(provider.no_credential)`** — provedor de API key sem chave.
- **`blocked(credential.invalid_auth_mode)`** — credencial com modo que a
  família não suporta.
- **`ready`** — há uma credencial utilizável cujo modo a família aceita.

## Política de egress (todos os provedores)

Toda conexão upstream passa pela política de egress (ADR-SEC-05): HTTPS
obrigatório, denylist de ranges privados/loopback, revalidação de redirect e TLS
verificado. Uma URL `http://` só é aceita para um literal de loopback com
`allow_loopback = true`, e `allow_loopback` só é legal para esse literal. O
mesmo vale para os clientes OAuth (`internal/auth/oauth` usa a mesma política).
