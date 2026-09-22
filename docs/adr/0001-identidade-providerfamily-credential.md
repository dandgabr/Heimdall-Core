# ADR-0001 — Identidade: `ProviderFamily` × `Credential`

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F1 (Auth e Providers)

## Contexto

O plano v1 tratava "provedor" como uma coisa só e a `Provider` acumulava dois
conceitos distintos:

1. o **código do protocolo** — a implementação do dialeto de uma família
   (Anthropic, OpenAI-compat, Gemini). É imutável, existe uma vez por binário e
   não guarda segredo;
2. a **conta concreta** — o par (token/refresh token, escopos, identidade
   upstream) que o usuário autenticou. É mutável, existe N vezes e é o que
   expira, é revogado ou estoura cota.

Conflacionar os dois quebra o produto de formas concretas:

- **multi-conta**: duas contas OAuth da mesma família (dois e-mails Anthropic)
  não coexistiriam — a segunda sobrescreveria a primeira;
- **cota por conta**: cota é consumida pela conta, não pelo protocolo. Sem
  separação não há onde pendurar o contador;
- **round-robin**: alternar contas da mesma família seria impossível;
- **breaker**: um 429 de uma conta não pode abrir o circuito da família inteira
  (derrubaria as demais contas sadias).

O defeito foi apontado na revisão de arquitetura/segurança
(`notes/revisao-plano-arq-sec.md`, mudança estrutural nº 1) e o código da F0 já
começou a separação.

### Alinhamento com o código existente

- `internal/domain/ids.go` já define `ProviderID` (família/protocolo) e
  `CredentialID` (conta), com comentários que fixam exatamente essa distinção, e
  `ComboID`/`RequestID`/`ModelID` como identificadores irmãos.
- `internal/domain/errors.go` define `ErrScope` com `ScopeRequest`,
  `ScopeCredential` e `ScopeProvider`. Essa tripla **só faz sentido** se família
  e credencial forem entidades separáveis: `ScopeCredential` é o que permite
  cooldownar uma conta sem afetar as outras.
- `internal/contracts/contracts.go` mantém as portas mínimas (`Clock`, `IDGen`,
  `Redactor`); as portas de identidade entram na F1 como `ProviderFamily`,
  `Credential` e `AuthFlow`.
- `internal/config/config.go` tem hoje um bloco `Passthrough` com `Family` +
  `APIKey`/`APIKeyEnv` — ele é o embrião de uma família com uma credencial e
  será substituído pelo registry de providers na F1. O `Family string` ali já
  aponta para `ProviderID`.

## Decisão

**Separar `ProviderID` (família/protocolo, imutável) de `CredentialID` (conta
concreta), com `Credential` como o agregado da conta.**

- `ProviderID` identifica a **família**: o código que implementa um protocolo.
  Imutável, único por binário, sem segredo associado.
- `CredentialID` identifica a **conta**: uma autenticação concreta de uma
  família. É o alvo de cota, cooldown e rotação.
- **`AuthMode`** (`None | APIKey | OAuth`) identifica o mecanismo de credencial
  da conta e determina qual `AuthFlow` a família instancia e como o refresh
  funciona. `None` cobre famílias sem autenticação (ex.: um Ollama local), onde
  `SecretRef` é vazio.

Forma canônica do agregado (a fixar em `internal/domain` na F1):

```go
type AuthMode uint8

const (
    AuthNone   AuthMode = iota // sem credencial (local)
    AuthAPIKey                 // chave estática contratada
    AuthOAuth                  // PKCE / device_code (sessão de assinatura)
)

// Credential é a conta. Nunca carrega segredo em claro: SecretRef é um handle
// opaco resolvido pelo SecretStore dentro do Executor e nunca logado.
type Credential struct {
    ID        CredentialID
    Provider  ProviderID
    AuthMode  AuthMode
    Label     string       // rótulo humano, ex.: "conta trabalho"
    SecretRef SecretRef    // opaco; vazio quando AuthMode == AuthNone
    Meta      AccountMeta  // identidade upstream não-secreta (e-mail, plano, escopos), datas
    CreatedAt time.Time
    ExpiresAt time.Time    // zero = sem expiração conhecida
}
```

**Referência por ID, nunca por ponteiro.** Componentes que atravessam uma
fronteira (Router, Dispatcher, Gate, persistência) trafegam `ProviderID` /
`CredentialID` ou o `Credential` **por valor**; ponteiros para objetos vivos
criam acoplamento de ciclo de vida e tornam o teste não-determinístico.

**Regra de identidade:** `ProviderID` + `AuthMode` caracterizam a *família* e o
*modo*; `CredentialID` caracteriza a *conta*. Qualquer código que precise das
duas coisas recebe as duas.

## Consequências

- **Schema do `CredentialStore`:** tabela de credenciais com chave
  `CredentialID`, FK lógica para `ProviderID`, colunas `auth_mode`, `label`,
  `secret_ref`, `meta` e timestamps. Chave única opcional em
  `(provider, account_key)` para impedir a mesma conta duplicada. A migração
  `0001_init.sql` (hoje só `meta`) cresce aqui.
- **Assinaturas (F1+):** `AuthFlow`, `Executor`, `Router` e `Gate` recebem
  `Credential` (ou `CredentialID` + metadados), **nunca** `ProviderFamily`.
  A família é consultada no registry por `ProviderID` para construir o
  `Executor` daquela credencial.
- **Cota é por `Credential`.** `QuotaFilter`, `Breaker` e `UsageRecorder`
  trabalham no eixo `CredentialID`; o `BreakerKey` carrega
  `{Provider, Credential, Model}` e o escopo decide a granularidade.
- **`DomainError.Scope` ganha semântica operacional:** `ScopeCredential`
  cooldowna a conta; `ScopeProvider` abre o circuito da família; `ScopeRequest`
  não cooldowna nada. Ver ADR-0002.
- `internal/domain/ids.go` não muda: os tipos já existem. O que entra é o
  agregado `Credential` e o registry por família.

## Alternativas consideradas

- **Manter `Provider` único com uma lista de contas embutida.** Rejeitada: o
  agregado vira um God object, o ciclo de vida da conta (expira, revoga, rotaciona)
  fica preso ao da família (que é estática), e o registry fica stateful.
- **Modelar conta como `Provider` clonado por conta** (um `Provider` "por
  credencial"). Rejeitada: duplica o código de protocolo, impede compartilhar o
  `Translator`/`Executor` da família e não escala para 3+ contas.
- **Identificar a conta só pelo token (sem ID estável).** Rejeitada: o token
  rotaciona no refresh e a cota/cooldown precisam de uma chave estável; usar o
  hash do segredo como ID vaza entropia e quebra a rotação.
- **Referenciar `Credential` por ponteiro compartilhado.** Rejeitada: acopla
  ciclo de vida, dificulta teste determinístico e cria corrida em refresh/rotação.
