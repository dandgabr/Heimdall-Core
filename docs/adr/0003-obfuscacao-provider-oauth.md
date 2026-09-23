# ADR-0003 — Ocultação (obfuscação) por provedor OAuth

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** Conectores OAuth (F1/F2 estendidos; habilita Antigravity)
- **Substitui:** a cláusula **"sem cloaking/fingerprint"** da ADR-003 (ai-memory: `decisions/adr-003-escopo-seguranca-v1.md`), e o entendimento correlato em `notes/revisao-plano-arq-sec.md` e `notes/analise-candidatos.md`.

## Contexto

Alguns provedores que expõem uma assinatura via OAuth restringem o uso do token ao
**harness/cliente oficial** (a IDE ou o CLI do próprio provedor). Quando a requisição chega
por um cliente diferente, o backend do provedor pode recusá-la (ex.: `429 RESOURCE_EXHAUSTED`
mesmo com cota disponível), por fingerprint de cliente: user-agent, formato de ferramentas
(tools) e branding no system prompt.

Exemplo concreto investigado: o **Antigravity** (Google). Ele não fala OpenAI nem o Gemini
público — fala o dialeto **CloudCode** (`daily-cloudcode-pa.googleapis.com`, métodos
`v1internal:*`). A implementação de referência do 9router
(`open-sse/executors/antigravity.js`) faz, além do protocolo, uma **ocultação deliberada**
para que o backend aceite a requisição:

1. **Ferramentas (tools):** renomeia as ferramentas do cliente com sufixo (`_ide`) e injeta
   ferramentas "isca" com os nomes nativos do cliente oficial.
2. **System prompt:** reescreve branding de clientes concorrentes (remove `"You are a Claude
   agent…"`, header `x-anthropic-billing-header`, troca `opencode` por `antigravity`).
3. **User-Agent:** forja o UA do cliente oficial (`antigravity/ide/<versão> darwin/arm64`),
   fixo mesmo fora do macOS.
4. **Project id:** gera um `project` sintético quando o `loadCodeAssist` não devolve um
   `cloudaicompanionProject`.
5. O próprio registry do 9router marca o provedor como `deprecated` com `RISK_NOTICE`.

A comparação com o binário `agy` instalado confirmou que o **protocolo** (endpoints, envelope,
client_id/secret público do CLI) é real; a **ocultação** é uma escolha de implementação, não um
requisito do protocolo.

## Decisão

**Toda conexão OAuth a um provedor que restrinja o harness pode exigir uma camada de ocultação
específica daquele provedor para funcionar.** A ocultação é modelada por provedor, não
global, e é aplicada no executor da família OAuth correspondente.

Regras:

1. **Por provedor, explícita e versionada.** A ocultação de cada provedor vive no seu executor
   (`internal/executors/<provider>`), declarada no descriptor (`Obfuscation: {UserAgent,
   PromptRewrites, ToolCloaking, SyntheticProject}`). Não há ocultação "genérica" aplicada a
   todos.
2. **Separada do protocolo.** O envelope/roteamento (CloudCode, Gemini, Anthropic) é
   independente das técnicas de ocultação; o teste de protocolo não depende do fingerprint.
3. **Ela é reversível e testável.** A camada é pura e determinística (entrada→saída), com
   golden files como os tradutores; um teste prova que o corpo enviado casa o fingerprint
   esperado, sem rede.
4. **RISK_NOTICE obrigatório.** Cada provedor com ocultação exibe aviso de ToS na CLI e na GUI
   (F5): uso de sessão de assinatura como proxy pode causar bloqueio/banimento da conta. O
   aviso é condição de habilitação do provedor.
5. **Nunca ocultação de identidade do usuário.** A ocultação é do *harness/cliente*, nunca de
   quem o usuário é; nenhum dado de identidade é falsificado.

## Consequências

- **Risco aceito explicitamente pelo dono do projeto:** a ocultação converte risco contratual
  (violar ToS) em risco de **banimento ativo** da conta, por evadir detecção. Registrado aqui
  como decisão consciente; a ADR-003 perde a cláusula que proibia isso.
- Habilita o conector **Antigravity** (executor CloudCode + ocultação) e serve de modelo para
  outros provedores restritos.
- `ProviderDescriptor.RequiresClientSecret`: o fluxo do Antigravity é
  `authorization_code` **com client_secret** (client público do CLI), não PKCE puro; o
  contrato passa a admitir segredo de cliente quando o descriptor o exigir.
  **Emenda (2026-09-23):** o `client_secret` **NÃO é embutido no descriptor** — um
  literal em código é um risco de secret scanning (bloqueou o push no GitHub). O
  descriptor carrega só `ClientID` (público) e `RequiresClientSecret: true`; o
  **operador** fornece o segredo via a config do provedor (`client_secret` ou
  `client_secret_env`, com a precedência normal), e o composition root o injeta no
  `FlowFactory` (`NewFlowFactoryWithSecrets`). Sem ele, o fluxo **falha fechado**
  com `auth.provider_client_secret_missing` — nunca um placeholder. `config show`
  redige o campo; o valor nunca é logado; um teste-guard varre `internal/` e
  `docs/` contra a reintrodução.
- A camada de ocultação aumenta a superfície de manutenção: quando o provedor muda o
  fingerprint, o conector quebra (falha explícita, não silenciosa).

## Alternativas consideradas

- **Manter a proibição (ADR-003 original).** Rejeitada pelo dono do projeto: sem a ocultação o
  provedor simplesmente não funciona para o caso de uso pretendido.
- **Ocultação global/genérica.** Rejeitada: fingerprints são específicos; aplicar a todos
  arriscaria quebrar provedores que não restringem harness.
- **Delegar ao cliente externo (o harness original).** Rejeitada: o objetivo do roteador é
  unificar os clientes sob uma API só.
