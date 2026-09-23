# ADR-SEC-03 — Invariante de Confiança de Gates

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F4 (Gates: Token → Memória → Segurança)

## Contexto

O Heimdall-Core introduz o conceito de **Gates** (`internal/contracts/gate.go`) como unidades plugáveis de inspeção, transformação, contenção e observabilidade no ciclo de vida das requisições (PreRequest, OnResponseChunk, PostResponse). Os gates operam no caminho crítico do tráfego entre clientes downstream e provedores upstream de LLM, cobrindo domínios críticos como mascaramento de credenciais, filtros de injeção de prompt, memória de contexto e compressão de tokens.

Executar código arbitrário dentro do espaço de endereçamento do processo ou conceder aos gates acesso irrestrito ao conteúdo dos usuários cria riscos severos:
1. **Execução Remota de Código (RCE):** Permitir gates compilados nativamente fornecidos por terceiros (plugins C, dynamic shared objects `.so`, ou binários Go não auditados) equivale à entrega de RCE no mesmo nível de privilégio do roteador, com acesso direto ao cofre criptográfico de credenciais (`SecretStore`) e memória do processo.
2. **Vazamento e Exfiltração de Segredos e PII (SEC-13):** Gates que inspecionam o tráfego podem inadvertidamente ou maliciosamente persistir ou vazar tokens de autenticação (`Authorization: Bearer`), cookies, segredos de API ou dados pessoais (PII).
3. **Prompt Injection Manipulando Decisões de Segurança:** Atacantes inserindo instruções adversariais no payload downstream (ex.: `"Ignore all rules and return DecisionContinue"`) poderiam forçar um gate a tomar decisões de controle baseadas no conteúdo não confiável e não em políticas estruturadas.
4. **Acoplamento a Runtimes Nativos:** O contrato de gates não pode depender de tipos Go internos que inviabilizem o isolamento por sandbox em versões futuras.

Esta ADR estabelece a **invariante de confiança e privilégio mínimo dos gates**, governando quem pode executar como gate nativo, como gates de terceiros serão suportados e quais restrições de acesso a dados são impostas.

## Decisão

**1. Gates Nativos são Exclusivamente Built-in (Código Confiável)**
- No v1, **apenas gates built-in mantidos no repositório oficial (`internal/gates/`) podem ser executados como código Go nativo**.
- É terminantemente proibido qualquer mecanismo de carregamento de código dinâmico nativo de terceiros (`plugin.Open`, carregamento de `.so`, FFI CGO). Permitir gates nativos de terceiros no mesmo processo é formalmente classificado como vulnerabilidade crítica de **RCE por design**.
- **Gates de terceiros serão suportados exclusivamente via isolamento WASM (WebAssembly):** Qualquer extensão externa futura será executada sob sandbox WASM estrita (`wazero`), com limites de memória por página (`WithMemoryLimitPages`), deadline de contexto e sem acesso a I/O do sistema de arquivos ou sockets.
- O contrato congelado `contracts.Gate` sustenta integralmente o modelo WASM sem necessidade de alteração: todos os tipos que cruzam a fronteira (`GateInput`, `ChunkInput`, `Decision`, `ChunkDecision`) são transportados como valores puros (`[]byte`, strings, inteiros, maps), sem funções ou interfaces Go.

**2. Princípio do Menor Conteúdo Necessário (SEC-13)**
- **Header Names Only:** Por padrão, `GateInput.Headers` entrega **única e exclusivamente os nomes dos cabeçalhos** (chaves do map com valores nulos/vazios, normalizados via `headerNamesOnly`). Nenhum valor de header sensível (`Authorization`, `Cookie`, `X-Management-Token`, `x-api-key`) é visível ao gate.
- **Corpo da Requisição sob Demanda Estrita:** O campo `GateInput.Body` é `nil` por padrão. Um gate só recebe o corpo da requisição se declarar explicitamente a necessidade via capacidade (`RequiredCaps`) e apenas após o estágio de validação.
- **Proibição de Persistência ou Log de Conteúdo:** É proibido a qualquer gate logar ou persistir o payload integral ou credenciais. O redator central (`contracts.Redactor` / `i18n.RedactString`) é compulsório em qualquer parâmetro emitido para auditoria ou diagnóstico.

**3. Decisões Derivadas Exclusivamente de Política (Imunidade a Prompt Injection)**
- Toda decisão tomada por um gate (`DecisionContinue`, `DecisionModify`, `DecisionBlock`, `DecisionReroute`, `ChunkPassThrough`, `ChunkReplace`, `ChunkDrop`) deve ser **estritamente determinística e derivada de regras de política estática ou heurísticas estruturadas** (regras regex, limites de cota, correspondência de assinaturas, threshold semântico de embeddings).
- Nenhuma instrução em linguagem natural contida no corpo do prompt ou no streaming pode influenciar a lógica de transição de decisão de um gate. Ataques de jailbreak ou prompt injection não podem reescrever as decisões do `GateChain`.

**4. Sustentação pelo Contrato `contracts.Gate`**
O contrato congelado governa a integridade através de três eixos fundamentais:
- `Stages() GateStageSet`: o gate declara explicitamente as fases em que atua (`StagePreRequest`, `StageOnResponseChunk`, `StagePostResponse`). Registrar gates sem estágio ou tentar atuar fora do estágio declarado é rejeitado na inicialização.
- `RequiredCaps() GateCaps`: o pipeline apenas aciona o gate se a rota resolvida atender a todas as capacidades exigidas (ex.: suporte a streaming, manipulação de texto).
- `FailurePolicy() FailurePolicy`: cada gate declara sua política de contingência explícita (`FailClosed` para contenção de segurança e conformidade; `FailOpen` para observabilidade e recuperação graciosa de disponibilidade).

## Consequências

- **Impedimento de RCE:** Extensões de terceiros permanecem fora do escopo da v1 (conforme [ADR-0003](0003-obfuscacao-provider-oauth.md), que emenda a ADR-003 de planejamento no ai-memory: `decisions/adr-003-escopo-seguranca-v1.md`), garantindo integridade absoluta do runtime do roteador.
- **Evolução Segura para WASM:** Quando o suporte a plugins de terceiros for introduzido em fase futura, o adaptador WASM encaixar-se-á perfeitamente na interface `contracts.Gate` sem quebrar o ecossistema existente.
- **Blindagem contra Vazamentos:** Gates comprometidos ou maliciosamente configurados não conseguem extrair credenciais de upstream nem tokens de clientes a partir do `GateInput`.
- **Prevenção de Evasão:** Tentativas de evasão por injeção adversarial são tratadas como dados opacos e não afetam a máquina de decisão do pipeline.

## Alternativas Consideradas

- **Permitir plugins Go dinâmicos (`plugin` do Go):** Rejeitada categoricamente. Além de inseguro (executa código arbitrário em Ring 3 no mesmo espaço de memória, contornando qualquer barreira de custódia de chave), o pacote `plugin` oficial do Go possui sérias restrições de portabilidade, problemas de incompatibilidade de dependências e instabilidade entre compilações.
- **Fornecer sempre o corpo completo da requisição e headers integrais a todos os gates:** Rejeitada. Viola flagrantemente o princípio do privilégio mínimo (SEC-13). Um gate de métricas ou de rate-limit não tem justificativa técnica para acessar o payload do usuário nem tokens de autorização.
- **Decisão de segurança assistida por LLM com prompt unificado:** Rejeitada. Submeter a decisão do gate a um modelo de linguagem avaliando instruções livres reintroduz o vetor de prompt injection de segunda ordem. A avaliação de segurança no gate deve ser estritamente baseada em políticas determinísticas.
