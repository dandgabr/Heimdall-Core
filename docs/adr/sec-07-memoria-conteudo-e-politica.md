# ADR-SEC-07 — Memória: Conteúdo, TTL, Namespace e Governança de Privacidade

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F4 (Gates: Token → Memória → Segurança)

## Contexto

A Fase F4 do Heimdall-Core introduz o gate de **Memória de Contexto** (implementado com busca híbrida FTS5 e busca vetorial embutida `vec0` via extensão sqlite-vec). Esse subsistema capacita o roteador a reter fatos, preferências e histórico de turnos anteriores e reintroduzi-los no prompt para personalizar a inferência.

A persistência contínua de conversas e contexto em banco de dados local introduz riscos severos de segurança e privacidade:
1. **Quebra de Isolamento Multi-Tenant (Vazamento de Contexto):** Se memórias de clientes distintos forem misturadas, a inferência de um usuário pode vazar segredos ou informações privadas de outro.
2. **Envenenamento de Memória (Memory Poisoning):** Se dados persistidos forem tratados com o mesmo nível de confiança de instruções do sistema (`System Prompt`), dados manipulados por injeção adversarial podem sequestrar o comportamento do modelo em turnos futuros.
3. **Não-Conformidade com LGPD / GDPR:** Armazenar dados pessoais por tempo indeterminado viola os princípios de minimização, retenção limitada e o direito do titular à exclusão (direito de expurgo/esquecimento).
4. **Degradação de Latência no Downstream:** Se a geração de embeddings e gravação no banco de dados ocorrerem no caminho síncrono da resposta, o tempo total de resposta ao usuário sofrerá degradação severa.

Esta ADR formaliza os requisitos normativos para o schema de memória, TTL, isolamento mandatório por namespace, prevenção a envenenamento, privacidade (LGPD/GDPR) e desacoplamento de escrita.

## Decisão

**1. Desacoplamento Arquitetural: `Retriever` Síncrono vs `Writer` Assíncrono**
O gate de memória é estruturado compulsoriamente como duas unidades funcionais independentes:
- **`MemoryRetriever` (PreRequest, Síncrono, FailOpen):** Executado antes da montagem final do prompt. Consulta o banco local por memórias relevantes e as injeta no contexto. Possui política `FailOpen`: caso a busca falhe ou atinja timeout (orçamento máximo de 100ms), o roteador segue normalmente sem enriquecimento de memória.
- **`MemoryWriter` (PostResponse, Assíncrono, Fora do Caminho da Resposta):** A persistência de novos fatos, resumos e geração de embeddings roda fora do ciclo de vida da requisição downstream, desacoplada via `AsyncSink`. Ela nunca atrasa o primeiro byte nem a conclusão da resposta ao usuário.

**2. Schema Estrito, TTL e Metadados de Proveniência**
Toda entrada de memória persistida no banco SQLite deve seguir obrigatoriamente a estrutura:
- `id` (UUIDv7 determinístico ou aleatório com ordenação temporal);
- `namespace` (Identificador estrito de escopo derivado da chave de API / cliente);
- `content` (Texto da memória, redigido contra segredos);
- `embedding` (Vetor float32 gerado pelo motor local ou remoto autorizado);
- `created_at` (Timestamp UTC);
- `expires_at` (Timestamp UTC de expiração calculado com base no TTL);
- `provenance` (Metadado de auditoria: `source: user|assistant|system`, `turn_id`, hash da mensagem original).

**Regra de Imunidade Anti-Poisoning:**
Memórias recuperadas são marcadas e delimitadas no prompt downstream com tags explícitas de **dados não confiáveis** (ex.: `<retrieved_memory provenance="...">...</retrieved_memory>`). Elas **jamais** devem ser inseridas como diretivas de controle de sistema (`system instructions`). O prompt deve explicitar ao modelo que memórias são fatos históricos consultivos e não têm autoridade para revogar regras de segurança.

**3. Isolamento Mandatório por Namespace**
- O particionamento de memórias é **estritamente isolado por namespace**.
- O namespace é derivado criptograficamente do identificador do cliente ou hash da chave de API (`sha256(client_id)`).
- É **proibida** qualquer consulta sem filtro de `namespace`. Toda cláusula SQL de busca vetorial (`vec0`) ou léxica (`FTS5`) deve conter a restrição obrigatória `WHERE namespace = ?`.

**4. TTL e Política de Retenção Limitada**
- Nenhuma memória é perene por padrão. Toda entrada deve possuir um **TTL (Time-To-Live)** configurado (padrão de 30 dias para memórias episódicas; 90 dias para preferências declaradas).
- Um worker periódico (background sweep) e triggers no banco devem purgar registros onde `expires_at < NOW()`.

**5. Governança de Privacidade (LGPD / GDPR) e Redação Compulsória**
- **Minimização de PII:** Antes de gravar qualquer memória no `AsyncSink`, o payload passa compulsoriamente pelo redator central (`i18n.RedactString` / `PII Masker`). Dados sensíveis como CPFs, números de cartão de crédito, senhas e tokens de autenticação são mascarados antes de atingir o disco.
- **Direito de Expurgo (Right to Erasure):** A Management API deve disponibilizar rotas para consulta e exclusão em cascata de todas as memórias vinculadas a determinado `namespace` (`DELETE /api/v1/memory?namespace=...`), com remoção física imediata das tabelas FTS5 e índices vetoriais.
- **Embeddings Seguros:**
  - O motor de embeddings opera em modo **Local-First** por padrão (utilizando modelos locais rápidos e offline).
  - O uso de APIs externas de embeddings é estritamente **opt-in explícito** do operador.
  - Caso embeddings externos sejam autorizados, a requisição deve ser submetida compulsoriamente à política de egress da [ADR-SEC-05](sec-05-politica-de-egress.md), com pseudonimização prévia do payload.

## Consequências

- **Privacidade Assegurada:** Clientes diferentes não têm qualquer possibilidade de colisão ou vazamento de memórias mútuas.
- **Conformidade Regulatória:** Aderência direta à LGPD e ao GDPR através de ciclo de vida delimitado por TTL, minimização na ingestão e capacidade de exclusão a pedido do titular.
- **Imunidade contra Envenenamento:** O demarcador de proveniência impede que atacantes utilizem memórias para realizar ataques de persistência de jailbreak.
- **Desempenho Preservado:** Latência de resposta downstream é totalmente isolada dos custos de banco de dados e geração de embeddings através do `AsyncSink`.

## Alternativas Consideradas

- **Persistência síncrona em `PostResponse`:** Rejeitada categoricamente. Gerar embeddings e gravar índices SQLite vetoriais síncronos adicionaria de 200ms a 1s à resposta de cada requisição.
- **Armazenamento de memórias em texto puro sem limpeza:** Rejeitada. Criaria um banco de dados local com alto volume de PII e credenciais vazadas em texto claro.
- **Memória global compartilhada sem namespace:** Rejeitada. Quebraria os princípios mais fundamentais de segurança multi-tenant.
