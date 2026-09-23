# ADR-SEC-09 — Cadeia de Suprimentos e Release

- **Status:** Aceita
- **Data:** 2026-09-23
- **Fase / bloqueia:** F6 (Empacotamento e Documentação)

## Contexto

O Heimdall-Core é distribuído como um binário estático autocontido em Go, operando no caminho crítico da infraestrutura de IA local como roteador e guardião de credenciais de provedores externos (LLMs). Esse posicionamento torna a integridade do artefato e a segurança da cadeia de suprimentos de software (*software supply chain*) vitais:
1. **Comprometimento de Dependências:** A introdução de bibliotecas transitivas vulneráveis, maliciosas ou descontinuadas pode levar ao roubo de chaves de API, vazamento de tokens de autenticação ou quebra das garantias criptográficas do cofre local (`SecretStore`).
2. **Ataques de Build e Irreprodutibilidade:** Se o processo de compilação depender de variáveis dinâmicas de ambiente, relógios não determinísticos ou caminhos absolutos locais da máquina do desenvolvedor, é impossível para auditores externos provarem que o binário publicado corresponde estritamente ao código-fonte inspecionado no repositório.
3. **Ausência de Proveniência e Assinatura Criptográfica:** Sem uma lista formal de componentes (*Software Bill of Materials* - SBOM) e assinaturas digitais verificáveis, usuários finais e pipelines automatizados ficam incapazes de auditar vulnerabilidades conhecidas ou detectar adulterações/trojanizações pós-compilação em trânsito.
4. **Acoplamento Inseguro a Runtimes Nativos (`CGO`):** O uso de CGO vincula a compilação a bibliotecas dinâmicas do sistema operacional host (`glibc`, etc.), introduzindo superfícies de ataque em memória (C/C++), inviabilizando compilações estáticas seguras e complicando a matriz de cross-compile para arquiteturas distintas (amd64/arm64).
5. **Precedente de Plugins de Terceiros:** A execução de código dinâmico ou plugins não assinados (abordada na ADR-SEC-03) reitera a necessidade de garantias explícitas quanto à proveniência e integridade de qualquer extensão de terceiros.

Esta ADR define a política normativa e obrigatória para a **governança de dependências, geração de SBOM CycloneDX, assinatura e proveniência de artefatos, compilação estática reprodutível e gates de release da Fase F6**.

## Decisão

**Adotar compilação estática e puramente determinística em Go puro (`CGO_ENABLED=0`, `-trimpath`), bloqueio de vulnerabilidades no CI via `govulncheck`, geração compulsória de SBOM no padrão CycloneDX, publicação de manifestos de integridade SHA-256 acompanhados de assinatura digital `cosign` (ou fallback SLSA documentado), e isolamento absoluto de supply chain para gates/plugins.**

---

### 1. Política de Dependências e Toolchain

1. **Pinning Rigoroso de Versões (`go.mod` e `go.sum`):**
   - Todas as dependências diretas e indiretas são pinadas em versões exatas no `go.mod` e checksums criptográficos imutáveis no `go.sum`.
   - O toolchain do compilador é fixado no patch release exato (`go 1.27.0` / `toolchain go1.27.1`), garantindo consistência entre o CI e a compilação local de release.
2. **Proibição Compulsória de CGO (`CGO_ENABLED=0`):**
   - É terminantemente proibido o uso de `cgo`. Todo binário de produção e release DEVE ser compilado com `CGO_ENABLED=0`.
   - O projeto utiliza exclusivamente drivers em Go puro (ex.: `modernc.org/sqlite` em vez de bindings `mattn/go-sqlite3` que dependem de gcc/glibc).
   - O artefato final é um binário puramente estático, sem dependências dinâmicas de SO (`statically linked`).
3. **Varredura Contínua de Vulnerabilidades (`govulncheck`):**
   - O alvo `make vuln` executa `govulncheck ./...` pinado em versão declarada no pipeline (`GOVULNCHECK_VERSION = v1.8.0`).
   - O CI e o gate de release **falham fechados** (bloqueio imediato) se qualquer vulnerabilidade com caminho de chamada alcançável (*reachable call graph*) for identificada nas dependências diretas ou indiretas.
4. **Política para Adição de Novas Dependências:**
   A adição de qualquer novo módulo ao `go.mod` exige aprovação prévia com base nos seguintes critérios mandatórios:
   - **Necessidade Inegociável:** A funcionalidade não pode ser implementada internamente na biblioteca padrão com menos de 200 linhas de código limpo.
   - **Reputação e Manutenção:** Projeto ativamente mantido, com múltiplos contribuidores e ausência de histórico de negligência de segurança.
   - **Licença Conforme:** Licenças permissivas auditadas (MIT, Apache-2.0, BSD-3-Clause). Proibição categórica de licenças virais (GPL/AGPL) no núcleo do roteador.
   - **Zero CGO:** A dependência não pode exigir bindings nativos ou flags CGO.

---

### 2. Software Bill of Materials (SBOM) no Padrão CycloneDX

1. **Formato e Conteúdo:**
   - No processo de release, um SBOM é gerado compulsoriamente no formato padrão **CycloneDX JSON v1.5/v1.6** (via `syft` ou `cyclonedx-gomod`).
   - O SBOM cataloga de forma completa e estruturada:
     - Metadados do produto (nome, versão semver, commit SHA do Git, licença);
     - Toolchain exato do compilador Go e arquitetura de build;
     - Grafo completo de dependências diretas e indiretas com hashes criptográficos;
     - Componentes embutidos da GUI web (`web/package.json` e dependências NPM/pnpm).
2. **Nomeação e Publicação:**
   - O SBOM é gerado e arquivado como artefato oficial de release junto com os binários executáveis:
     - `heimdall-<versão>-cyclonedx.json`
     - `heimdall-<versão>-sbom.spdx.json` (opcional complementar).
   - O arquivo do SBOM é anexado aos GitHub Releases e disponibilizado nos canais oficiais de distribuição.

---

### 3. Integridade, Assinatura e Proveniência de Artefatos

1. **Manifesto de Checksums Criptográficos (SHA-256):**
   - Para cada build de release, o processo gera um arquivo canônico de somas de verificação:
     ```
     sha256sum dist/* > dist/checksums.txt
     ```
   - O arquivo `checksums.txt` contém os hashes SHA-256 de todos os binários compilados (`linux/amd64`, `linux/arm64`, etc.) e do respectivo SBOM.
2. **Assinatura Digital com Sigstore / `cosign`:**
   - **Modo Primário (Keyless via GitHub Actions OIDC):**
     - Em pipelines do GitHub Actions acionados por tags de release, os artefatos e o `checksums.txt` são assinados digitalmente utilizando **Sigstore `cosign`** com autenticação OIDC (OpenID Connect sem chave estática privada), registrando a transparência no log público Rekor:
       ```bash
       cosign sign-blob --output-signature checksums.txt.sig --output-certificate checksums.txt.pem dist/checksums.txt
       ```
   - **Instrução de Verificação pelo Usuário:**
     A documentação do usuário no README e manuais deve instruir a verificação com comando único:
     ```bash
     cosign verify-blob \
       --certificate checksums.txt.pem \
       --signature checksums.txt.sig \
       --certificate-identity "https://github.com/dandgabr/heimdall-core/.github/workflows/ci.yml@refs/tags/<versao>" \
       --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
       dist/checksums.txt
     sha256sum -c dist/checksums.txt
     ```
3. **Fallback Documentado e Registro de Dívida de Infraestrutura (D-SEC-09-01):**
   - Se a execução ocorrer em ambiente local, sem conectividade com a infraestrutura Sigstore/Fulcio/Rekor ou em runners de CI sem permissão OIDC configurada:
     - O release **recorre ao fallback obrigatório:** publicação estrita do `checksums.txt` acompanhado de atestação de proveniência GitHub SLSA Build Level 2/3 gerada pelo GitHub Artifact Attestations (`actions/attest-build-provenance`).
     - **Registro de Dívida:** A dependência de assinatura externa em ambientes offline é registrada em `docs/SECURITY-DEBT.md` como aceita, mantendo a verificação primária local por SHA-256.

---

### 4. Compilação Determinística e Reprodutibilidade Bit-a-Bit

Para assegurar que qualquer terceiro que compile a partir do mesmo commit obtenha exatamente os mesmos bytes e o mesmo hash SHA-256:

1. **Flags do Compilador:**
   - `-trimpath`: Remove prefixos de caminhos de arquivos absolutos locais do host nos stack traces e metadados DWARF.
   - `-buildvcs=false`: Evita injeção não determinística de metadados do repositório local ou timestamps de commit nos binários.
   - `-ldflags '-s -w -X .../internal/cli.Version=<versão>'`: Suprime tabelas de símbolos desnecessárias e debug info não determinística, injetando exclusivamente o identificador imutável da versão semver.
2. **Proibição de Timestamps de Build:**
   - É terminantemente proibido carimbar a data ou hora da compilação (`BUILD_DATE`, `time.Now()`) em variáveis globais do binário. Dois builds do mesmo commit devem produzir hashes rigorosamente idênticos independentemente do momento em que foram compilados.
3. **Matriz de Arquiteturas:**
   - Compilação cruzada oficial e padronizada para:
     - `linux/amd64`
     - `linux/arm64`
4. **Verificação de Reprodutibilidade Local:**
   O alvo `make dist-verify` (ou verificação de duas etapas) assegura:
   ```bash
   make dist VERSION=v1.0.0
   sha256sum dist/* > /tmp/sums1.txt
   make clean
   make dist VERSION=v1.0.0
   sha256sum dist/* > /tmp/sums2.txt
   diff -u /tmp/sums1.txt /tmp/sums2.txt
   ```
   A ausência de diferenças no `diff` comprova a reprodutibilidade estrita.

---

### 5. Governança do Ciclo de Release

1. **Versionamento Semântico Estrito (SemVer v2.0.0):**
   - Formato `vMAJOR.MINOR.PATCH` (ex.: `v1.0.0`).
   - Breaking changes no contrato público da API (`/v1/*` ou contratos de CLI) exigem incremento de `MAJOR`.
   - Adição de novos provedores, estratégias ou gates built-in incrementam `MINOR`.
   - Correções de bugs e vulnerabilidades de segurança incrementam `PATCH`.
2. **Gate de Release Inviolável (Checklist Obrigatório):**
   Nenhum release pode ser emitido sem que todos os seguintes gates estejam comprovadamente verdes:
   - `make vet`: zero alertas do compilador;
   - `make lint`: `staticcheck` 100% limpo segundo `staticcheck.conf`;
   - `make race`: zero data races em concorrência;
   - `make cover-check`: 100,0% de cobertura com zero blocos descobertos;
   - `make vuln`: `govulncheck` sem achados de vulnerabilidade;
   - Cross-compile `dist` sem warnings em amd64 e arm64.
3. **Changelog e Rastreabilidade:**
   - Todo release acompanha notas descritivas estruturadas (`CHANGELOG.md` ou GitHub Release Notes) categorizadas conforme Conventional Commits (`feat`, `fix`, `sec`, `perf`).
   - Vulnerabilidades mitigadas ou dívidas resolvidas são explicitamente referenciadas pelos seus IDs normativos (ex.: P1-6, BD-01).

---

### 6. Isolamento e Supply Chain de Gates e Plugins

1. **Reafirmação Normativa (v1):**
   - Conforme congelado na [ADR-003](decisions/adr-003-escopo-seguranca-v1.md) e na [ADR-SEC-03](sec-03-invariante-de-gates.md), a versão v1 do Heimdall-Core **NÃO aceita gates dinâmicos nem código nativo fornecido por terceiros**.
   - Todos os gates ativos em v1 são módulos nativos built-in, auditados, empacotados e compilados estaticamente dentro da base oficial de código (`internal/gates/`).
2. **Requisitos de Supply Chain para Evolução Futura (WASM pós-v1):**
   Quando o suporte a gates de terceiros for introduzido em versões futuras pós-v1:
   - Extensões externas serão permitidas única e exclusivamente sob sandbox WASM (`wazero`);
   - Módulos WASM deverão ser acompanhados de atestação criptográfica de integridade e proveniência (assinados via `cosign` em formato OCI image spec);
   - A runtime verificará a assinatura do módulo WASM antes de instanciar a sandbox.

---

### 7. Critérios de Aceite Verificáveis (Normativos para F6)

A aprovação formal e o encerramento da Fase F6 exigem a verificação direta dos seguintes pontos:

1. **`govulncheck` Totalmente Limpo:** A execução de `make vuln` (ou `govulncheck ./...`) não relata nenhuma vulnerabilidade conhecida em qualquer dependência direta ou indireta.
2. **Compilação Estática Verificada (`CGO_ENABLED=0`):** `file dist/heimdall-*` atesta `statically linked` em todos os artefatos compilados da matriz `linux/amd64` e `linux/arm64`.
3. **Reprodutibilidade Comprovada:** Duas compilações consecutivas de `make dist` a partir do mesmo commit geram arquivos idênticos com hashes SHA-256 exatamente coincidentes.
4. **Geração de SBOM CycloneDX Válido:** O artefato `dist/heimdall-<versão>-cyclonedx.json` é gerado, atende ao schema oficial CycloneDX e lista todos os módulos presentes no `go.mod`.
5. **Manifesto de Checksums (`checksums.txt`):** Disponível contendo os hashes SHA-256 de todos os binários e artefatos de release.
6. **Assinatura Cosign ou SLSA Provenance Válida:** O manifesto de checksums e/ou binários possuem assinatura verificável via `cosign` ou atestação de proveniência de build SLSA no GitHub Actions.
7. **Documentação de Verificação Pública:** O README contém a seção "Verificação de Integridade e Assinatura", demonstrando o comando exato para validação pelo operador.

## Consequências

- **Blindagem Contra Ataques de Supply Chain:** Elimina riscos de injeção de código malicioso no processo de compilação ou distribuição.
- **Auditoria Transparente:** Desenvolvedores e empresas podem inspecionar a árvore completa de dependências via CycloneDX SBOM.
- **Independência de Ambiente:** Binários rodam em qualquer distribuição Linux sem conflitos de `glibc` ou bibliotecas compartilhadas ausentes.
- **Rigor Operacional em Releases:** O processo de lançamento é completamente automatizado e à prova de regressão técnica ou de segurança.

## Alternativas Consideradas

- **Permitir CGO para aproveitar SQLite otimizado do sistema:** Rejeitada categoricamente. CGO compromete o cross-compile determinístico e reintroduz vulnerabilidades clássicas de estouro de memória nativa da libc. O driver em Go puro `modernc.org/sqlite` atende integralmente os requisitos de performance e segurança.
- **Geração de SBOM apenas em formato texto simples:** Rejeitada. A conformidade regulatória moderna (NIST SSDF, EO 14028, CISA) exige formatos estruturados e interoperáveis por máquina (CycloneDX / SPDX).
- **Assinatura com chave GPG pessoal de mantenedores:** Rejeitada como padrão primário. Chaves GPG privadas estáticas apresentam alto risco de comprometimento e extravio. A adoção de `cosign` keyless via OIDC com transparência Rekor representa o estado da arte em segurança de software.
