# ADR-SEC-01 — Custódia da chave mestra e esquema de cifra/envelope de credenciais

- **Status:** Aceita
- **Data:** 2026-09-22
- **Fase / bloqueia:** F1 (Auth e Providers)

## Contexto

A página `decisions/adr-sec-01-custodia-chave.md` do ai-memory decidiu **onde**
guardar a chave (KEK selada ao TPM2 via `systemd-creds --user`; keyring na
sessão gráfica; arquivo `0600` + passphrase Argon2id como fallback universal;
recovery passphrase), mas **não** decidiu o **formato do dado cifrado** nem a
**semântica de falha**. Sem essa decisão, a F1 grava a primeira credencial e o
formato fica congelado por acidente: mudar depois vira migração de dados com
risco de perda.

A F1 é a fase que materializa o `SecretStore` e o `CredentialStore`, então o
formato e o comportamento de falha precisam estar fixados **antes** de a fase
começar.

### Verificação de ambiente

Verificado nesta máquina: **systemd 259** (compilado com `+TPM2`), `/dev/tpm0` e
`/dev/tpmrm0` presentes, `systemd-analyze has-tpm2` → `yes`, `systemd-creds` com
`--user` e `--with-key=tpm2` disponíveis. TPM2 é viável como camada primária;
onde não houver, valem o keyring e o arquivo `0600` + passphrase.

### Falha a não herdar

O `enc:v1:IV:CT:TAG` do **OmniRoute** é o precedente mais próximo. Ele acerta o
formato versionado, mas comete **duas violações de fail-closed** que este ADR
proíbe explicitamente (ver Comparativo obrigatório).

## Decisão

**Formato versionado `enc:v1:IV:CT:TAG` com AES-256-GCM, envelope encryption
(DEK/KEK) e KDF Argon2id, operando sempre fail-closed.**

### 1. Formato do dado cifrado

```
enc:v1:<IV>:<CT>:<TAG>
```

- **Cifra:** **AES-256-GCM**.
- **IV:** **12 bytes** aleatórios, gerados por operação, nunca reutilizados.
- **TAG:** **16 bytes**, tamanho **pinado** (NIST SP 800-38D §5.2.1.1).
- **Versão:** o prefixo `enc:v1:` é o espaço de manobra para migração futura;
  o parser rejeita prefixo desconhecido em vez de tentar adivinhar.

### 2. Envelope encryption

- Um **DEK por registro** cifra o campo;
- a **KEK** cifra o DEK.
- Versionar no prefixo permite **rotação incremental**: re-cifrar apenas os DEKs
  sob a nova KEK, sem reescrever o conteúdo dos registros.

### 3. KDF

- **Argon2id** (`golang.org/x/crypto/argon2`), com **salt de 16 bytes aleatório
  por instalação** e **32 bytes de saída**.
- **NUNCA** usar valor de `env` cru como chave. Um segredo em variável de
  ambiente aparece em `/proc/<pid>/environ`, em `systemctl show` e em logs de
  orquestração; derivar com Argon2id garante que o material em repouso não seja
  o valor que o operador digitou.

### 4. Semântica de falha (fail-closed)

- **Ausência de KEK recusa iniciar**, com o code i18n `config.secret_missing`.
- **Erro de cifra aborta a operação** — nunca devolve o dado em claro.
- **Jamais persistir plaintext**, em nenhum caminho, nem como fallback.

### 5. Custódia (resumo do ADR-SEC-01 do ai-memory)

Ordem de disponibilidade da KEK:

1. **`systemd --user` headless (primário):** KEK selada ao TPM2 via
   `systemd-creds --user --with-key=tpm2`, entregue ao serviço por
   `LoadCredentialEncrypted=` e lida de `$CREDENTIALS_DIRECTORY`.
2. **Sessão gráfica:** keyring (`secret-tool`) como conveniência.
3. **Fallback universal:** arquivo `0600` + passphrase Argon2id (salt de 16 B por
   instalação, 32 B de saída).
4. **`env`:** somente override explícito, com aviso e depreciação.

Mais uma **recovery passphrase** que embrulha a mesma KEK: a perda do TPM
(troca de placa, reset) **não** perde os dados. Permissões do cofre verificadas
no boot: `0600` (arquivo) / `0700` (diretório); modo mais permissivo → recusa
(fail-closed, implementado em `internal/store/store.go:ensurePermissions`).

### 6. Interface

```go
// SecretStore é a única porta para material secreto. Seal cifra; Open decifra.
// Ambas devolvem erro em vez de plaintext quando a KEK falta ou a cifra falha.
type SecretStore interface {
    Seal(ctx context.Context, plaintext []byte) ([]byte, error) // -> "enc:v1:..."
    Open(ctx context.Context, ciphertext []byte) ([]byte, error)
}
```

O **`CredentialStore`** persiste apenas o resultado de `Seal` no campo secreto
do registro e resolve o valor via `Open` **dentro do `Executor`** — o segredo em
claro nunca cruza a fronteira do executor, nunca é logado (o redator central é a
rede de segurança, não a política) e nunca entra no caminho de serialização.

## Comparativo obrigatório — OmniRoute

| Aspecto | OmniRoute | Decisão Heimdall-Core |
| --- | --- | --- |
| Formato | `enc:v1:IV:CT:TAG` | **Mesmo formato** (versionado, IV/TAG explícitos) |
| (a) Chave ausente | `passthrough` grava **plaintext** | **Recusa iniciar** (`config.secret_missing`) |
| (b) Erro na cifra | `encrypt()` devolve **plaintext** | **Aborta a operação**; nunca devolve claro |
| Envelope | DEK = KEK (implícito) | **DEK/KEK explícito**, rotação incremental |
| KDF | valor de env direto | **Argon2id** com salt por instalação |

As duas falhas do OmniRoute — **(a)** gravar plaintext quando a chave falta e
**(b)** devolver plaintext em erro — são exatamente o que **não** será herdado:
ambas violam fail-closed e transformam um problema de disponibilidade em
vazamento de credencial. Um erro de cifra no Heimdall-Core **falha a operação**;
nunca há caminho em que o plaintext chegue ao disco ou ao chamador.

## Consequências

### Critérios de aceite (verificáveis)

1. **Round-trip:** `Open(Seal(x)) == x` para x arbitrário, inclusive vazio e
   binário.
2. **Tag truncada rejeitada:** alterar ou truncar a TAG faz `Open` **falhar**,
   nunca devolver plaintext.
3. **DB copiado sem a KEK é ilegível:** um `heimdall.db` copiado sem o material
   da KEK não expõe nenhuma credencial.
4. **Dois cofres com a mesma passphrase geram chaves distintas:** o salt é por
   instalação, então a mesma passphrase em duas instalações não produz a mesma
   KEK (impede que decorar a passphrase comprometa cofres distintos de uma vez).
5. **Rotação preserva leitura:** após re-cifrar os DEKs sob nova KEK, registros
   antigos continuam legíveis pelo prefixo de versão.

### Impacto no código

- O cofre (F1) passa a ter o formato e a semântica de falha fixados; a migração
  `0001_init.sql` cresce com a tabela de credenciais apenas como colunas, não
  como formato de cifra.
- A checagem de permissão de `internal/store/store.go` (0600/0700, fail-closed)
  é a mesma política aplicada ao arquivo de KEK.

### Dívidas registradas

- **Rotação automática de KEK** (agendada/por evento) — o formato já a suporta,
  a automação não entra no v1.
- **Migração de salt** — trocar o salt de instalação exige re-derivar e re-cifrar
  tudo; o procedimento fica pendente.

## Alternativas consideradas

- **(a) Chave derivada direto do valor de `env`.** **Rejeitada:** o valor cru
  fica exposto em `/proc/<pid>/environ`, `systemctl show` e logs de orquestração,
  e não tem separação entre o que o operador fornece e o material que cifra.
  Argon2id com salt por instalação elimina essa equivalência.
- **(b) Sem envelope (DEK = KEK).** **Aceita como simplificação inicial, mas
  descartada como decisão:** usar a mesma chave para cifrar registro e para ser
  embrulhada elimina a rotação incremental (trocar a KEK exigiria re-cifrar todo
  o conteúdo, não só os DEKs) e acopla o custo de troca ao volume de dados. O
  envelope custa um nível a mais de cifra por registro e compra rotação barata e
  a possibilidade futura de custódia diferente por DEK (ex.: uma instalação
  multi-usuário). O v1 adota o envelope por ser o formato que não exige migração
  depois — decisão coerente com o motivo desta ADR existir.
- **Cifra alternativa (ChaCha20-Poly1305).** Descartada: AES-256-GCM tem
  aceleração de hardware difundida em amd64/arm64 e o NIST SP 800-38D fixa os
  tamanhos de IV/TAG que o formato usa.
