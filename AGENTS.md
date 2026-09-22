# Heimdall-Core — instruções para agentes

## Regra de saída por fase (obrigatória)

Leia `docs/GOVERNANCE.md`. Em resumo:

- **Nenhuma fase avança com pendência ou decisão aberta.** Cada achado (P0–P3) ou é
  resolvido, ou é **explicitamente aceito como dívida pelo dono do projeto**, com registro
  e fase-gatilho (`docs/SECURITY-DEBT.md` para segurança).
- A fase fecha apenas com validação independente e os gates técnicos verdes: `go build`,
  `go vet`, `go test -race`, `make lint`, `make cover-check` (100,0% race+atomic, 0 blocos)
  e cross-compile estático amd64+arm64.
- **Ao final de cada fase, fazer o commit** do que foi desenvolvido; working tree limpo.

## Contexto do projeto

- Roteador local multi-provedor (LLM) em **Go**, binário único, API OpenAI-compatible, com
  gates plugáveis (memória, economia de token, segurança) e combos.
- Planos, ADRs e relatórios vivem no **ai-memory** (workspace `router`, project `router`).
  Leia `plans/implementation-plan-v2.md` e as `decisions/` antes de trabalhar.
- ADRs executáveis ficam em `docs/adr/` (arquitetura: `NNNN-*`; segurança: `sec-NN-*`).

## Convenções

- Go puro, `CGO_ENABLED=0`; sem cgo. Dependências mínimas e pinadas.
- Erros sempre por `code` i18n (ADR-0002: `DomainError` com `Scope`/`Retryable`/`RetryAfter`).
- Segredos nunca em log; o redator central é obrigatório. Corpo de requisição nunca logado.
- Cobertura exata 100,0% em `-race -covermode=atomic`; nenhum teste sem asserção.
