# Governança de Fases

Regra de saída do projeto Heimdall-Core. Todo agente e colaborador segue esta regra.

## A regra

**Nenhuma fase avança enquanto houver pendência ou decisão aberta da fase atual.**
Ao final de cada fase, o trabalho desenvolvido é **commitado**.

Uma fase só é declarada concluída — e a seguinte só começa — quando todos os pontos
abaixo são verdadeiros:

1. **Zero achados abertos (P0, P1, P2, P3 ou qualquer Pn) da fase.** Cada achado é
   **resolvido**, ou **explicitamente aceito como dívida pelo dono do projeto**, com
   registro e fase-gatilho. Aceitar como dívida não é o padrão: é uma decisão consciente,
   registrada e aprovada (segurança em `docs/SECURITY-DEBT.md`, demais no plano).
2. **Zero decisões abertas.** Toda decisão pendente (ADR, escolha de design, endpoint a
   confirmar) está fechada ou formalmente aceita como dívida.
3. **Validação independente concluída** — QA e, quando aplicável, arquitetura/código e
   segurança. O autor da implementação não valida o próprio trabalho.
4. **Gates técnicos verdes:** `go build`, `go vet`, `go test -race`, `make lint`,
   `make cover-check` (100,0% em `-race -covermode=atomic`, 0 blocos descobertos) e
   cross-compile estático amd64 + arm64.
5. **Commit feito ao final da fase**, com mensagem descritiva, e working tree limpo.

## Por quê

A regra existe para impedir que dívida técnica e decisões adiadas se acumulem em silêncio
e contaminem as fases seguintes. Um achado carregado "para depois" vira retrabalho caro na
fase em que ele finalmente aparece.

## Aplicação

- Ao encerrar uma fase, o responsável lista **todas** as pendências abertas e submete cada
  uma ao dono do projeto para decisão: **resolver agora** ou **aceitar como dívida**.
- Só então a próxima fase começa, e só então o commit de fechamento é feito.
