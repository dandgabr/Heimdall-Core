# Compatibilidade OpenAI — subset suportado (F2.4)

Este documento fixa o **subset explícito** da API OpenAI que o Heimdall-Core
suporta na F2, e o que deliberadamente **não** suporta. Ele é normativo: um
campo classificado como *não suportado* não deve ser implementado sem uma
decisão registrada (ADR), e um campo *parcial* deve ser tratado exatamente como
descrito.

- **Versão-alvo da API:** OpenAI Chat Completions, estável em `/v1` (dialeto
  `chat.completions`, o mesmo da API pública de 2024+). Não há pin de data de
  release: o formato canônico interno é o JSON OpenAI-shaped descrito em
  `internal/contracts/translator.go`, e este documento é o contrato do que esse
  JSON pode conter.
- **Pivô interno:** o formato canônico do núcleo é o OpenAI
  (`contracts.CanonicalFormat == "openai"`). O tradutor da família OpenAI é a
  **identidade** (`contracts.IsIdentity`): o pipeline o pula e os bytes passam
  inalterados.

Legenda: **S** = suportado · **P** = parcial (o que exatamente) · **N** = não
suportado (justificativa).

## Endpoints

| Endpoint | Estado | Observação |
| --- | --- | --- |
| `POST /v1/chat/completions` (non-stream) | **S** | Caminho principal. |
| `POST /v1/chat/completions` (`stream: true`) | **S** | SSE; ver invariantes de streaming em `internal/contracts/executor.go`. |
| `GET /v1/models` | **S** | Catálogo derivado do registry de providers (`internal/api/mgmt`/`openai`). |
| `POST /v1/completions` (legacy) | **N** | Dialeto legado de completion; o pivô é chat. Se houver demanda, é uma tradução adicional, não um caminho novo. |
| `POST /v1/embeddings` | **N (F2)** | Gate de memória usa `Embedder` por HTTP (F4). Expor `/v1/embeddings` ao cliente é decisão de fase posterior; não entra na F2. |
| `POST /v1/responses` | **N (F2)** | API mais nova (stateful, tools nativas). Fora do pivô chat-completions; exigiria um segundo modelo canônico. |
| `POST /v1/audio/*`, `/v1/images/*` | **N** | Áudio/imagem como *entrada* multimodal é distinto de endpoints de mídia; ver multimodal abaixo. |

## Campos do request (`/v1/chat/completions`)

| Campo | Estado | Comportamento |
| --- | --- | --- |
| `model` | **S** | Obrigatório para roteamento. Espelhado em `WireRequest.Model`. |
| `messages` | **S** | Roles `system`, `developer`, `user`, `assistant`, `tool`. `system`/`developer` viram `system` (Anthropic) ou `systemInstruction` (Gemini). |
| `tools` | **S** | Formato OpenAI `{type:"function",function:{name,description,parameters}}`. Traduzido para `tools`/`input_schema` (Anthropic) e `functionDeclarations` (Gemini). |
| `tool_choice` | **P** | `"auto"`/`"required"`/`"none"` e `{type:"function",function:{name}}` mapeados. `"none"` no Anthropic é **omitido** (não há equivalente explícito). `parallel_tool_calls` não é honrado pelo Anthropic/Gemini. |
| `parallel_tool_calls` | **P** | Aceito no pivô; **não** propagado a Anthropic/Gemini (o controle de paralelismo é do provedor). No caminho OpenAI (identity) é preservado. |
| `max_tokens` | **S** | Anthropic exige o campo: ausente → default de `4096`. Gemini → `generationConfig.maxOutputTokens`. |
| `max_completion_tokens` | **P** | Usado como *fallback* de `max_tokens` quando este falta. Não é enviado sob o nome original a Anthropic/Gemini. |
| `temperature` | **S** | → `temperature` (Anthropic) / `generationConfig.temperature` (Gemini). |
| `top_p` | **S** | → `top_p` / `generationConfig.topP`. |
| `stop` | **S** | String ou array (`stringOrSlice`). → `stop_sequences` / `generationConfig.stopSequences`. |
| `stream` | **S** | Seleciona `DoStream`; `stream_options.include_usage` honrado. |
| `stream_options.include_usage` | **P** | Honrado no pivô/caminho OpenAI. Nos tradutores cross-format a flag em si **não** é propagada, porque Anthropic (`message_delta.usage`) e Gemini (`usageMetadata`) já emitem usage no frame de término — o tradutor a projeta no chunk final. |
| `response_format` | **P** | `{"type":"text"}` e `{"type":"json_object"}` são aceitos no pivô mas **não traduzidos** para Anthropic/Gemini (sem campo equivalente genérico); `json_schema` estruturado é **N** (exigiria tool/function shim). No caminho OpenAI é preservado por bytes. |
| `n` | **N** | Múltiplas escolhas não são modeladas: os tradutores emitem `choices[0]`. Um `n>1` não é honrado. |
| `seed` | **N** | Sem campo equivalente em Anthropic/Gemini; não propagado. |
| `logprobs` / `top_logprobs` | **N** | Descartados nos tradutores cross-format (documentado e testado). |
| `logit_bias` | **N** | Idem. |
| `frequency_penalty` / `presence_penalty` | **P** | Decodificados do pivô, **não** traduzidos para Anthropic/Gemini (sem equivalente). |
| `user` | **N** | Não propagado (campo de correlação do cliente OpenAI). |
| Campos desconhecidos (`x_*`) | **P** | O caminho **OpenAI (identity)** preserva por bytes. Os tradutores cross-format **descartam** qualquer campo que não modelam, porque o provedor não tem slot — documentado e testado. |

## Multimodal

| Entrada | Estado | Observação |
| --- | --- | --- |
| Texto | **S** | Blocos `{type:"text"}`. |
| Imagem por `image_url` (URL) | **S** | Anthropic `source.type="url"`; Gemini `fileData.fileUri`. |
| Imagem por `image_url` (data URL base64) | **S** | Parseada para Anthropic `source.type="base64"` / Gemini `inlineData`. Data URL malformada cai para a forma URL (nunca é descartada em silêncio). |
| Áudio / vídeo como entrada | **N (F2)** | Sem tradução; fora do subset da F2. |
| Saída de imagem/áudio | **N** | O pivô é texto + tool calls. |

## Streaming — o que o tradutor preserva

O tradutor é **puro e por frame**: ele nunca acumula estado entre frames.

| Aspecto | Garantia |
| --- | --- |
| Tool calls partidas entre chunks | **Preservadas como fragmentos.** Anthropic `input_json_delta.partial_json` é encaminhado como `tool_calls[].function.arguments` (string), sem re-serializar. O cliente remonta como faria com OpenAI. |
| `content_block_start` de tool_use | Vira um delta com `id`/`name` vazios de argumentos; o nome e o id chegam antes dos fragmentos. |
| Usage no chunk final | Anthropic `message_delta.usage` e Gemini `usageMetadata` viram `usage` no chunk de término. |
| Frames sem conteúdo | `ping`, `message_start` sem delta, frames vazios → `nil` (nada a emitir), nunca um chunk vazio. |
| `finish_reason` | Mapeado de `stop_reason` (Anthropic) e `finishReason` (Gemini) para o vocabulário OpenAI. |
| Erro de payload | `translate.failed`; em resposta de provedor, `ScopeProvider` (ADR-0002). |

## Não-objetivos explícitos

- **Sem `n>1`, `logprobs`, `seed`, `logit_bias`** nos tradutores cross-format.
- **Sem `/v1/responses` nem `/v1/completions`** na F2.
- **Sem reescrita de chunks de tool call**: o tradutor faz projeção, não
  reassembly. Reassembly é responsabilidade do cliente (igual ao OpenAI).

## Como adicionar um campo

1. Se é um campo do pivô que os provedores **têm**: modelá-lo em
   `canonicalRequest`/resposta, traduzir em cada tradutor e adicionar um golden
   em `internal/translators/testdata/`.
2. Se **não** há slot no provedor: classificar como **N** aqui, com a
   justificativa, e adicionar um caso a
   `TestUnmappedCanonicalFieldsAreDropped` para fixar o descarte.
3. Se é **parcial**: descrever exatamente o comportamento nesta tabela e cobrir
   cada ramo com teste.
