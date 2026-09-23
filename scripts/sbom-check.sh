#!/bin/sh
# sbom-check.sh — valida o SBOM CycloneDX do release (F6, ADR-SEC-09 §7.4).
#
# Verifica, sem depender de rede nem de ferramenta externa além de `jq` e `go`:
#   1. o arquivo é JSON bem-formado;
#   2. é um documento CycloneDX (`bomFormat`) com `specVersion` e componentes;
#   3. todo módulo exigido em go.mod aparece no SBOM (por `name` ou `purl`).
#
# Uso: scripts/sbom-check.sh <caminho-do-sbom.json>
set -eu

sbom="${1:?uso: scripts/sbom-check.sh <sbom.json>}"

if [ ! -f "$sbom" ]; then
	echo "sbom-check: arquivo não encontrado: $sbom" >&2
	exit 1
fi

# 1. JSON válido.
if ! jq -e . "$sbom" >/dev/null 2>&1; then
	echo "sbom-check: JSON inválido: $sbom" >&2
	exit 1
fi

# 2. Estrutura CycloneDX.
bom_format=$(jq -r '.bomFormat // empty' "$sbom")
spec=$(jq -r '.specVersion // empty' "$sbom")
count=$(jq -r '(.components // []) | length' "$sbom")

if [ "$bom_format" != "CycloneDX" ]; then
	echo "sbom-check: bomFormat esperado 'CycloneDX', veio '$bom_format'" >&2
	exit 1
fi
if [ -z "$spec" ]; then
	echo "sbom-check: specVersion ausente" >&2
	exit 1
fi
if [ "$count" -le 0 ]; then
	echo "sbom-check: nenhum componente no SBOM" >&2
	exit 1
fi

# 3. Cobertura dos `require` do go.mod.
missing=0
requires=$(go mod edit -json | jq -r '.Require[]?.Path')
if [ -z "$requires" ]; then
	echo "sbom-check: não foi possível ler os requires de go.mod" >&2
	exit 1
fi

for mod in $requires; do
	if ! jq -e --arg m "$mod" '
		[ .components[]
		  | select(
		      (.name // "") == $m
		      or ((.purl // "") | startswith("pkg:golang/" + $m + "@"))
		      or ((.purl // "") | startswith("pkg:golang/" + $m + "?"))
		      or ((.purl // "") == ("pkg:golang/" + $m))
		    )
		] | length > 0
	' "$sbom" >/dev/null; then
		echo "sbom-check: módulo ausente no SBOM: $mod" >&2
		missing=1
	fi
done

if [ "$missing" -ne 0 ]; then
	exit 1
fi

echo "sbom-check: OK — CycloneDX $spec, $count componentes, todos os requires do go.mod presentes"
