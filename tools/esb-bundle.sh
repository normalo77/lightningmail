#!/usr/bin/env bash
# Byte-identity gate for the comment sweep: bundling drops comments but keeps
# every string literal, so an old-vs-new bundle diff proves code is untouched.
# Usage: esb-bundle.sh <repo-root> <entry-rel-to-client/> <out.js> [extra esbuild flags]
set -euo pipefail
root=$1 entry=$2 out=$3; shift 3
esb=${ESBUILD:-<workspace>/node_modules/.bin/esbuild}
cd "$root/client"
# NODE_PATH fallback lets a pristine clone (no client/node_modules) bundle:
# derive the real modules dir from the esbuild package location.
nm=${ESB_NODE_MODULES:-$(cd "$(dirname "$(readlink -f "$esb")")/../.." && pwd)}
# esbuild prints "// <relpath>" input markers (location-dependent) and keeps
# comments inside class bodies, so comment edits would show up in the bundle.
# Strip comment-only lines: string literals live on code lines, gate stays hard.
NODE_PATH="$root/client/node_modules:$nm${NODE_PATH:+:$NODE_PATH}" \
  "$esb" "$entry" --bundle --format=esm "$@" \
  | sed -E -e '/^[[:space:]]*\/\//d' -e '/^[[:space:]]*\/\*.*\*\/[[:space:]]*$/d' \
        -e '/^[[:space:]]*\/\*$/d' -e '/^[[:space:]]*\*/d' >"$out"
