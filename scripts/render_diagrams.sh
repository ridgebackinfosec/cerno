#!/usr/bin/env bash
#
# Render every Mermaid diagram in docs/diagrams/ to a light/dark PNG pair in
# docs/images/diagrams/.
#
# The Markdown embeds the PNGs through a <picture> element keyed on
# prefers-color-scheme, so each diagram needs both renders to look native in
# GitHub's light and dark themes.
#
# Requires: node/npx (mermaid-cli is fetched on demand) and a Chromium build.
# We point Puppeteer at the system Chromium so its bundled ~150 MB download is
# never needed.
#
# Usage:
#   ./scripts/render_diagrams.sh            # render everything
#   ./scripts/render_diagrams.sh 01 03      # render only matching sources
#
set -euo pipefail

MERMAID_VERSION="@mermaid-js/mermaid-cli@12"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/docs/diagrams"
OUT_DIR="$REPO_ROOT/docs/images/diagrams"

# Scale factor: 2 against a large --size keeps text crisp on HiDPI displays and
# in slides. mermaid-cli fits each diagram inside SIZE, so a wide diagram needs a
# large SIZE to stay legible when a reader clicks through to the full image.
SCALE="${DIAGRAM_SCALE:-2}"
SIZE="${DIAGRAM_SIZE:-1800}"
# GitHub's light and dark canvas colours, so the PNG edges blend into the page.
LIGHT_BG="${DIAGRAM_LIGHT_BG:-white}"
DARK_BG="${DIAGRAM_DARK_BG:-#0d1117}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v npx >/dev/null 2>&1 || die "npx not found; install Node.js to render diagrams"

# Locate a Chromium/Chrome binary unless the caller already chose one.
if [[ -z "${PUPPETEER_EXECUTABLE_PATH:-}" ]]; then
    for candidate in chromium chromium-browser google-chrome google-chrome-stable; do
        if path="$(command -v "$candidate" 2>/dev/null)"; then
            PUPPETEER_EXECUTABLE_PATH="$path"
            break
        fi
    done
fi
[[ -n "${PUPPETEER_EXECUTABLE_PATH:-}" ]] || die \
    "no Chromium found. Install chromium, or set PUPPETEER_EXECUTABLE_PATH to a Chrome/Chromium binary."
export PUPPETEER_EXECUTABLE_PATH
# Don't let Puppeteer fetch its own browser if mermaid-cli is installed fresh.
export PUPPETEER_SKIP_DOWNLOAD=true

mkdir -p "$OUT_DIR"

# Headless Chromium needs --no-sandbox in most container/VM setups, and
# --disable-dev-shm-usage avoids crashes where /dev/shm is small.
PUPPETEER_CONFIG="$(mktemp -t cerno-puppeteer-XXXXXX.json)"
trap 'rm -f "$PUPPETEER_CONFIG"' EXIT
cat > "$PUPPETEER_CONFIG" <<'JSON'
{
  "args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
}
JSON

# Collect the sources to render: all of them, or only those matching an argument.
sources=()
for src in "$SRC_DIR"/*.mmd; do
    [[ -e "$src" ]] || die "no .mmd sources found in $SRC_DIR"
    if (( $# == 0 )); then
        sources+=("$src")
    else
        for pattern in "$@"; do
            if [[ "$(basename "$src")" == *"$pattern"* ]]; then
                sources+=("$src")
                break
            fi
        done
    fi
done
(( ${#sources[@]} > 0 )) || die "no sources matched: $*"

render() {
    local src="$1" theme="$2" background="$3" out="$4"
    printf '  %-12s -> %s\n' "$theme" "${out#"$REPO_ROOT"/}"
    npx --yes -p "$MERMAID_VERSION" mmdc \
        --input "$src" \
        --output "$out" \
        --theme "$theme" \
        --backgroundColor "$background" \
        --scale "$SCALE" \
        --size "$SIZE" \
        --puppeteerConfigFile "$PUPPETEER_CONFIG" \
        --quiet
}

printf 'Chromium: %s\n' "$PUPPETEER_EXECUTABLE_PATH"
printf 'Rendering %d diagram(s) at size %s, scale %s\n\n' "${#sources[@]}" "$SIZE" "$SCALE"

for src in "${sources[@]}"; do
    stem="$(basename "$src" .mmd)"
    printf '%s\n' "$stem"
    render "$src" default "$LIGHT_BG" "$OUT_DIR/$stem-light.png"
    render "$src" dark    "$DARK_BG"  "$OUT_DIR/$stem-dark.png"
done

printf '\nDone. %d PNG(s) in %s\n' \
    "$(find "$OUT_DIR" -name '*.png' | wc -l)" "${OUT_DIR#"$REPO_ROOT"/}"
