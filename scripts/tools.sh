#!/usr/bin/env bash
# Ensure the detection tooling is present: jq and chainsaw. Idempotent.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$ROOT/.tools"; mkdir -p "$TOOLS"
export PATH="$TOOLS:$PATH"
need(){ command -v "$1" >/dev/null 2>&1; }

if ! need jq || ! need curl; then
  if need apt-get; then sudo apt-get update -y && sudo apt-get install -y jq curl
  else echo "install jq and curl manually"; exit 1; fi
fi

# chainsaw: WithSecure static binary. Pin with CHAINSAW_VERSION, else latest.
# Asset pattern assumed: *x86_64-unknown-linux-gnu*.tar.gz
if ! need chainsaw; then
  echo "[*] fetching chainsaw into .tools"
  if [ -n "${CHAINSAW_VERSION:-}" ]; then
    api="https://api.github.com/repos/WithSecureLabs/chainsaw/releases/tags/${CHAINSAW_VERSION}"
  else
    api="https://api.github.com/repos/WithSecureLabs/chainsaw/releases/latest"
  fi
  url=$(curl -fsSL "$api" | jq -r '.assets[].browser_download_url' \
        | grep -i 'x86_64-unknown-linux-gnu' | grep -i '\.tar\.gz$' | head -1)
  [ -n "$url" ] || { echo "could not resolve chainsaw linux asset"; exit 1; }
  tmp=$(mktemp -d)
  curl -fsSL "$url" -o "$tmp/chainsaw.tgz"
  tar xzf "$tmp/chainsaw.tgz" -C "$tmp"
  bin=$(find "$tmp" -type f -name 'chainsaw*' ! -name '*.tar.gz' | head -1)
  install -m 0755 "$bin" "$TOOLS/chainsaw"
  rm -rf "$tmp"
fi
chainsaw --version >/dev/null 2>&1 || true
