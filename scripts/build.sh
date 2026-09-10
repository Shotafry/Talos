#!/usr/bin/env bash
# Compila Talos para Linux y Windows (amd64/arm64) sin CGO (binario estatico) y genera
# SHA256SUMS. Los binarios van a dist/ (gitignored); el SHA256SUMS se publica en la release
# y se registra en Argos (src/lib/binaries/). Windows lleva sufijo .exe.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
rm -f dist/talos-* dist/SHA256SUMS
# La version la lleva el propio codigo (internal/cli.version) y aqui NO se inyecta nada salvo que
# se pida. Antes se sacaba de `git describe --tags`, que dentro del monorepo de Argos devuelve el
# tag de ARGOS: los binarios que Argos sirve se identificaban como "talos 0.42.2". El CI del repo
# publico si la inyecta, con el tag de Talos, que es el suyo. Override: VERSION=1.6.0 ./build.sh
VERSION="${VERSION:-}"
if [ -n "$VERSION" ]; then
  VERSION="${VERSION#v}"
  LDFLAGS="-s -w -X github.com/Shotafry/talos/internal/cli.version=$VERSION"
  echo "version: $VERSION (inyectada)"
else
  LDFLAGS="-s -w"
  echo "version: la del codigo (internal/cli/cli.go)"
fi
for tgt in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  os=${tgt%/*}
  arch=${tgt#*/}
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  echo "build $os/$arch"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -buildvcs=false -ldflags "$LDFLAGS" -o "dist/talos-$os-$arch$ext" .
done
( cd dist && sha256sum talos-* > SHA256SUMS )
echo "--- dist ---"
ls -la dist
echo "--- SHA256SUMS ---"
cat dist/SHA256SUMS
