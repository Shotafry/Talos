#!/usr/bin/env bash
# Compila Talos para Linux y Windows (amd64/arm64) sin CGO (binario estatico) y genera
# SHA256SUMS. Los binarios van a dist/ (gitignored); el SHA256SUMS se publica en la release
# y se registra en Argos (src/lib/binaries/). Windows lleva sufijo .exe.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
rm -f dist/talos-* dist/SHA256SUMS
# La version sale del tag git (fuente unica). Override con VERSION=... ./scripts/build.sh
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}"
LDFLAGS="-s -w -X github.com/Shotafry/talos/internal/cli.version=$VERSION"
echo "version: $VERSION"
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
