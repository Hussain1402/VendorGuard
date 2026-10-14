#!/bin/sh
# Build VendorGuard for Windows, Linux and macOS. Requires Go 1.22 or newer.
set -e
cd "$(dirname "$0")"
go test ./...
mkdir -p bin
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/VendorGuard.exe .
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/vendorguard-linux .
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o bin/vendorguard-macos .
echo "Built:"; ls -l bin
