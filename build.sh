#!/bin/sh

set -e

BUILD_DIR=build

rm -rf ${BUILD_DIR}/ || true

GOOS=linux GOARCH=amd64 go build -o ${BUILD_DIR}/linklandaemon_${GOOS}_${GOARCH} cmd/daemon/main.go
GOOS=linux GOARCH=arm64 go build -o ${BUILD_DIR}/linklandaemon_${GOOS}_${GOARCH} cmd/daemon/main.go
GOOS=darwin GOARCH=arm64 go build -o ${BUILD_DIR}/linklandaemon_${GOOS}_${GOARCH} cmd/daemon/main.go
