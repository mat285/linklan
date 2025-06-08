#!/bin/sh

set -e

BUILD_DIR=build

rm -rf ${BUILD_DIR}/ || true

export GOOS=linux 
export GOARCH=amd64
go build -o ${BUILD_DIR}/linklandaemon_${GOOS}_${GOARCH} cmd/daemon/main.go
export GOOS=linux 
export GOARCH=arm64
go build -o ${BUILD_DIR}/linklandaemon_${GOOS}_${GOARCH} cmd/daemon/main.go
export GOOS=darwin
export GOARCH=arm64
go build -o ${BUILD_DIR}/linklandaemon_${GOOS}_${GOARCH} cmd/daemon/main.go
