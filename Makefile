.PHONY: build
build:
	GOOS=linux GOARCH=amd64 go build -o build/linklandaemon_amd64 cmd/daemon/main.go
	GOOS=darwin GOARCH=arm64 go build -o build/linklandaemon_arm64 cmd/daemon/main.go