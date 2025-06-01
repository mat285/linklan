VERSION ?= v0.1
GIT_SHA ?= $(shell git log --pretty=format:'%H' -n 1 2> /dev/null | cut -c1-8)

.PHONY: release
release: build push-files

.PHONY: push-files
push-files:
	@echo "Pushing files to GitHub release..."
	gh release upload ${VERSION} build/linklandaemon_amd64 build/linklandaemon_arm64 --clobber

.PHONY: build
build:
	GOOS=linux GOARCH=amd64 go build -o build/linklandaemon_amd64 cmd/daemon/main.go
	GOOS=darwin GOARCH=arm64 go build -o build/linklandaemon_arm64 cmd/daemon/main.go