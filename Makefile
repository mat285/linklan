VERSION ?= v0.4.0
GIT_SHA ?= $(shell git log --pretty=format:'%H' -n 1 2> /dev/null | cut -c1-8)

.PHONY: release-all
release-all: release
	VERSION=${VERSION} go run cmd/update/main.go ${VERSION}

.PHONY: release
release: build push-files

.PHONY: create-release
create-release:
	gh release create ${VERSION} --title "${VERSION}" --notes "Release ${VERSION} - Build ${GIT_SHA}" --generate-notes

.PHONY: push-files
push-files:
	@echo "Pushing files to GitHub release..."
	gh release upload ${VERSION} build/linklandaemon_linux_amd64 build/linklandaemon_linux_arm64 build/linklandaemon_darwin_arm64 linklandaemon.service install.sh _config/example.yml --clobber

.PHONY: build
build:
	./build.sh

.PHONY: install
install:
	sh -c "$(curl -fsSL https://github.com/mat285/linklan/releases/download/${VERSION}/install.sh)"

.PHONY: install-local
install-local:
	./install.sh ${VERSION}

