#!/bin/sh

set -e
VERSION=$1
if [ -z "$VERSION" ]; then
    VERSION="v0.1.2"
fi
CMD="$(curl -fsSL https://github.com/mat285/linklan/releases/download/${VERSION}/install.sh)"
