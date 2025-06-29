#!/bin/sh

set -e

VERSION=$1
if [ -z "$VERSION" ]; then
    VERSION=$(curl -sL https://api.github.com/repos/mat285/linklan/releases/latest | jq -r .name)
    echo "No version specified, using latest release: ${VERSION}"
fi

which kubectl >/dev/null 2>&1 || {
    echo "kubectl is not installed. Please install kubectl first."
    exit 1
}

OS=$(uname -s | dd conv=lcase 2>/dev/null)
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
fi

if [ "$ARCH" != "amd64" ] && [ "$ARCH" != "arm64" ]; then
    echo "Unsupported architecture: ${ARCH}"
    exit 1
fi

if [ "$OS" != "linux" ] && [ "$OS" != "darwin" ]; then
    echo "Unsupported OS: ${OS}"
    exit 1
fi

echo "Detected OS: ${OS}, Architecture: ${ARCH}"

sudo systemctl stop linklandaemon.service || true
sudo systemctl disable linklandaemon.service || true
echo "Installing LinkLan daemon version ${VERSION}..."

curl --fail-with-body -Lo linklandaemon https://github.com/mat285/linklan/releases/download/${VERSION}/linklandaemon_${OS}_${ARCH}
sudo mv linklandaemon /bin/linklandaemon
sudo chown root:root /bin/linklandaemon
sudo chmod a+x /bin/linklandaemon

curl --fail-with-body -Lo linklandaemon.service https://github.com/mat285/linklan/releases/download/${VERSION}/linklandaemon.service
sudo mv linklandaemon.service /etc/systemd/system/linklandaemon.service
sudo chmod 644 /etc/systemd/system/linklandaemon.service
sudo chown root:root /etc/systemd/system/linklandaemon.service

curl --fail-with-body -Lo linklandaemon https://github.com/mat285/linklan/releases/download/${VERSION}/example.yml
sudo mkdir -p /etc/linklandaemon
sudo mv linklandaemon /etc/linklandaemon/example.yml
sudo chown root:root /etc/linklandaemon/example.yml

sudo mkdir -p /etc/linklandaemon
sudo chown root:root /etc/linklandaemon

sudo systemctl daemon-reload
sudo systemctl enable linklandaemon.service
sudo systemctl start linklandaemon.service
echo "LinkLan daemon installed and started successfully."

