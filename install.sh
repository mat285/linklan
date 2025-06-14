#!/bin/sh

set -e

VERSION=$1
if [ -z "$VERSION" ]; then
    VERSION="v0.2.0"
fi

which kubectl >/dev/null 2>&1 || {
    echo "kubectl is not installed. Please install kubectl first."
    exit 1
}

SUDO_OPTS=$(echo $SUDO_OPTS)

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

sudo $SUDO_OPTS systemctl stop linklandaemon.service || true
sudo $SUDO_OPTS systemctl disable linklandaemon.service || true
echo "Installing LinkLan daemon version ${VERSION}..."

curl --fail-with-body -Lo linklandaemon https://github.com/mat285/linklan/releases/download/${VERSION}/linklandaemon_${OS}_${ARCH}
sudo $SUDO_OPTS mv linklandaemon /bin/linklandaemon
sudo $SUDO_OPTS chown root:root /bin/linklandaemon
sudo $SUDO_OPTS chmod a+x /bin/linklandaemon

curl --fail-with-body -Lo linklandaemon.service https://github.com/mat285/linklan/releases/download/${VERSION}/linklandaemon.service
sudo $SUDO_OPTS mv linklandaemon.service /etc/systemd/system/linklandaemon.service
sudo $SUDO_OPTS chmod 644 /etc/systemd/system/linklandaemon.service
sudo $SUDO_OPTS chown root:root /etc/systemd/system/linklandaemon.service

sudo $SUDO_OPTS systemctl daemon-reload
sudo $SUDO_OPTS systemctl enable linklandaemon.service
sudo $SUDO_OPTS systemctl start linklandaemon.service
echo "LinkLan daemon installed and started successfully."

