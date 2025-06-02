#!/bin/sh

set -e

VERSION=$1
if [ -z "$VERSION" ]; then
    VERSION="v0.1.0"
fi

which kubectl >/dev/null 2>&1 || {
    echo "kubectl is not installed. Please install kubectl first."
    exit 1
}

sudo systemctl stop linklandaemon.service || true
sudo systemctl disable linklandaemon.service || true
echo "Installing LinkLan daemon version $VERSION..."

curl -Lo linklandaemon https://github.com/mat285/linklan/releases/download/v0.1.0/linklandaemon_amd64
sudo mv linklandaemon /bin/linklandaemon
sudo chown root:root /bin/linklandaemon
sudo chmod a+x /bin/linklandaemon

curl -Lo linklandaemon.service https://github.com/mat285/linklan/releases/download/v0.1.0/linklandaemon.service
sudo mv linklandaemon.service /etc/systemd/system/linklandaemon.service
sudo chmod 644 /etc/systemd/system/linklandaemon.service
sudo chown root:root /etc/systemd/system/linklandaemon.service

sudo systemctl daemon-reload
sudo systemctl enable linklandaemon.service
sudo systemctl start linklandaemon.service
echo "LinkLan daemon installed and started successfully."

