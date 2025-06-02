#!/bin/sh

set -e

sudo curl --output /usr/local/bin/linklandaemon https://github.com/mat285/linklan/releases/download/v0.1.0/linklandaemon_amd64

sudo chmod +x /usr/local/bin/linklandaemon
sudo curl --output /etc/systemd/system/linklandaemon.service https://github.com/mat285/linklan/releases/download/v0.1.0/linklandaemon.service

sudo systemctl enable linklandaemon.service
sudo systemctl start linklandaemon.service
echo "LinkLan daemon installed and started successfully."

