#!/bin/sh

set -e

sudo curl --output /bin/linklandaemon https://github.com/mat285/linklan/releases/download/v0.1.0/linklandaemon_amd64

sudo chmod a+x /bin/linklandaemon
sudo curl --output /etc/systemd/system/linklandaemon.service https://github.com/mat285/linklan/releases/download/v0.1.0/linklandaemon.service
sudo chmod a+x /etc/systemd/system/linklandaemon.service

sudo systemctl daemon-reload
sudo systemctl enable linklandaemon.service
sudo systemctl start linklandaemon.service
echo "LinkLan daemon installed and started successfully."

