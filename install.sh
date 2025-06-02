#!/bin/sh

set -e

sudo curl --output linklandaemon https://github.com/mat285/linklan/releases/download/v0.1.0/linklandaemon_amd64
sudo mv linklandaemon /bin/linklandaemon
sudo chown root:root /bin/linklandaemon
sudo chmod a+x /bin/linklandaemon

sudo curl --output linklandaemon.service https://github.com/mat285/linklan/releases/download/v0.1.0/linklandaemon.service
sudo mv linklandaemon.service /etc/systemd/system/linklandaemon.service
sudo chmod 0755 /etc/systemd/system/linklandaemon.service
# sudo chmod 644 /etc/systemd/system/linklandaemon.service
# sudo chown root:root /etc/systemd/system/linklandaemon.service

sudo systemctl daemon-reload
sudo systemctl enable linklandaemon.service
sudo systemctl start linklandaemon.service
echo "LinkLan daemon installed and started successfully."

