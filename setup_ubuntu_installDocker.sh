#!/bin/bash
## Install Docker on Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Tested on 19 Oct 2020
## Duration - Quick (about 5 minutes)
set -euo pipefail
IFS=$'\n\t'

sudo apt update && sudo apt install -y aptitude
sudo aptitude install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common

# If script fails to connect to keyserver host, wait a bit & run the script again.
sudo apt update && sudo apt-key adv --keyserver pool.sks-keyservers.net --recv-keys 7EA0A9C3F273FCD8
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo apt-key fingerprint 0EBFCD88
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update && sudo aptitude install -y docker-ce docker-ce-cli containerd.io docker-compose

echo "Adding user to docker group! Be sure to log out & log back in."
sudo usermod -aG docker $USER
echo "Great! Now run this command to confirm docker group was added: id"
