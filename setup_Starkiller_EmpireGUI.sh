#!/bin/bash
## Install Starkiller on Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Tested on 23 Oct 2020
## Duration - Quick (5 minutes)
set -euo pipefail
IFS=$'\n\t'

mkdir -p $HOME/tools/starkiller && cd $HOME/tools/starkiller
wget https://github.com/BC-SECURITY/Starkiller/releases/download/v1.4.0/starkiller-1.4.0.AppImage
chmod +x starkiller-1.4.0.AppImage
sudo ln -s $HOME/tools/starkiller/starkiller-1.4.0.AppImage /usr/bin/starkiller

echo '[*] Booting up Starkiller; run in the future with: starkiller --no-sandbox'
echo '[*] Connect to team member running the Empire server on port 1337, e.g. 1.2.3.4:1337'
echo '[!!] Request server admin to create a user account for you!'
cd $HOME/tools/starkiller && ./starkiller-1.4.0.AppImage --no-sandbox
