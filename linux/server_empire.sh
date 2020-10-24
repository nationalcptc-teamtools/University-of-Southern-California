#!/bin/bash
## Install C2 Empire & Starkiller on Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Tested on 23 Oct 2020
## Duration - Medium (10 minutes)
set -euo pipefail
IFS=$'\n\t'

echo 'Must have Docker already installed beforehand!' && sleep 3
mkdir -p $HOME/tools/starkiller && cd $HOME/tools/starkiller
wget https://github.com/BC-SECURITY/Starkiller/releases/download/v1.4.0/starkiller-1.4.0.AppImage
chmod +x starkiller-1.4.0.AppImage
sudo ln -s $HOME/tools/starkiller/starkiller-1.4.0.AppImage /usr/bin/starkiller

# With persistent storage at $HOME/shares/docker.empire
mkdir -p $HOME/shares/docker.empire
docker pull bcsecurity/empire:latest
docker create -v $HOME/shares/docker.empire --name data bcsecurity/empire:latest
echo '[*] Running Empire container in background. To view if running, run: docker ps'
echo '[>] docker run -d -it --network host --volumes-from data bcsecurity/empire:latest /bin/bash -c "./empire --rest"'
docker run -d -it --network host --volumes-from data bcsecurity/empire:latest /bin/bash -c "./empire --rest"

echo ''

echo '[*] Booting up Starkiller; run in the future with: starkiller --no-sandbox'
echo '[*] Default URL should be 127.0.0.1:1337'
echo '[!!] Change the default password when you sign in! empireadmin:password123'
cd $HOME/tools/starkiller && ./starkiller-1.4.0.AppImage --no-sandbox
