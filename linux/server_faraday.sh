#!/bin/bash
## Install Faraday IDE Server & Faraday CLI on Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Tested on 19 Oct 2020
## Duration - Quick (about 5 minutes)
set -euo pipefail
IFS=$'\n\t'

sudo apt update && sudo apt install -y curl wget aptitude
sudo aptitude remove -y faraday faraday-client
mkdir -p $HOME/tools/faraday-server && cd $HOME/tools/faraday-server
wget https://github.com/infobyte/faraday/releases/download/v3.12/faraday-server_amd64.deb
sudo aptitude install -y postgresql
sudo systemctl enable postgresql
sudo dpkg -i faraday-server_amd64.deb
sudo systemctl start postgresql
sudo usermod -aG faraday $USER
sudo faraday-manage initdb | tee creds_faraday.txt
echo "^^ It's dangerous to go alone! Here, take these creds ^^"
sudo systemctl stop faraday-server.service
sudo sed -i 's|localhost|0.0.0.0|g' /home/faraday/.faraday/config/server.ini
sudo systemctl start faraday-server && sudo systemctl enable faraday-server
echo 'Cool! Wait for a few seconds for the server to be ready.'

echo "Meanwhile, let's install Faraday-CLI since the GUI app conflicts with the server"
sudo aptitude install -y python3-pip python3-venv && python3 -m pip install --user pipx && python3 -m pipx ensurepath
cd $HOME/tools/ && git clone https://github.com/infobyte/faraday-cli && cd faraday-cli
$HOME/.local/bin/pipx install git+https://github.com/infobyte/faraday-cli.git
echo ". $(pwd)/faraday-cli-autocomplete_bash.sh" >> ~/.bash_aliases && source ~/.bashrc
echo 'The Faraday server should be ready! Check it out at http://127.0.0.1:5985/'
echo "To have pipx added to path, the terminal will now be reloaded. Type in user's pw when prompted & hit enter."
su - $USER
