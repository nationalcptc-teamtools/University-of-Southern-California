#!/bin/bash
## Linux setup on Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Tested on 23 Oct 2020
## Duration - Quick (5 minutes)
set -euo pipefail
IFS=$'\n\t'

#===# Common Tools
sudo apt update && sudo apt install -y aptitude
sudo aptitude install -y python3 python3-venv python3-pip flameshot curl wget git asciinema p7zip tmux terminator screen nmap
sudo curl -o /usr/local/bin/tldr https://raw.githubusercontent.com/raylee/tldr/master/tldr && sudo chmod +x /usr/local/bin/tldr

#===# Folder Setup
mkdir -p $HOME/cptc.west/{screenshots,recon,web,vulns,creds,notes,exfil,logs}
mkdir -p $HOME/cptc.west/logs/asciinema
mkdir -p $HOME/tools/
git clone https://github.com/trustedsec/ptf $HOME/tools/ptf

#===# Documentation Tools
wget -O - https://raw.githubusercontent.com/laurent22/joplin/master/Joplin_install_and_update.sh | bash
wget https://github.com/tjnull/TJ-JPT/raw/master/TJ-Pentest-Template-1.0.jex -O $HOME/cptc.west/notes/TJ-Pentest-Template-1.0.jex

#===# Bash Aliases
cp bash_aliases.txt $HOME/.bash_aliases

#===# Docker Setup
# If script complains about a keyserver host, uncomment the next few lines & run again.
sudo aptitude install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common
#sudo apt update && sudo apt-key adv --keyserver pool.sks-keyservers.net --recv-keys 7EA0A9C3F273FCD8
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
#sudo apt-key fingerprint 0EBFCD88
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update && sudo aptitude install -y docker-ce docker-ce-cli containerd.io docker-compose

echo "Adding user to docker group!"
sudo usermod -aG docker $USER

#===# Python Setup
# Special shout-out for pwal.ch!
# https://pwal.ch/posts/2019-11-10-sane-python-environment-2020-part-1-isolation/
echo 'Let us set up pyenv & pipx properly'
sudo aptitude install -y python3-pip python3-venv make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python-openssl git
curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash

echo 'export PATH="$HOME/.pyenv/bin:$PATH"
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"' >> ~/.bash_aliases

python3 -m pip install -U pip pipx && python3 -m pipx ensurepath
source ~/.bash_aliases
echo 'Done! Log out & log in once to ensure changes will take effect'

# Need to install Python 3.7 for AutoRecon & other tools? Do this:
#pyenv doctor
#pyenv install 3.7.9 && pyenv rehash && pyenv global 3.7.9
#python3 -m pip install -U pip pipx
