#!/bin/bash
## Install Faraday GUI Client on Kali 2020.03 & Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Tested on 20 Oct 2020
## Duration - Quick (about 5 minutes)
set -euo pipefail
IFS=$'\n\t'

# If using Kali / Kali repos, use this option.
sudo apt update && sudo apt install -y aptitude
sudo apt purge -y faraday
sudo aptitude install -y faraday-client
echo 'Done! Now run this command & connect it to the server: faraday-client'

# If using Ubuntu / Debian without Kali repos, uncomment these lines instead.
# sudo apt update && sudo apt install -y aptitude
# sudo aptitude install -y curl zsh
# mkdir $HOME/tools/faraday-gui && cd $HOME/tools/faraday-gui
# wget https://storage.googleapis.com/faraday-community/faraday-client_amd64.deb -O faraday-client_v3.11.1_amd64.deb 
# echo 'If dpkg reports an error, run this afterwards: sudo apt update; sudo aptitude install -f -y'
# echo 'You may also wish to install the Python dependencies if that too does not work: https://github.com/infobyte/faraday-client/blob/master/requirements.txt'
# sudo dpkg -i faraday-client_v3.11.1_amd64.deb 
