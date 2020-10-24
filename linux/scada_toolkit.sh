#!/bin/bash
## Install Auto Recon on Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Tested on 22 Oct 2020

set -euo pipefail
IFS=$'\n\t'

mkdir -p $HOME/tools/scada
git clone https://github.com/digitalbond/Redpoint $HOME/tools/scada/Redpoint
sudo cp $HOME/tools/scada/Redpoint/*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
