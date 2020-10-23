#!/bin/bash
## Install Bloodhound & Sharphound Ingestors on Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Tested on 23 Oct 2020
## Duration - Quick (about 5 minutes)
set -euo pipefail
IFS=$'\n\t'

echo 'Adding Bloodhound file to ~/tools/BloodHound-linux-x64/'
wget https://github.com/BloodHoundAD/BloodHound/releases/download/3.0.5/BloodHound-linux-x64.zip -O $HOME/tools/bloodhound/BloodHound-linux-x64_v3.0.5.zip
cd $HOME/tools/ && unzip BloodHound-linux-x64_v3.0.5.zip && chmod +x BloodHound-linux-x64/Bloodhound

echo 'Now adding Sharphound ingestors at ~/tools/sharphound'
mkdir -p $HOME/tools/sharphound && cd $HOME/tools/sharphound
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Ingestors/SharpHound.exe
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Ingestors/SharpHound.ps1 

echo 'Booting up Bloodhound now. Log in with the Neo4j creds. Have fun now!'
echo 'To access afterwards, run: cd ~/tools/BloodHound-linux-x64 && ./BloodHound --no-sandbox'
cd $HOME/tools/BloodHound-linux-x64 && ./BloodHound --no-sandbox
