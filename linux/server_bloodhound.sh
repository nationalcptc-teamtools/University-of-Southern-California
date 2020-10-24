#!/bin/bash
## Install Neo4j container for Bloodhound data on Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Tested on 23 Oct 2020
## Duration - Quick (about 5 minutes)
set -euo pipefail
IFS=$'\n\t'

echo 'Creating folder at ~/shares/bloodhound.data/ ; add Bloodhound data files there!'
mkdir -p $HOME/shares/docker.bloodhound/
wget https://github.com/BloodHoundAD/BloodHound/releases/download/3.0.5/BloodHound-linux-x64.zip -O $HOME/tools/bloodhound/BloodHound-linux-x64_v3.0.5.zip
cd $HOME/tools/ && unzip BloodHound-linux-x64_v3.0.5.zip && chmod +x BloodHound-linux-x64/Bloodhound

echo 'Now adding Sharphound ingestors at ~/tools/sharphound'
mkdir -p $HOME/tools/sharphound && cd $HOME/tools/sharphound
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Ingestors/SharpHound.exe
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Ingestors/SharpHound.ps1 

sudo docker pull metalmandalore/houndcrate:v2
echo 'Running Neo4j container in the background, view with: docker ps'
sudo docker run -d --rm -it --publish=0.0.0.0:7474:7474 --publish=0.0.0.0:7687:7687 -v $HOME/shares/docker.bloodhound:/data --shm-size=2gb --ulimit nofile=40000 metalmandalore/houndcrate:v2 /bin/bash -c "./neo4j console"

echo 'Access Neo4j service in browser at http://127.0.0.1:7474 & change the password (neo4j:neo4j)'
echo 'Booting up Bloodhound now. Log in with new neo4j creds. Have fun now!'
echo 'To access afterwards, run: cd ~/tools/BloodHound-linux-x64 && ./BloodHound --no-sandbox'
cd $HOME/tools/BloodHound-linux-x64 && ./BloodHound --no-sandbox
