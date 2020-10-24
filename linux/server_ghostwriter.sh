#!/bin/bash
## Install Auto Recon on Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Tested on 23 Oct 2020
## Requires: Docker & a cup of tea

sudo aptitude install -y openssl
wget https://github.com/GhostManager/Ghostwriter/archive/c9a5bbc14cba17ec8ebec8309280362e679b5bad.zip -O $HOME/tools/ghostwriter.zip
sudo mkdir /server
sudo unzip $HOME/tools/ghostwriter.zip -d /server && cd /server/Ghost*/
sudo chown -R $USER:$USER /server

## Next: Setup config files
## consider adding team number in .django options
mkdir .envs && cd .envs_template && cp -r .local .production ../.envs && cd ../
cp .envs/.local/.postgres .envs/.production/.postgres
sed -i 's|DJANGO_SECURE_SSL_REDIRECT=False|DJANGO_SECURE_SSL_REDIRECT=True|g' .envs/.production/.django

#change DJANGO_SECRET_KEY
#change DJANGO Allowed Hosts - own public IP
#change company info
read -p "Enter in a new DJANGO secret key:"  djangokey
read -p "Enter in the external IP address:"  externalip
read -p "Enter in company info:" companyinfo

# Nginx / SSL Fun
sed -i 's|# ssl on;|ssl on;|g' compose/production/nginx/nginx.conf
sed -i 's|resolver 8.8.8.8;|resolver 1.1.1.1;|g' compose/production/nginx/nginx.conf
cd ssl/
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -subj "/C=/ST=/L=/O=Ghostwriter/CN=ghostwriter.local" -keyout ghostwriter.key -out ghostwriter.crt
openssl dhparam -out dhparam.pem 2048

## Then: Install Ghostwriter
## WARNING: commands may fail due to network resolution issue; good luck if that happens.
sudo docker-compose -f production.yml run --rm django /seed_data; sudo docker-compose -f production.yml stop; sudo docker-compose -f production.yml rm -f; sudo docker-compose -f production.yml build; sudo docker-compose -f production.yml up -d
cd /server/Ghost*/
sudo docker-compose -f production.yml run --rm django /seed_data
sudo docker-compose -f production.yml run --rm django python manage.py createsuperuser
