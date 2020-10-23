# Built for Ubuntu

## works with this!
wget https://github.com/GhostManager/Ghostwriter/archive/c9a5bbc14cba17ec8ebec8309280362e679b5bad.zip

## First: Install Docker
sudo apt-get update && sudo apt install -y aptitude git
sudo aptitude install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo apt-key fingerprint 0EBFCD88
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
sudo apt-get update
sudo aptitude install -y docker-ce docker-ce-cli containerd.io docker-compose

# adding docker group to user (can check with id)
sudo usermod -aG docker $USER && su - $USER

## Next: Setup config files
sudo git clone https://github.com/GhostManager/Ghostwriter /ghostwriter && cd /ghostwriter
sudo chown -R $USER:$USER /ghostwriter
mkdir .envs && cd .envs_template && cp -r .local .production ../.envs && cd ../
## consider configuring slack
## consider adding team number in .django options

## Then: Install Ghostwriter
## WARNING: commands may fail due to network resolution issue; didn't work on a VPN.
## ALSO: test with modding local.yml file 8000 to 127.0.0.1:8000
sudo docker-compose -f local.yml up -d
sudo docker-compose -f local.yml run --rm django /seed_data

# expected to break the first time; rebuild again.
sudo docker-compose -f local.yml stop; sudo docker-compose -f local.yml rm -f; sudo docker-compose -f local.yml build; sudo docker-compose -f local.yml up -d

# sudo docker-compose -f local.yml run --rm django python manage.py migrate
sudo docker-compose -f local.yml run --rm django /seed_data
sudo docker-compose -f local.yml run --rm django python manage.py createsuperuser
## if it breaks, remove docker container (stop first), then reinstall again...


## visit qhere? http://127.0.0.1:8000/admin

## PRODUCTION
## >> also: SSL cert setup (yaamaro!)
## >> use free cert from letsencrypt, please (nightmare here to do pem file)
sudo docker-compose -f production.yml run --rm django /seed_data; sudo docker-compose -f production.yml stop; sudo docker-compose -f production.yml rm -f; sudo docker-compose -f production.yml build; sudo docker-compose -f production.yml up -d
sudo docker-compose -f production.yml run --rm django /seed_data
sudo docker-compose -f production.yml run --rm django python manage.py createsuperuser

## stop, rebuild, restart
docker-compose -f local.yml stop; docker-compose -f local.yml rm -f; docker-compose -f local.yml build; docker-compose -f local.yml up -d

////
docker-compose -f local.yml up -d,docker-compose -f local.yml run --rm django /seed_data,docker-compose -f local.yml run --rm django python manage.py createsuperuser
