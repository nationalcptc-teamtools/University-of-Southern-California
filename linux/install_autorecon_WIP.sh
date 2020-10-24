#!/bin/bash
## Install Auto Recon on Ubuntu 18.04 LTS
## Powered by Hecuba's Hackers
## Not Tested
## Duration - Medium (about 10 minutes)

sudo apt install -y curl enum4linux gobuster nbtscan nikto nmap onesixtyone oscanner smbclient smbmap smtp-user-enum snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf

## NOTE: Ubuntu needs the following manually installed:
## enum4linux gobuster oscanner smbmap smtp-user-enum sipvicious tnscmd10g
## Of these 7 tools, PTF has all BUT tnscmd10g & a broken Gobuster installation & sipvicious doesn't install properly.

## Sanity check - where are these tools?
whereis enum4linux gobuster oscanner smbmap smtp-user-enum sipvicious tnscmd10g

echo 'Use PTF to isntall: enum4linux oscanner smbmap smtp-user-enum'
find $HOME/tools/ptf/modules/ -type f -print0 | xargs -0 sed -i 's|python3 -m pip install|pipx install|g'

## HOTFIX: update ALL config file with wget --no-check-certificate
git clone https://github.com/trustedsec/ptf $HOME/tools
find $HOME/tools/ptf/modules/ -type f -print0 | xargs -0 sed -i 's|wget http|wget --no-check-certificate http|g'

## gobuster has binaries ready to use
wget https://github.com/OJ/gobuster/releases/download/v3.1.0/gobuster-linux-amd64.7z -O $HOME/tools/gobuster-linux-amd64.7z
p7zip -d gobuster-linux-amd64.7z && sudo cp $HOME/tools/gobuster-linux-amd64/gobuster /usr/bin/gobuster && sudo chmod +x /usr/bin/gobuster

## tnscmd10g is a perl script for Oracle TNS listener for port 1521.
## Easy to install, just install enum4linux first to handle perl deps.
sudo wget https://gitlab.com/kalilinux/packages/tnscmd10g/-/raw/kali/master/tnscmd10g?inline=false -O /usr/bin/tnscmd10g && sudo chmod +x /usr/bin/tnscmd10g

pipx install git+https://github.com/Tib3rius/AutoRecon.git

## In place of seclists, these are the only wordlists used. Faster to download.
[ -d "/usr/share/seclists/" ] && echo "SecLists directory already exists!" || echo "[*]: SecLists directory not found; making one right now!" && sudo mkdir -p /usr/share/seclists/{Discovery/Web-Content,Discovery/SNMP,Passwords/Default-Credentials,Usernames}

sudo wget -q https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/common.txt -O /usr/share/seclists/Discovery/Web-Content/common.txt

sudo wget -q https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/big.txt -O /usr/share/seclists/Discovery/Web-Content/big.txt

sudo wget -q https://github.com/danielmiessler/SecLists/raw/master/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -O /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt

sudo wget -q https://github.com/danielmiessler/SecLists/raw/master/Passwords/darkweb2017-top100.txt -O /usr/share/seclists/Passwords/darkweb2017-top100.txt

sudo wget -q https://github.com/danielmiessler/SecLists/raw/master/Passwords/Default-Credentials/oracle-betterdefaultpasslist.txt -O /usr/share/seclists/Passwords/Default-Credentials/oracle-betterdefaultpasslist.txt

sudo wget -q https://github.com/danielmiessler/SecLists/raw/master/Usernames/top-usernames-shortlist.txt -O /usr/share/seclists/Usernames/top-usernames-shortlist.txt

## ISSUES AND HOTFIXES
#> autorecon & UDP | always do sudo autorecon

#> gobuster -l option not supported in v3.1.0 | apply hotfix after installing autorecon
sed -i 's|-e -k -l -s|-e -k -s|g' $HOME/.local/pipx/venvs/autorecon/lib/python3.7/site-packages/autorecon/config/service-scans-default.toml
