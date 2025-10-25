#!/usr/bin/env bash
set -euo pipefail

# Tools from apt
sudo apt install -y \
    nmap masscan netcat-traditional curl wget git \
    python3 python3-pip python3-venv \
    seclists nikto sqlmap \
    enum4linux smbclient smbmap \
    hydra john hashcat \
    tmux vim jq rlwrap proxychains4 \
    responder bloodhound neo4j \
    unzip ruby-full dnsrecon \
    netexec \
    autorecon \
    theharvester \
    s3scanner \
    impacket-scripts

# evil-winrm
sudo gem install evil-winrm

# enum4linux-ng
if [ ! -d /opt/enum4linux-ng ]; then
    sudo git clone https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng
fi
sudo chmod +x /opt/enum4linux-ng/enum4linux-ng.py
sudo ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng

# kerbrute (AD)
cd $HOME/tools/
wget -q https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64
mv kerbrute_linux_amd64 kerbrute
chmod +x kerbrute
sudo ln -sf ~/tools/ad-attacks/kerbrute /usr/local/bin/kerbrute

# Ligolo-ng
cd $HOME/tools/

LIGOLO_PROXY=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep "browser_download_url.*proxy.*linux_amd64.tar.gz" | cut -d '"' -f 4)
LIGOLO_AGENT_LINUX=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep "browser_download_url.*agent.*linux_amd64.tar.gz" | cut -d '"' -f 4)
LIGOLO_AGENT_WIN=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep "browser_download_url.*agent.*windows_amd64.zip" | cut -d '"' -f 4)

wget -q "$LIGOLO_PROXY" -O ligolo-proxy.tar.gz
wget -q "$LIGOLO_AGENT_LINUX" -O ligolo-agent-linux.tar.gz
wget -q "$LIGOLO_AGENT_WIN" -O ligolo-agent-windows.zip

tar -xzf ligolo-proxy.tar.gz
tar -xzf ligolo-agent-linux.tar.gz
unzip -q ligolo-agent-windows.zip
chmod +x proxy agent 2>/dev/null
rm -f *.tar.gz *.zip

#Ligolo-ng setup
cd ~
sudo ip tuntap add user $(whoami) mode tun ligolo 2>/dev/null || true
sudo ip link set ligolo up 2>/dev/null || true


# Chisel
CHISEL_URL=$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | grep "browser_download_url.*linux_amd64.gz" | cut -d '"' -f 4)
wget -q "$CHISEL_URL" -O chisel.gz
gunzip chisel.gz
chmod +x chisel
