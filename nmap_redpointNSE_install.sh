# NOTE - keep this cheatsheet handy - https://github.com/gnebbia/nmap_tutorial/blob/master/sections/ics_scada.md
mkdir -p $HOME/tools/scada
git clone https://github.com/digitalbond/Redpoint $HOME/tools/scada/Redpoint
cp $HOME/tools/scada/Redpoint/*.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
