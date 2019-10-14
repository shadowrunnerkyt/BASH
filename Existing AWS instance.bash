#!/bin/bash
# Author: Chris Cook
# initDate: 08/26/19
# Version: 0.3
# Desc: Check installed software versions



########## Ubuntu ##########
# Get release
lsb_release -a 2>/dev/null | egrep 'Release' | awk -F' ' '{print $2}' # print release to console
printf -v releaseInt '%d' $(lsb_release -a 2>/dev/null | egrep 'Release' | awk -F' ' '{print $2}') 2>/dev/null # save release as Int in $releaseInt

# is wget installed?
dpkg -l | grep wget
# If wget isn't currently installed (remove it when done)
sudo apt install wget # install it
sudo apt remove wget # remove it



########## SSM ##########
# https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-manual-agent-install.html#agent-install-ubuntu-deb
# On Ubuntu Server 18.04, use Snaps only. Don't install deb packages.

# is SSM installed
dpkg -l | grep amazon-ssm-agent
sudo snap list amazon-ssm-agent # 18+

# is SSM running
ps aux | grep -v $USER | grep amazon-ssm-agent  # -v $USER ignores the user's grep process

# check snap status
sudo snap services amazon-ssm-agent # 18+

# check systemctl status
sudo systemctl status amazon-ssm-agent # Ubuntu Server 16.04+
sudo status amazon-ssm-agent # Ubuntu Server 14.04

# start service if amazon-ssm-agent is stopped, inactive, or disabled
sudo systemctl enable amazon-ssm-agent # Ubuntu Server 16.04+
sudo start amazon-ssm-agent # Ubuntu Server 14.04



########## DeepSec ##########
# is DS installed
dpkg -l | grep ds-agent

# is DS running
ps aux | grep -v $USER | grep ds_agent # -v $USER ignores the user's grep process

# install DS
vim ds.sh # paste script
sudo chmod +x ds.sh # make executable
sudo ./ds.sh # execute
sudo rm ./ds.sh # remove script when done



########## Zabbix ##########
# is it installed
dpkg -l | grep zabbix

#is it available
apt-cache policy zabbix-agent

# is it running
ps aux | grep -v $USER | grep -i zabbix # -v $USER ignores the user's grep process
initctl list | grep zabbix-agent

# display version
zabbix_agentd -V # lots of garbage
zabbix_agentd -V | grep -i zabbix | awk -F' ' '{print $4}' # '3.4.15'
zabbix_agentd -V | egrep '(zabbix|daemon)' | awk -F' ' '{print $4}' | sed 's/v//' # '3.4.15' or 'v2.4.7'

zabbix_agentd --print | grep agent.version # agent.version                                 [s|3.4.15]
zabbix_agentd --print | grep agent.version | awk -F'|' '{print $2}' | sed 's/]//' # '3.4.15'

# conf location: /etc/zabbix/zabbix_agentd.conf
# show conf server IP
egrep '^Server=|^ServerActive=|Hostname=.+|HostMetadataItem=|^Include=' /etc/zabbix/zabbix_agentd.conf

# modify conf if these values don't match Alex's zabbix_agentd.conf
sudo sed -i -E 's/(127.0.0.1|172.24.18.224)/10.25.250.38/' /etc/zabbix/zabbix_agentd.conf
# sudo sed -i -E 's/^Hostname=(Zabbix.*|ip.*)/# &/' /etc/zabbix/zabbix_agentd.conf
sudo sed -i 's/^Hostname=.*/# &/' /etc/zabbix/zabbix_agentd.conf # Alex says always comment this line
sudo sed -i 's/^# HostMetadataItem=/HostMetadataItem=system.uname/' /etc/zabbix/zabbix_agentd.conf
sudo sed -i 's/^Include=.*/Include=\/etc\/zabbix\/zabbix_agentd\.d\/\*.conf/' /etc/zabbix/zabbix_agentd.conf

# restart zabbix service
sudo service zabbix-agent restart

# check systemctl status
systemctl status zabbix-agent # Ubuntu 16+
status zabbix-agent # Ubuntu 14

# stop zabbix agent
sudo systemctl stop zabbix-agent # ubuntu 16+
sudo service zabbix-agent stop # ubuntu 14

# Uninstall zabbix-agent and its dependencies
sudo apt remove --auto-remove zabbix-agent -y
sudo mv /etc/zabbix/zabbix_agentd.conf /etc/zabbix/zabbix_agentd.conf.bak

# if a full clean is absolutely necessary
sudo apt purge zabbix-agent -y
sudo apt purge zabbix-release -y
sudo rm -r /etc/zabbix

# install zabbix-agent
# For Ubuntu 18.04 (bionic), run the following commands:
sudo wget https://repo.zabbix.com/zabbix/4.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_4.2-1+bionic_all.deb
sudo dpkg -i zabbix-release_4.2-1+bionic_all.deb
sudo rm zabbix-release_*.deb
sudo apt update

# For Ubuntu 16.04, substitute 'bionic' with 'xenial' in the commands.
wget https://repo.zabbix.com/zabbix/4.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_4.2-1+xenial_all.deb
sudo dpkg -i zabbix-release_4.2-1+xenial_all.deb
sudo rm zabbix-release_*.deb
sudo apt update

# For Ubuntu 14.04, substitute 'bionic' with 'trusty' in the commands.
wget https://repo.zabbix.com/zabbix/4.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_4.2-1+trusty_all.deb
sudo dpkg -i zabbix-release_4.2-1+trusty_all.deb
sudo rm zabbix-release_*.deb
sudo apt update

# To upgrade Zabbix agent minor version please run:
sudo apt install --only-upgrade 'zabbix-agent.*'

# Agent installation
# To install the agent, run:
sudo apt install --fix-missing zabbix-agent

# If zabbix-agent is masked
sudo systemctl unmask zabbix-agent # ubuntu 16+

# To start the agent, run:
sudo systemctl enable zabbix-agent # ubuntu 16+
sudo systemctl start zabbix-agent # ubuntu 16+
sudo service zabbix-agent start # ubuntu 14
