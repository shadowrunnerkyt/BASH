#!/bin/bash
# Author: Chris Cook
# initDate: 08/29/19
# Version: 0.1
# Desc: check for/or install Amazon SSM, DeepSec, Zabbix

########## Formatting ##########
RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color


########## Ubuntu ##########
# Get release version and save as Int in $releaseInt
# printf -v releaseInt '%d' $(lsb_release -a 2>/dev/null | egrep 'Release' | awk -F' ' '{print $2}') 2>/dev/null
releaseInt=$(lsb_release -a 2>/dev/null | egrep 'Release' | awk -F' ' '{print $2}' | cut -b -2) 2>/dev/null
echo -e "\nLocal hostname:${GREEN} $(hostnamectl | grep -i static | awk -F' ' '{print $3}')${NC}"

########## SSM ##########
# https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-manual-agent-install.html#agent-install-ubuntu-deb
# On Ubuntu Server 18.04, use Snaps only. Don't install deb packages.

# is SSM running
ps aux | grep -v $USER | grep amazon-ssm-agent &> /dev/null # -v $USER ignores the user's grep process
if [[ $? -eq 0 ]]; then
  echo -e "SSM is ${GREEN}installed and running${NC}"
else
  echo -e "SSM is ${RED}not running, you need to install it${NC}"
fi


########## DeepSec ##########
# is DS installed
ps aux | grep -v $USER | grep ds_agent &> /dev/null
if [[ $? == 0 ]]; then
  echo -e "DeepSec is ${GREEN}installed and running${NC}"
else
  echo -e "DeepSec is ${ORANGE}not running${NC}"
fi


########## Zabbix ##########
zConf='/etc/zabbix/zabbix_agentd.conf'
zabbixVer=''
zabbixInt=''

function zabbixVersion {
  echo -e "${GREEN}Checking Zabbix version..."
  zabbixVer=$(zabbix_agentd --print | grep agent.version | awk -F'|' '{print $2}' | sed 's/]//' 2> /dev/null)
  [[ -z $zabbixVer ]] && zabbixVer=$(zabbix_agentd -V | egrep '(zabbix|daemon)' | awk -F' ' '{print $4}' | sed 's/v//')
}

function zabbixRestart {
  echo -e "${GREEN}Attempting to restart Zabbix service...${NC}"
  if [[ $releaseInt == 14 ]]; then
    sudo service zabbix-agent restart &> /dev/null
    wait
  else
    [[ -L /lib/systemd/system/zabbix-agent.service ]] && sudo systemctl unmask zabbix-agent
    sudo systemctl enable zabbix-agent &> /dev/null
    sudo systemctl restart zabbix-agent &> /dev/null
    wait
  fi
}

function zabbixConfigure {
  echo -e "${GREEN}Checking Zabbix configuration...${NC}"
  egrep '^Server.*|^Host.*|^Include.*' $zConf
}

if [[ -f $zConf ]]; then
  zabbixConfigure
  zabbixVersion
  # is zabbix running
  ps aux | grep -v $USER | grep -i zabbix &> /dev/null # -v $USER ignores the user's grep process
  if [[ $? == 0 ]]; then
    echo -e "zabbix_agentd${PURPLE} ${zabbixVer} ${NC}is ${GREEN}installed and running${NC}"
  else
    echo -e "zabbix_agentd ${zabbixVer} is ${ORANGE}not running${NC}"
    zabbixRestart
    ps aux | grep -v $USER | grep -i zabbix &> /dev/null # -v $USER ignores the user's grep process
    if [[ $? == 0 ]]; then
      zabbixVersion
      echo -e "zabbix_agentd${PURPLE} ${zabbixVer} ${NC}is ${GREEN}installed and running${NC}"
    else
      echo -e "Zabbix Agent is ${RED}installed but cannot be started${NC}"
    fi
  fi
else
    echo -e "Zabbix Agent is ${RED}not installed${NC}"
fi
