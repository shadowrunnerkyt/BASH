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

# Is wget installed?
function getWget {
  # If wget isn't currently installed (remove it when done)
  dpkg -l | grep wget | grep ii &> /dev/null
  if [[ $? != 0 ]]; then
    echo -e "${ORANGE}wget is not installed, it will be removed when done${NC}"
    echo -e "${GREEN}Installing wget...${NC}"
    export wgetInstalled=0
    sudo apt-get install wget &> /dev/null # install it
  else
    echo -e "${GREEN}wget is currently installed${NC}"
    export wgetInstalled=1
  fi
}

function removeWget {
  if [[ $wgetInstalled == 0 ]]; then
    echo -e "${ORANGE}wget was not installed, but we installed it, so removing it...${NC}"
    sudo apt-get remove wget -y &> /dev/null
  fi
}

########## Ubuntu ##########
# Get release version and save as Int in $releaseInt
# printf -v releaseInt '%d' $(lsb_release -a 2>/dev/null | egrep 'Release' | awk -F' ' '{print $2}') 2>/dev/null
releaseInt=$(lsb_release -a 2>/dev/null | egrep 'Release' | awk -F' ' '{print $2}' | cut -b -2)
echo -e "\nLocal hostname:${GREEN} $(hostnamectl | grep -i static | awk -F' ' '{print $3}')${NC}"


########## SSM ##########
# https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-manual-agent-install.html#agent-install-ubuntu-deb
# On Ubuntu Server 18.04, use Snaps only. Don't install deb packages.
# install SSM
function ssmInstall {
  if [[ $releaseInt -gt 14 ]]; then
    sudo snap install amazon-ssm-agent --classic -y
    if [[ $? -gt 0 ]]; then
      sudo apt-get install amazon-ssm-agent -y
    fi
  else
    getWget
    echo -e "${YELLOW}Getting AWS SSM Agent...${NC}"
    sudo wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb &> /dev/null
    wait
    echo -e "${YELLOW}Installing ${NC}amazon-ssm-agent.deb"
    sudo dpkg -i amazon-ssm-agent.deb &> /dev/null
    wait
  fi
}

function ssmCleanup {
  echo -e "${YELLOW}Cleaning up...${NC}"
  sudo rm amazon-ssm-agent.deb
  removeWget
}

function ssmRestart {
  echo -e "${YELLOW}Attempting to restart Amazon SSM Agent...${NC}"
  if [[ $releaseInt -gt 14 ]]; then
    sudo snap services amazon-ssm-agent &> /dev/null
    wait
    ssmStatus
    [[ $? -ne 0 ]] && echo -e "${RED}There's a problem with SSM, you'll have to check it manually${NC}"; return 1
  else
    sudo service amazon-ssm-agent restart &> /dev/null
    wait
    ssmStatus
    [[ $? -ne 0 ]] && echo -e "${RED}There's a problem with SSM, you'll have to check it manually${NC}"; return 1
  fi
}

# is SSM running
function ssmStatus {
  ps aux | grep -v $USER | grep amazon-ssm-agent &> /dev/null # -v $USER ignores the user's grep process
  if [[ $? -eq 0 ]]; then
    echo -e "SSM is ${GREEN}installed and running${NC}"
    return 0
  else
    echo -e "SSM is ${ORANGE}not running${NC}"
    return 1
  fi
}

ssmStatus
if [[ $? -eq 1 ]]; then
  echo -e "${YELLOW}Attempting to restart Amazon SSM Agent...${NC}"
  ssmRestart &> /dev/null
  ssmStatus
  if [[ $? -eq 1 ]]; then
    ssmInstall
    ssmCleanup
    ssmStatus
    [[ $? -eq 1 ]] && ssmRestart
  fi
fi

########## DeepSec ##########
function AgentDeploymentScript {
  ACTIVATIONURL='dsm://agents.deepsecurity.trendmicro.com:443/'
  MANAGERURL='https://app.deepsecurity.trendmicro.com:443'
  CURLOPTIONS='--silent --tlsv1.2'
  linuxPlatform='';
  isRPM='';

  # if [[ $(/usr/bin/id -u) -ne 0 ]]; then
  #   echo You are not running as the root user.  Please try again with root privileges.;
  #   logger -t You are not running as the root user.  Please try again with root privileges.;
  #   exit 1;
  # fi;

  if type curl >/dev/null 2>&1; then
    CURLOUT=$(eval curl $MANAGERURL/software/deploymentscript/platform/linuxdetectscriptv1/ -o /tmp/PlatformDetection $CURLOPTIONS;)
    err=$?
    if [[ $err -eq 60 ]]; then
      echo "TLS certificate validation for the agent package download has failed. Please check that your Deep Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center."
      logger -t TLS certificate validation for the agent package download has failed. Please check that your Deep Security Manager TLS certificate is signed by a trusted root certificate authority. For more information, search for \"deployment scripts\" in the Deep Security Help Center.
      exit 2;
    fi

    if [ -s /tmp/PlatformDetection ]; then
      . /tmp/PlatformDetection
      platform_detect

      if [[ -z "${linuxPlatform}" ]] || [[ -z "${isRPM}" ]]; then
        echo Unsupported platform is detected
        logger -t Unsupported platform is detected
        false
      else
        echo Downloading agent package...
        if [[ $isRPM == 1 ]]; then package='agent.rpm'
      else package='agent.deb'
      fi
      curl $MANAGERURL/software/agent/$linuxPlatform -o /tmp/$package $CURLOPTIONS

      echo Installing agent package...
      rc=1
      if [[ $isRPM == 1 && -s /tmp/agent.rpm ]]; then
        sudo rpm -ihv /tmp/agent.rpm
        rc=$?
      elif [[ -s /tmp/agent.deb ]]; then
        sudo dpkg -i /tmp/agent.deb &> /dev/null
        rc=$?
      else
        echo Failed to download the agent package. Please make sure the package is imported in the Deep Security Manager
        logger -t Failed to download the agent package. Please make sure the package is imported in the Deep Security Manager
        false
      fi
      if [[ ${rc} == 0 ]]; then
        echo Install the agent package successfully
        sleep 15
        sudo /opt/ds_agent/dsa_control -r
        sudo /opt/ds_agent/dsa_control -a $ACTIVATIONURL "tenantID:AB8B1757-94B3-D41E-FEEC-4BDC8A19A5C6" "token:F6B8E19D-779B-167E-0C59-15DACD7EDD02" "policyid:1"
      else
        echo Failed to install the agent package
        logger -t Failed to install the agent package
        false
      fi
    fi
  else
    echo "Failed to download the agent installation support script."
    logger -t Failed to download the Deep Security Agent installation support script
    false
  fi
else
  echo "Please install CURL before running this script."
  logger -t Please install CURL before running this script
  false
fi
}
# is DS installed
ps aux | grep -v $USER | grep ds_agent &> /dev/null
if [[ $? == 0 ]]; then
  echo -e "DeepSec is ${GREEN}installed and running${NC}"
else
  echo -e "DeepSec is ${ORANGE}not running: ${YELLOW}starting installation${NC}"
  AgentDeploymentScript
  wait
  ps aux | grep -v $USER | grep ds_agent &> /dev/null
  if [[ $? == 0 ]]; then
    echo -e "DeepSec is ${GREEN}installed and running${NC}"
  else
    echo -e "${RED}There was a problem installing DeepSec${NC}"
    exit 1
  fi
fi


########## Zabbix ##########
zConf='/etc/zabbix/zabbix_agentd.conf'
zabbixVer=''
zabbixInt=''

function zabbixVersion {
  echo -e "${YELLOW}Checking Zabbix version..."
  zabbixVer=$(zabbix_agentd --print | grep agent.version | awk -F'|' '{print $2}' | sed 's/]//' 2> /dev/null)
  [[ -z $zabbixVer ]] && zabbixVer=$(zabbix_agentd -V | egrep '(zabbix|daemon)' | awk -F' ' '{print $4}' | sed 's/v//')
  zabbixInt=$(echo $zabbixVer | cut -b 1)
}

# Uninstall zabbix-agent and its dependencies
function removeZabbix {
  sudo apt-get remove zabbix-agent -y &> /dev/null
  wait
  sudo apt-get remove zabbix-release -y &> /dev/null
  wait
  sudo mv /etc/zabbix/zabbix_agentd.conf /etc/zabbix/zabbix_agentd.conf.bak
}

function zabbixCleanUp {
  echo -e "${YELLOW}Cleaning up...${NC}"
  sudo rm zabbix-release_*.deb
  removeWget
}

function zabbixRestart {
  echo -e "${YELLOW}Attempting to restart Zabbix service...${NC}"
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
  [[ -f ${zConf} ]] && echo -e "${YELLOW}Checking Zabbix configuration...${NC}"
  sudo sed -i -E 's/(127.0.0.1|172.24.18.224)/10.25.250.38/' $zConf &> /dev/null
  sudo sed -i 's/^Hostname=Zabbix.*/# &/' $zConf &> /dev/null
  [[ $(egrep -c "^HostMetadataItem=.*" $zConf) -eq 0 ]] && echo 'HostMetadataItem=system.uname' | sudo tee -a $zConf &> /dev/null
  [[ $(egrep -c "^Include=.*" $zConf) -eq 0 ]] && echo 'Include=/etc/zabbix/zabbix_agentd.d/*.conf' | sudo tee -a $zConf &> /dev/null
  echo -e "${GREEN}Config done${NC}"
  zabbixRestart
}

function zabbixInstall {
  echo -e "${GREEN}Determined Ubuntu release, as an integer, to be:${PURPLE} $releaseInt${NC}"
  getWget
  if [[ $releaseInt == 18 ]]; then
    echo -e "${YELLOW}Installing Zabbix for Ubuntu${PURPLE} 18 (Bionic)${NC}"
    sudo wget https://repo.zabbix.com/zabbix/4.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_4.2-1+bionic_all.deb &> /dev/null
    wait
    sudo dpkg -i zabbix-release_4.2-1+bionic_all.deb &> /dev/null
    wait
  elif [[ $releaseInt == 16 ]]; then
    echo -e "${YELLOW}Installing Zabbix for Ubuntu${PURPLE} 16 (Xenial)${NC}"
    sudo wget https://repo.zabbix.com/zabbix/4.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_4.2-1+xenial_all.deb &> /dev/null
    wait
    sudo dpkg -i zabbix-release_4.2-1+xenial_all.deb &> /dev/null
    wait
  elif [[ $releaseInt == 14 ]]; then
    echo -e "${YELLOW}Installing Zabbix for Ubuntu${PURPLE} 14 (Trusty)${NC}"
    sudo wget https://repo.zabbix.com/zabbix/4.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_4.2-1+trusty_all.deb &> /dev/null
    wait
    sudo dpkg -i zabbix-release_4.2-1+trusty_all.deb &> /dev/null
    wait
  else
    echo -e "${RED}Unable to determine Ubuntu version, requires manual intervention${NC}"
    exit 1
  fi
  sleep 5s
  echo -e "${ORANGE}apt-get update might take a few moments...${NC}"
  apt-cache policy zabbix-agent | egrep --color=always '(Installed|Candidate)'
  sudo apt-get update &> /dev/null
  wait
  echo -e "${GREEN}apt-get update completed${NC}"
  apt-cache policy zabbix-agent | egrep --color=always '(Installed|Candidate)'
  wait
  echo -e "${YELLOW}Installing zabbix-agent...${NC}"
  # sudo apt-get install zabbix-agent=1:4.* -y #&> /dev/null
  sudo DEBIAN_FRONTEND=noninteractive apt-get -qq -o Dpkg::Options::=--force-confdef install zabbix-agent=1:4.* #&> /dev/null
  wait
  apt-cache policy zabbix-agent | egrep --color=always '(Installed|Candidate)'
  zabbixCleanUp
  zabbixConfigure
  zabbixVersion
  echo -e "Zabbix Agent ${GREEN}is now installed and running ${NC}version: ${PURPLE} ${zabbixVer}${NC}"
}

function zabbixPurge {
  sudo apt-get purge zabbix-agent -y &> /dev/null
  wait
  sudo apt-get purge zabbix-release -y &> /dev/null
  wait
  sudo dpkg --purge --force-all zabbix-agent &> /dev/null
  wait
  sudo dpkg --purge --force-all zabbix-release &> /dev/null
  wait
  sudo rm -r /etc/zabbix  &> /dev/null
}

#### starts Zabbix assessment ###
[[ -f $zConf ]] && zabbixConfigure
# is zabbix running
ps aux | grep -v $USER | grep -i zabbix &> /dev/null # -v $USER ignores the user's grep process
if [[ $? -eq 0 ]]; then
  zabbixVersion
  echo -e "Zabbix Agent is ${GREEN}installed and running ${NC}version: ${PURPLE} ${zabbixVer}${NC}"
  if [[ -n ${zabbixInt} && ${zabbixInt} -lt 4 ]]; then
    echo -e "Zabbix version${PURPLE} ${zabbixVer} ${NC}is less than ${PURPLE}4.0.0${NC}: ${ORANGE}Removing Zabbix...${NC}"
    removeZabbix
    echo -e "${YELLOW}Installing Zabbix current version...${NC}"
    zabbixInstall
  fi
else
  echo -e "zabbix_agentd is ${ORANGE}not running${NC}: ${YELLOW}starting installation${NC}"
  dpkg -l | grep zabbix &> /dev/null
  [[ $? -eq 0 ]] && zabbixPurge
  zabbixInstall
fi

if [[ -n ${zabbixInt} && ${zabbixInt} -lt 3 ]]; then
  echo -e "${ORANGE}There seems to have been a problem${NC}"
  echo -e "${ORANGE}Zabbix version${PURPLE} ${zabbixVer} ${GREEN}is less than 3: trying again...${NC}"
  echo -e "${ORANGE}Performing purge..${NC}"
  zabbixPurge
  echo -e "${YELLOW}Installing Zabbix current version again...${NC}"
  zabbixInstall
fi

if [[ -n ${zabbixInt} && ${zabbixInt} -lt 3 ]]; then
  echo -e "${RED}Problem with Zabbix is extensive, requires manual intervention${NC}"
  exit 2
fi
