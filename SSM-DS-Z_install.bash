#!/bin/bash
# Author :: Chris Cook
# initDate :: 08/29/19
# upDate :: 02/01/21
# Version :: 1.4
# Desc: check for/install/configure Amazon SSM, DeepSec, Chrony, Zabbix

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
    echo -e "wget is currently :: ${ORANGE}not installed${NC}"
    echo -e "Installing :: ${ORANGE}wget${NC}"
    export wgetInstalled=0
    sudo apt-get install wget &> /dev/null # install it
    wait
  else
    echo -e "wget is currently :: ${GREEN}installed${NC}"
    export wgetInstalled=1
  fi
}

function removeWget {
  if [[ $wgetInstalled == 0 ]]; then
    echo -e "${ORANGE}wget was not installed, but we installed it, so removing it...${NC}"
    sudo apt-get remove wget -y &> /dev/null
    wait
  fi
}

########## Ubuntu ##########
# Get release version and save as Int in $releaseInt
echo -e "Checking :: ${GREEN}OS Release${NC}"
releaseInt=$(lsb_release -a 2>/dev/null | egrep 'Release' | awk -F' ' '{print $2}' | cut -b -2)
wait
echo -e "Determined Ubuntu release, as an integer, to be :: ${PURPLE}$releaseInt${NC}"
echo -e "\nLocal hostname :: ${GREEN}$(hostnamectl | grep -i static | awk -F' ' '{print $3}')${NC}"
wait
[[ $(snap list core &> /dev/null; test=$?; wait; echo $test) -eq 0 ]] && snapTest=1 || snapTest=0


########## SSM ##########
# https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-manual-agent-install.html#agent-install-ubuntu-deb
# On Ubuntu Server 18.04, use Snaps only. Don't install deb packages.
# install SSM
echo -e "\nChecking :: ${GREEN}Amazon SSM Agent${NC}"
function ssmInstall {
  if [[ $snapTest -eq 1 ]]; then
    sudo snap install amazon-ssm-agent --classic -y
    wait
  else
    getWget
    echo -e "Getting Amazon SSM Agent..."
    sudo wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb &> /dev/null
    wait
    echo -e "Installing :: ${ORANGE}Amazon SSM Agent${NC}"
    sudo dpkg -i amazon-ssm-agent.deb &> /dev/null
    wait
  fi
}

function ssmCleanup {
  echo -e "Cleaning up..."
  [[ -f amazon-ssm-agent.deb ]] && sudo rm amazon-ssm-agent.deb
  wait
  removeWget
}

function ssmRestart {
  echo -e "Attempting to restart :: ${ORANGE}Amazon SSM Agent${NC}"
  if [[ $snapTest -eq 1 ]]; then
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
    echo -e "Amazon SSM Agent is currently :: ${GREEN}installed and running${NC}"
    return 0
  else
    echo -e "Amazon SSM Agent is currently :: ${ORANGE}not running${NC}"
    return 1
  fi
}

ssmStatus
if [[ $? -eq 1 ]]; then
  echo -e "Attempting to restart :: ${ORANGE}Amazon SSM Agent${NC}"
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
echo -e "\nChecking :: ${GREEN}TrendMicro Deep Security Agent${NC}"
function AgentDeploymentScript {
  echo -e "${RED}### get current activation script from Security ###${NC}'
}

# is DS installed
ps aux | grep -v $USER | grep ds_agent &> /dev/null
if [[ $? == 0 ]]; then
  echo -e "TrendMicro Deep Security Agent is currently :: ${GREEN}installed and running${NC}"
else
  echo -e "TrendMicro Deep Security Agent is currently :: ${ORANGE}not running${NC} ==> starting installation"
  AgentDeploymentScript
  wait
  ps aux | grep -v $USER | grep ds_agent &> /dev/null
  if [[ $? == 0 ]]; then
    echo -e "TrendMicro Deep Security Agent is currently :: ${GREEN}installed and running${NC}"
  else
    echo -e "${RED}There was a problem installing TrendMicro Deep Security Agent${NC}"
    exit 1
  fi
fi


########## Chrony NTP ##########
# exit code '2' on failure
cConf=$(find /etc 'chrony.conf' 2>/dev/null | grep 'chrony.conf$')
cConf=${cConf:='/etc/chrony/chrony.conf'}
# cBak='/etc/chrony/chrony.conf.original'
cBak="${cConf}.original"
echo -e "\nChecking :: ${GREEN}Chrony NTP${NC}"

function chronyInstall {
	echo -e "Installing :: ${GREEN}chrony${NC}"
	sudo apt-get install chrony -y &> /dev/null
	wait $!
}

function chronyBackup {
	if [[ ! -f ${cBak} ]]; then
		echo -e "Original configuration backup currenty :: ${RED}does not exist${NC}\nCopying ${ORANGE}$cConf${NC} to ${ORANGE}$cBak${NC}"
		sudo cp -n $cConf $cBak # -n don't overwrite existing
	else
		echo -e "Original configuration backup ${GREEN}exists${NC}"
	fi
}

function chronyConfigure {
	if [[ -f ${cConf} ]]; then # is conf present
		echo -e "Checking chrony configuration..."
		cOld=$(du -b $cConf | cut -f1)
		[[ $(egrep -c "^server 169.254.169.123.*" $cConf) -eq 0 ]] && sudo sed -i -e '1iserver 169.254.169.123 prefer iburst minpoll 4 maxpoll 4\n' $cConf
		cNew=$(du -b $cConf | cut -f1)
		if [[ "$cOld" != "$cNew" ]]; then
			echo -e "${GREEN}Configuration updated${NC}"
			chronyRestart
		fi
	else
		echo -e "${RED}Configuration not found :: $cConf${NC}"
		exit 2
	fi
}

function chronyRestart {
	echo -e "Attempting to restart :: ${ORANGE}chrony${NC}"
	sudo /etc/init.d/chrony restart
	wait $!
	# sleep 5
}

function chronyVerify {
	sudo chronyc tracking | grep -E -i --color=always "169.254.169.123"
	if [[ $? -gt 0 ]]; then
		echo -e "${RED}Unable to confirm ${ORANGE}chronyc tracking${NC} ==> retrying"
		sleep 5
		sudo chronyc tracking | grep -E -i --color=always "169.254.169.123"
		if [[ $? -gt 0 ]]; then
			echo -e "${RED}Unable to confirm ${ORANGE}chronyc tracking${RED} ==> requires manual intervention${NC}"
			echo -e "===> head $cConf"
			head $cConf
			exit 2
		fi
	fi
}

# is chrony running
ps aux | grep -v $USER | grep -i chronyd &> /dev/null # -v $USER ignores the user's grep process
if [[ $? -gt 0 ]]; then # >0 service is not running
	echo -e "Chrony is currently :: ${ORANGE}not running${NC}"
	if [[ ! -f ${cConf} ]]; then # chrony config is not found either
		echo -e "Chrony is currently :: ${ORANGE}not installed${NC}"
		chronyInstall
		chronyBackup
		chronyConfigure
	else
		echo -e "Chrony is currently :: ${GREEN}installed${NC} but ${ORANGE}not running${NC}"
		chronyBackup
		chronyConfigure
	fi
else
	echo -e "Chrony is currently :: ${GREEN}running${NC}"
	chronyBackup
	chronyConfigure
fi
chronyVerify




########## Zabbix ##########
# exit code '3' on failure
zConf='/etc/zabbix/zabbix_agentd.conf'
zabbixVer=''
zabbixInt=''
echo -e "\nChecking :: ${GREEN}Zabbix Agent${NC}"

function zabbixVersion {
	zabbixVer=$(zabbix_agentd --print | grep agent.version | awk -F'|' '{print $2}' | sed 's/]//' 2> /dev/null)
	[[ -z $zabbixVer ]] && zabbixVer=$(zabbix_agentd -V | egrep '(zabbix|daemon)' | awk -F' ' '{print $4}' | sed 's/v//')
	zabbixInt=$(echo $zabbixVer | cut -b 1)
}

# Uninstall zabbix-agent and its dependencies
function removeZabbix {
	sudo apt-get remove zabbix-agent -y &> /dev/null
	wait $!
	sudo apt-get remove zabbix-release -y &> /dev/null
	wait $!
}

function zabbixCleanUp {
	echo -e "Cleaning up..."
	[[ -f zabbix-release_*.deb ]] && sudo rm zabbix-release_*.deb
	wait $!
	removeWget
}

function zabbixRestart {
	echo -e "Attempting to restart :: ${ORANGE}Zabbix Agent${NC}"
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
	[[ -f ${zConf} ]] && echo -e "Checking Zabbix Agent configuration..."
	zOld=$(du -b $zConf | cut -f1)
	sudo sed -i -E 's/(127.0.0.1|172.24.18.224)/10.25.250.38/' $zConf &> /dev/null
	sudo sed -i 's/^Hostname=Zabbix.*/# &/' $zConf &> /dev/null
	[[ $(egrep -c "^HostMetadataItem=.*" $zConf) -eq 0 ]] && echo 'HostMetadataItem=system.uname' | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "^Include=.*" $zConf) -eq 0 ]] && echo 'Include=/etc/zabbix/zabbix_agentd.d/*.conf' | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=sockstat.sockets.count" $zConf) -eq 0 ]] && echo "UserParameter=sockstat.sockets.count, netstat -an | egrep -i '(tcp|udp)' | wc -l" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=sockstat.tcp.established.count" $zConf) -eq 0 ]] && echo "UserParameter=sockstat.tcp.established.count, netstat -an | egrep 'ESTABLISHED' | wc -l" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=sockstat.tcp.closewait.count" $zConf) -eq 0 ]] && echo "UserParameter=sockstat.tcp.closewait.count, netstat -an | egrep 'CLOSE_WAIT' | wc -l" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=sockstat.tcp.timewait.count" $zConf) -eq 0 ]] && echo "UserParameter=sockstat.tcp.timewait.count, netstat -an | egrep 'TIME_WAIT' | wc -l" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=sockstat.tcp.listening.count" $zConf) -eq 0 ]] && echo "UserParameter=sockstat.tcp.listening.count, netstat -an | egrep 'LISTEN' | wc -l" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=sockstat.tcp.finwait1.count" $zConf) -eq 0 ]] && echo "UserParameter=sockstat.tcp.finwait1.count, netstat -an | egrep 'FIN_WAIT_?1' | wc -l" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=sockstat.tcp.finwait2.count" $zConf) -eq 0 ]] && echo "UserParameter=sockstat.tcp.finwait2.count, netstat -an | egrep 'FIN_WAIT_?2' | wc -l" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=sockstat.udp.inuse.count" $zConf) -eq 0 ]] && echo "UserParameter=sockstat.udp.inuse.count, netstat -an | egrep -i 'UDP' | wc -l" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=aws.ec2metadata.availability-zone" $zConf) -eq 0 ]] && echo "UserParameter=aws.ec2metadata.availability-zone, ec2metadata --availability-zone" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=aws.ec2metadata.instance-id" $zConf) -eq 0 ]] && echo "UserParameter=aws.ec2metadata.instance-id, ec2metadata --instance-id" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=aws.ec2metadata.instance-type" $zConf) -eq 0 ]] && echo "UserParameter=aws.ec2metadata.instance-type, ec2metadata --instance-type" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=aws.ec2metadata.private-ipv4" $zConf) -eq 0 ]] && echo "UserParameter=aws.ec2metadata.private-ipv4, ec2metadata --local-ipv4" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=aws.ec2metadata.mac" $zConf) -eq 0 ]] && echo "UserParameter=aws.ec2metadata.mac, ec2metadata --mac" | sudo tee -a $zConf &> /dev/null
	[[ $(egrep -c "UserParameter=aws.ec2metadata.platform" $zConf) -eq 0 ]] && echo "UserParameter=aws.ec2metadata.platform, ec2metadata --profile" | sudo tee -a $zConf &> /dev/null
	
	zNew=$(du -b $zConf | cut -f1)
	echo "Config file size :: $zOld ==> $zNew"
	if [[ "$zOld" != "$zNew" ]]; then
		echo -e "${GREEN}Configuration updated${NC}"
		zabbixRestart
	fi
}

function zabbixInstall {
	getWget
	if [[ $releaseInt == 20 ]]; then
		echo -e "Installing :: ${ORANGE}Zabbix${NC} for Ubuntu${PURPLE} 20 (Focal)${NC}"
		sudo wget https://repo.zabbix.com/zabbix/5.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_5.2-1+ubuntu20.04_all.deb #&> /dev/null
		wait $!
	elif [[ $releaseInt == 18 ]]; then
		echo -e "Installing :: ${ORANGE}Zabbix${NC} for Ubuntu${PURPLE} 18 (Bionic)${NC}"
		sudo wget https://repo.zabbix.com/zabbix/5.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_5.2-1+ubuntu18.04_all.deb #&> /dev/null
		wait $!
	elif [[ $releaseInt == 16 ]]; then
		echo -e "Installing :: ${ORANGE}Zabbix${NC} for Ubuntu${PURPLE} 16 (Xenial)${NC}"
		sudo wget https://repo.zabbix.com/zabbix/5.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_5.2-1+ubuntu16.04_all.deb #&> /dev/null
		wait $!
	elif [[ $releaseInt == 14 ]]; then
		echo -e "Installing :: ${ORANGE}Zabbix${NC} for Ubuntu${PURPLE} 14 (Trusty)${NC}"
		sudo wget https://repo.zabbix.com/zabbix/5.2/ubuntu/pool/main/z/zabbix-release/zabbix-release_5.2-1+ubuntu14.04_all.deb #&> /dev/null
		wait $!
	else
		echo -e "${RED}Unable to determine Ubuntu version, requires manual intervention${NC}"
		exit 3
	fi
	sudo dpkg -i zabbix-release_5*.deb &> /dev/null
	wait $!
	sleep 5
	echo -e "${ORANGE}apt-get update might take a few moments...${NC}"
	apt-cache policy zabbix-agent | egrep --color=always '(Installed|Candidate)'
	sudo apt-get update &> /dev/null
	wait $!
	echo -e "${GREEN}apt-get update completed${NC}"
	apt-cache policy zabbix-agent | egrep --color=always '(Installed|Candidate)'
	wait $!
	echo -e "Installing :: ${ORANGE}zabbix-agent${NC}"
	sudo DEBIAN_FRONTEND=noninteractive apt-get -qq -o Dpkg::Options::=--force-confold install zabbix-agent=1:5.* &> /dev/null
	wait $!
	apt-cache policy zabbix-agent | egrep --color=always '(Installed|Candidate)'
	zabbixCleanUp
	zabbixConfigure
	zabbixVersion
	echo -e "Zabbix Agent is currently :: ${GREEN}installed and running${NC} version ${PURPLE}${zabbixVer}${NC}"
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
	wait
}

#### starts Zabbix assessment ###
[[ -f $zConf ]] && zabbixConfigure
# is zabbix running
ps aux | grep -v $USER | grep -i zabbix &> /dev/null # -v $USER ignores the user's grep process
if [[ $? -eq 0 ]]; then
	zabbixVersion
	echo -e "Zabbix Agent is currently :: ${GREEN}installed and running${NC} version ${PURPLE}${zabbixVer}${NC}"
	if [[ -n ${zabbixInt} && ${zabbixInt} -lt 4 ]]; then
		echo -e "Zabbix version ${PURPLE}${zabbixVer}${NC}is less than ${PURPLE}4.0.0${NC} ==> ${ORANGE}Removing Zabbix${NC}"
		removeZabbix
		echo -e "Installing Zabbix current version..."
		zabbixInstall
	fi
else
	echo -e "zabbix_agentd is currently :: ${ORANGE}not running${NC} ==> starting installation"
	dpkg -l | grep zabbix &> /dev/null
	[[ $? -eq 0 ]] && zabbixPurge
	zabbixInstall
fi

if [[ -n ${zabbixInt} && ${zabbixInt} -lt 3 ]]; then
	echo -e "${ORANGE}There seems to have been a problem${NC}"
	echo -e "${ORANGE}Zabbix major version ${PURPLE}${zabbixVer}${NC} is less than 3.0.0 :: trying again..."
	echo -e "${ORANGE}Performing purge..${NC}"
	zabbixPurge
	echo -e "Installing Zabbix current version again..."
	zabbixInstall
fi

if [[ -n ${zabbixInt} && ${zabbixInt} -lt 3 ]]; then
	echo -e "${RED}Problem with Zabbix is extensive, requires manual intervention${NC}"
	exit 3
fi
