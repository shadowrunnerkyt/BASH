#!/bin/bash
# Author: Chris Cook
# upDate: 01/25/21
# Version: 0.9
# Desc: New EC2 Instance Launch


echo "alias lss='sudo ls -Alhp --color --group-directories-first'" >> /home/ubuntu/.bash_aliases
chown ubuntu:ubuntu /home/ubuntu/.bash_aliases
apt update && apt upgrade -y
wait $!
apt install chrony -y
wait $!
cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.original
sed -i -e '1iserver 169.254.169.123 prefer iburst minpoll 4 maxpoll 4\n' /etc/chrony/chrony.conf
shutdown -r now
