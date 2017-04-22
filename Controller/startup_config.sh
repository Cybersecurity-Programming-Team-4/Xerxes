#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root!" 1>&2
   exit 1
fi

apt install at libpcap-dev tshark -y


iptables -A INPUT -p tcp --dport 60000 -j DROP
make ../Scanners/src/masscan

