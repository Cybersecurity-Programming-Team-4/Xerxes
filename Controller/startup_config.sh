#!/bin/bash

iptables -A INPUT -p tcp --dport 60000 -j DROP
