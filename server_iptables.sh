#!/bin/bash

set -e  # Остановить выполнение при ошибке

sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP
sudo iptables -A OUTPUT -d 239.255.255.250/32 -p udp --dport 5555 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 5556 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 5556 ! -d 239.255.255.250 -j ACCEPT
