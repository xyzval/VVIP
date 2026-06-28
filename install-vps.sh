#!/bin/bash
# ============================================================
# VALLSTORE VPN TUNNELING - Bootstrap Installer
# Supported OS: Ubuntu 20.04/22.04/24.04, Debian 11/12
# Architecture: x86_64 only
# ============================================================

# Disable IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Update system
apt update -y
apt upgrade -y
apt install -y bzip2 gzip coreutils screen curl unzip

# Install lolcat
apt install ruby -y 2>/dev/null
gem install lolcat 2>/dev/null

# Download and run main setup
wget -q https://raw.githubusercontent.com/xyzval/VVIP/main/setup-main.sh
chmod +x setup-main.sh
sed -i -e 's/\r$//' setup-main.sh
screen -S setupku ./setup-main.sh
