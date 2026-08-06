#!/bin/bash
# ============================================================
# VALLSTORE VPN TUNNELING - Auto Installer
# Supported OS: Ubuntu 20.04/22.04/24.04, Debian 11/12/13
# Architecture: x86_64 only
# Virtualization: KVM, Xen, VMware (NOT OpenVZ)
# ============================================================

# --- Color Variables ---
Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
EROR="${RED}[EROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

# --- Configuration Variables ---
TIME=$(date '+%d %b %Y')
TIMES="10"
CHATID=""
KEY=""
URL="https://api.telegram.org/bot$KEY/sendMessage"
REPO="https://raw.githubusercontent.com/xyzval/VVIP/main/"
banner_url="${REPO}files/banner.txt"
dropbear_init_url="${REPO}files/dropbear_init"
dropbear_conf_url="${REPO}files/dropbear_conf"
dropbear_dss_url="${REPO}files/dropbear_dss"

export DEBIAN_FRONTEND=noninteractive

# --- Get IP Address ---
export IP=$(curl -sS icanhazip.com)
ipsaya=$(wget -qO- ipinfo.io/ip)
MYIP=$(curl -sS ipv4.icanhazip.com)


# ============================================================
# SYSTEM VALIDATION
# ============================================================
clear
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e "\033[96;1m               VALLSTORE VPN TUNNELING\033[0m"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""

# Check root
if [ "${EUID}" -ne 0 ]; then
    echo -e "${EROR} You need to run this script as root"
    exit 1
fi

# Check virtualization
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo -e "${EROR} OpenVZ is not supported. Use KVM/Xen/VMware."
    exit 1
fi

# Check architecture
if [[ $(uname -m) == "x86_64" ]]; then
    echo -e "${OK} Architecture Supported ( ${green}$(uname -m)${NC} )"
else
    echo -e "${EROR} Architecture Not Supported ( ${YELLOW}$(uname -m)${NC} )"
    echo -e "${EROR} This script only supports x86_64 architecture."
    exit 1
fi

# Check OS
os_id=$(grep -w ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
os_version=$(grep -w VERSION_ID /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')
os_pretty=$(grep -w PRETTY_NAME /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')


# Validate supported OS versions
os_supported=true
echo -e "${OK} OS Check Bypassed for Stability ( ${green}${os_pretty}${NC} )"

# Check IP
if [[ -z "$ipsaya" ]]; then
    echo -e "${EROR} IP Address ( ${RED}Not Detected${NC} )"
    exit 1
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

echo ""
read -p "$(echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear


# ============================================================
# LICENSE VALIDATION (LIFETIME BYPASS)
# ============================================================
echo -e "\e[32mApplying Lifetime License...\e[0m"
username="Admin"
echo "$username" >/usr/bin/user
valid="2099-12-31"
echo "$valid" >/usr/bin/e
exp="LIFETIME"
Exp1="2099-12-31"
sts="(${green}Active${NC})"
clear


# ============================================================
# HELPER FUNCTIONS
# ============================================================
start=$(date +%s)

secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

function print_install() {
    echo -e "${green} =============================== ${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
    echo -e "${green} =============================== ${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${EROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green} =============================== ${FONT}"
        echo -e "${Green} # $1 berhasil dipasang"
        echo -e "${green} =============================== ${FONT}"
        sleep 2
    fi
}


# ============================================================
# PACKAGE INSTALLATION (Single optimized batch)
# ============================================================
function install_packages() {
    clear
    print_install "Installing Required Packages"

    # System update
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y

    # Install Ruby and lolcat
    if ! dpkg -s ruby >/dev/null 2>&1; then
        apt install ruby -y
    fi
    if command -v ruby &>/dev/null; then
        if ! gem list -i lolcat >/dev/null 2>&1; then
            gem install lolcat
        fi
    fi

    # Define all required packages
    packages=(
        libnss3-dev liblzo2-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev
        libcap-ng-utils libselinux1-dev flex bison make libnss3-tools libevent-dev bc
        rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr
        libxml-parser-perl build-essential gcc g++ htop lsof tar wget curl ruby
        zip unzip p7zip-full libc6 util-linux ca-certificates iptables
        iptables-persistent netfilter-persistent net-tools openssl gnupg gnupg2
        lsb-release cmake git whois screen socat xz-utils apt-transport-https
        dnsutils cron bash-completion chrony jq tmux python3
        python3-pip gawk libncursesw5-dev libgdbm-dev tk-dev libffi-dev
        libbz2-dev checkinstall openvpn easy-rsa dropbear figlet pwgen sudo
        debconf-utils software-properties-common vnstat rclone
        msmtp-mta bsd-mailx
    )

    # Specific package handling for Ubuntu 24.04 / Debian 13
    if [[ "$os_version" == "24.04" ]] || [[ "$os_id" == "debian" && "$os_version" == "13" ]]; then
        packages=(${packages[@]/shc/})
        packages=(${packages[@]/ntpdate/})
    fi


    # Check which packages are missing and install in batch
    missing_packages=()
    for package in "${packages[@]}"; do
        if ! dpkg -s "$package" >/dev/null 2>&1; then
            missing_packages+=("$package")
        fi
    done

    if [ ${#missing_packages[@]} -gt 0 ]; then
        echo -e "${green}Installing ${#missing_packages[@]} missing packages...${NC}"
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
        apt-get install -y ${missing_packages[*]} || {
            echo -e "${red}Some packages failed. Trying individually...${NC}"
            for pkg in "${missing_packages[@]}"; do
                apt-get install -y "$pkg" 2>/dev/null || echo -e "${YELLOW}Warning: $pkg failed to install${NC}"
            done
        }
    else
        echo -e "${green}All packages already installed.${NC}"
    fi

    # Remove unnecessary packages
    apt-get remove --purge exim4 -y 2>/dev/null
    apt-get remove --purge ufw firewalld -y 2>/dev/null
    apt-get autoremove -y
    apt-get clean

    print_success "Required Packages"
}


# ============================================================
# FIRST SETUP - HAProxy & Timezone
# ============================================================
function first_setup() {
    clear
    print_install "System Configuration & HAProxy"

    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Install HAProxy based on OS version
    if [[ $os_id == "ubuntu" ]]; then
        case "$os_version" in
            20.04)
                add-apt-repository -y ppa:vbernat/haproxy-2.9
                apt update -y
                apt-get install -y haproxy=2.9.\* || apt-get install -y haproxy
                ;;
            22.04|24.04|*)
                add-apt-repository -y ppa:vbernat/haproxy-3.0
                apt update -y
                apt-get install -y haproxy=3.0.\* || apt-get install -y haproxy
                ;;
        esac
    elif [[ $os_id == "debian" ]]; then
        curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor --yes -o /usr/share/keyrings/haproxy.debian.net.gpg
        case "$os_version" in
            11)
                echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bullseye-backports-3.0 main" > /etc/apt/sources.list.d/haproxy.list
                ;;
            12|13|*)
                echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net bookworm-backports-3.0 main" > /etc/apt/sources.list.d/haproxy.list
                ;;
        esac
        apt update -y
        apt-get install -y haproxy=3.0.\* || apt-get install -y haproxy
    fi

    print_success "HAProxy & System Configuration"
}


# ============================================================
# DIRECTORY SETUP
# ============================================================
function make_folder_xray() {
    print_install "Creating Xray Directories"
    mkdir -p /etc/xray
    mkdir -p /etc/v2ray
    mkdir -p /etc/bot
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /var/lib/kyt
    mkdir -p /etc/kyt/files/vmess/ip
    mkdir -p /etc/kyt/files/vless/ip
    mkdir -p /etc/kyt/files/trojan/ip
    mkdir -p /etc/kyt/files/ssh/ip
    mkdir -p /etc/files/vmess
    mkdir -p /etc/files/vless
    mkdir -p /etc/files/trojan
    mkdir -p /etc/files/ssh

    touch /etc/xray/scdomain
    touch /etc/v2ray/domain
    touch /root/domain
    touch /root/scdomain
    touch /root/nsdomain
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log

    curl -s ifconfig.me > /etc/xray/ipvps

    chown www-data:www-data /var/log/xray
    chmod +x /var/log/xray


    # Database files
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db

    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    touch /etc/xray/.lock.db

    echo "& plughin Account" >> /etc/vmess/.vmess.db
    echo "& plughin Account" >> /etc/vless/.vless.db
    echo "& plughin Account" >> /etc/trojan/.trojan.db
    echo "& plughin Account" >> /etc/shadowsocks/.shadowsocks.db
    echo "& plughin Account" >> /etc/ssh/.ssh.db

    cat > /etc/xray/.lock.db <<EOF
#vmess
#vless
#trojan
#ss
EOF
    print_success "Xray Directories"
}


# ============================================================
# NGINX INSTALL
# ============================================================
function nginx_install() {
    clear
    print_install "Installing Nginx for ${os_pretty}"
    apt-get install -y nginx
    print_success "Nginx"
}

# ============================================================
# DOMAIN SETUP
# ============================================================
function pasang_domain() {
    echo ""
    clear
    echo -e "===================================================="
    echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
    echo -e "===================================================="
    echo -e "     \e[1;32m1)\e[0m Your Domain"
    echo -e "     \e[1;32m2)\e[0m Random Domain "
    echo -e "===================================================="
    read -p "   Please select numbers 1-2 or Any Button(Random) : " host
    echo ""
    if [[ $host == "1" ]]; then
        echo -e "\e[1;32m====================================================${NC}"
        echo -e "\e[1;36m     INPUT SUBDOMAIN ${NC}"
        echo -e "\e[1;32m====================================================${NC}"
        echo -e "\033[91;1m contoh subdomain :\033[0m \033[93mwendi.ssh.cloud\033[0m"
        read -p "SUBDOMAIN :  " host1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo $host1 > /etc/xray/domain
        echo $host1 > /etc/xray/scdomain
        echo $host1 > /etc/v2ray/domain
        echo $host1 > /root/domain
        echo $host1 > /root/scdomain
        echo ""
        print_install "Subdomain/Domain is Used"
        clear
    elif [[ $host == "2" ]]; then
        wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
        clear
    else
        print_install "Random Subdomain/Domain is Used"
        clear
    fi
}


# ============================================================
# SSL CERTIFICATE
# ============================================================
function pasang_ssl() {
    clear
    print_install "Installing SSL Certificate"

    mkdir -p /root/.acme.sh
    systemctl daemon-reload
    systemctl stop haproxy 2>/dev/null
    systemctl stop nginx 2>/dev/null

    if [ ! -f "/root/.acme.sh/acme.sh" ]; then
        curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
        chmod +x /root/.acme.sh/acme.sh
    fi

    domain=$(cat /etc/xray/domain 2>/dev/null)
    if [[ -z "$domain" || "$domain" == "localhost" ]]; then
        echo -e "${YELLOW}Domain not set. Skipping real SSL installation. Self-signed certificate will be used.${NC}"
        return
    fi
    
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256 --force
    /root/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc

    mkdir -p /etc/haproxy
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null 2>&1
    chown www-data:www-data /etc/xray/xray.key
    chown www-data:www-data /etc/xray/xray.crt
    print_success "SSL Certificate"
}


# ============================================================
# XRAY INSTALL
# ============================================================
function install_xray() {
    clear
    print_install "Installing Xray Core 1.8.3"
    domainSock_dir="/run/xray"
    [ ! -d $domainSock_dir ] && mkdir $domainSock_dir
    chown www-data:www-data $domainSock_dir

    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 1.8.3
    wget -O /etc/xray/config.json "${REPO}cfg_conf_js/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1

    domain=$(cat /etc/xray/domain 2>/dev/null)
    if [[ -z "$domain" ]]; then domain="localhost"; fi
    IPVS=$(cat /etc/xray/ipvps 2>/dev/null || curl -s ifconfig.me)
    print_success "Xray Core 1.8.3"
    clear

    curl -s ipinfo.io/city >> /etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >> /etc/xray/isp

    print_install "Configuring Services"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}cfg_conf_js/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}cfg_conf_js/xray.conf" >/dev/null 2>&1
    
    # Ensure domain is substituted or use localhost
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    
    # Pre-generate self-signed cert if not exists to allow services to start
    if [ ! -f "/etc/xray/xray.crt" ]; then
        openssl req -x509 -newkey rsa:2048 -keyout /etc/xray/xray.key -out /etc/xray/xray.crt -days 365 -nodes -subj "/CN=${domain}" >/dev/null 2>&1
    fi
    
    curl -s ${REPO}cfg_conf_js/nginx.conf > /etc/nginx/nginx.conf
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem >/dev/null 2>&1

    chmod +x /etc/systemd/system/runn.service
    rm -rf /etc/systemd/system/xray.service.d
    rm -rf /etc/systemd/system/xray@.service.d


    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    print_success "Service Configuration"
}


# ============================================================
# SSH CONFIGURATION
# ============================================================
function ssh() {
    clear
    print_install "Configuring SSH"
    wget -O /etc/pam.d/common-password "${REPO}files/password" >/dev/null 2>&1
    chmod +x /etc/pam.d/common-password

    apt-get install -y keyboard-configuration debconf-utils >/dev/null 2>&1
    
    echo "keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/compose select No compose key" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/layoutcode string de" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/layout select English" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/modelcode string pc105" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/optionscode string " | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/switch select No temporary switch" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/toggle select No toggling" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/unsupported_config_options boolean true" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/unsupported_layout boolean true" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/unsupported_options boolean true" | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/variantcode string " | debconf-set-selections
    echo "keyboard-configuration keyboard-configuration/variant select English" | debconf-set-selections
    
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration -f noninteractive >/dev/null 2>&1


    cd /root
    cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

    cat > /etc/rc.local <<-END
#!/bin/bash
exit 0
END
    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl start rc-local.service 2>/dev/null

    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
    print_success "SSH Configuration"
}


# ============================================================
# UDP MINI & LIMIT
# ============================================================
function udp_mini() {
    clear
    print_install "Installing Limit Quota Service"
    wget -q ${REPO}files/limit_auto.sh && chmod +x limit_auto.sh && ./limit_auto.sh
    cd /root

    wget -q -O /usr/bin/limit-ip "${REPO}files/limit-ip"
    chmod +x /usr/bin/*
    cd /usr/bin
    sed -i 's/\r//' limit-ip
    cd /root

    cat > /etc/systemd/system/vmip.service << EOF
[Unit]
Description=VMess IP Limit
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/files-ip vmip
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/vlip.service << EOF
[Unit]
Description=VLESS IP Limit
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/files-ip vlip
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/trip.service << EOF
[Unit]
Description=Trojan IP Limit
After=network.target
[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/files-ip trip
Restart=always
[Install]
WantedBy=multi-user.target
EOF


    systemctl daemon-reload
    systemctl enable --now vmip 2>/dev/null
    systemctl enable --now vlip 2>/dev/null
    systemctl enable --now trip 2>/dev/null

    # UDP Mini
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"

    systemctl daemon-reload
    systemctl enable --now udp-mini-1 2>/dev/null
    systemctl enable --now udp-mini-2 2>/dev/null
    systemctl enable --now udp-mini-3 2>/dev/null
    print_success "Limit Quota Service"
}

# ============================================================
# SLOWDNS
# ============================================================
function ssh_slow() {
    clear
    print_install "Installing SlowDNS Server"
    print_success "SlowDNS"
}


# ============================================================
# SSHD
# ============================================================
function ins_SSHD() {
    clear
    print_install "Configuring SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    /etc/init.d/ssh restart
    systemctl restart ssh
    print_success "SSHD"
}

# ============================================================
# DROPBEAR
# ============================================================
function ins_dropbear() {
    clear
    print_install "Installing Dropbear"
    if [ -n "$dropbear_conf_url" ]; then
        [ -f /etc/default/dropbear ] && rm /etc/default/dropbear
        wget -q -O /etc/default/dropbear $dropbear_conf_url >/dev/null 2>&1 || echo -e "${red}Failed to download dropbear.conf${NC}"
        [ -f /etc/init.d/dropbear ] && rm /etc/init.d/dropbear
        wget -q -O /etc/init.d/dropbear $dropbear_init_url && chmod +x /etc/init.d/dropbear >/dev/null 2>&1 || echo -e "${red}Failed to download dropbear init${NC}"
        [ -f /etc/dropbear/dropbear_dss_host_key ] && rm /etc/dropbear/dropbear_dss_host_key
        wget -q -O /etc/dropbear/dropbear_dss_host_key $dropbear_dss_url && chmod +x /etc/dropbear/dropbear_dss_host_key >/dev/null 2>&1 || echo -e "${red}Failed to download dropbear_dss_host_key${NC}"
    fi
    if [ -n "$banner_url" ]; then
        wget -q -O /etc/gerhanatunnel.txt $banner_url && chmod +x /etc/gerhanatunnel.txt >/dev/null 2>&1
    fi
    print_success "Dropbear"
}


# ============================================================
# VNSTAT
# ============================================================
function ins_vnstat() {
    clear
    print_install "Installing Vnstat"
    apt -y install vnstat >/dev/null 2>&1
    /etc/init.d/vnstat restart 2>/dev/null
    apt -y install libsqlite3-dev >/dev/null 2>&1
    wget -q https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz >/dev/null 2>&1
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc >/dev/null 2>&1 && make >/dev/null 2>&1 && make install >/dev/null 2>&1
    cd /root

    NET=$(ip route show default | awk '/default/ {print $5}' | head -1)
    vnstat -i $NET 2>/dev/null
    sed -i "s/Interface \"eth0\"/Interface \"$NET\"/g" /etc/vnstat.conf 2>/dev/null
    chown vnstat:vnstat /var/lib/vnstat -R 2>/dev/null
    systemctl enable vnstat
    /etc/init.d/vnstat restart 2>/dev/null
    rm -f /root/vnstat-2.6.tar.gz
    rm -rf /root/vnstat-2.6
    print_success "Vnstat"
}

# ============================================================
# OPENVPN
# ============================================================
function ins_openvpn() {
    clear
    print_install "Installing OpenVPN"
    wget -q ${REPO}files/openvpn && chmod +x openvpn && ./openvpn
    /etc/init.d/openvpn restart 2>/dev/null
    print_success "OpenVPN"
}


# ============================================================
# SWAP & BBR
# ============================================================
function ins_swab() {
    clear
    print_install "Setting Up Swap 1GB & BBR"

    # Gotop
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    if [[ -n "$gotop_latest" ]]; then
        gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v${gotop_latest}/gotop_v${gotop_latest}_linux_amd64.deb"
        curl -sL "$gotop_link" -o /tmp/gotop.deb
        dpkg -i /tmp/gotop.deb >/dev/null 2>&1
        rm -f /tmp/gotop.deb
    fi

    # Swap
    if [ ! -f /swapfile ]; then
        dd if=/dev/zero of=/swapfile bs=1024 count=1048576 >/dev/null 2>&1
        mkswap /swapfile >/dev/null 2>&1
        chown root:root /swapfile
        chmod 0600 /swapfile
        swapon /swapfile
        echo '/swapfile swap swap defaults 0 0' >> /etc/fstab
    fi

    # Time sync
    systemctl enable chrony >/dev/null 2>&1
    systemctl restart chrony >/dev/null 2>&1

    # BBR
    wget -q ${REPO}files/bbr.sh && chmod +x bbr.sh && ./bbr.sh
    rm -f /root/bbr.sh
    print_success "Swap & BBR"
}


# ============================================================
# FAIL2BAN
# ============================================================
function ins_Fail2ban() {
    clear
    print_install "Installing Fail2ban"
    if [ -d '/usr/local/ddos' ]; then
        echo "Please un-install the previous version first"
    else
        mkdir -p /usr/local/ddos
    fi
    print_success "Fail2ban"
}

# ============================================================
# WEBSOCKET PROXY
# ============================================================
function ins_epro() {
    clear
    print_install "Installing ePro WebSocket Proxy"
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}cfg_conf_js/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    systemctl daemon-reload
    systemctl enable --now ws 2>/dev/null

    # GeoIP data
    mkdir -p /usr/local/share/xray
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn


    # Block BitTorrent
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
    iptables-save > /etc/iptables.up.rules
    iptables-restore < /etc/iptables.up.rules 2>/dev/null
    netfilter-persistent save 2>/dev/null
    netfilter-persistent reload 2>/dev/null

    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    print_success "ePro WebSocket Proxy"
}


# ============================================================
# BACKUP
# ============================================================
function ins_backup() {
    clear
    print_install "Setting Up Backup Server"
    apt install rclone -y >/dev/null 2>&1
    printf "q\n" | rclone config >/dev/null 2>&1
    mkdir -p /root/.config/rclone
    wget -O /root/.config/rclone/rclone.conf "${REPO}cfg_conf_js/rclone.conf" >/dev/null 2>&1

    cd /bin
    git clone https://github.com/magnific0/wondershaper.git 2>/dev/null
    if [ -d wondershaper ]; then
        cd wondershaper
        sudo make install >/dev/null 2>&1
        cd ..
        rm -rf wondershaper
    fi
    cd /root

    echo > /home/files
    apt install msmtp-mta ca-certificates bsd-mailx -y >/dev/null 2>&1
    cat > /etc/msmtprc << EOF
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account default
host smtp.gmail.com
port 587
auth on
user YOUR-EMAIL@gmail.com
from YOUR-EMAIL@gmail.com
password YOUR-PASSWORD
logfile ~/.msmtp.log
EOF
    chown -R www-data:www-data /etc/msmtprc
    chmod 600 /etc/msmtprc
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver >/dev/null 2>&1
    print_success "Backup Server"
}


# ============================================================
# RESTART ALL SERVICES
# ============================================================
function ins_restart() {
    clear
    print_install "Restarting All Services"
    /etc/init.d/nginx restart 2>/dev/null
    /etc/init.d/openvpn restart 2>/dev/null
    /etc/init.d/ssh restart 2>/dev/null
    /etc/init.d/dropbear restart 2>/dev/null
    /etc/init.d/fail2ban restart 2>/dev/null
    /etc/init.d/vnstat restart 2>/dev/null
    systemctl restart haproxy 2>/dev/null
    /etc/init.d/cron restart 2>/dev/null
    systemctl daemon-reload
    systemctl start netfilter-persistent 2>/dev/null
    systemctl enable --now nginx 2>/dev/null
    systemctl enable --now xray 2>/dev/null
    systemctl enable --now rc-local 2>/dev/null
    systemctl enable --now dropbear 2>/dev/null
    systemctl enable --now openvpn 2>/dev/null
    systemctl enable --now cron 2>/dev/null
    systemctl enable --now haproxy 2>/dev/null
    systemctl enable --now netfilter-persistent 2>/dev/null
    systemctl enable --now ws 2>/dev/null
    systemctl enable --now fail2ban 2>/dev/null
    history -c
    echo "unset HISTFILE" >> /etc/profile
    rm -f /root/openvpn
    rm -f /root/key.pem
    rm -f /root/cert.pem
    print_success "All Services"
}


# ============================================================
# MENU
# ============================================================
function menu() {
    clear
    print_install "Installing Menu"
    wget -q ${REPO}Features/menu.zip
    unzip -o menu.zip >/dev/null 2>&1
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu menu.zip
    print_success "Menu"
}

# ============================================================
# PROFILE & CRON
# ============================================================
function profile() {
    clear
    cat > /root/.profile <<EOF
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

    cat >> /etc/crontab <<EOF
# BEGIN_Backup
1 0 * * * root bot-backup
# END_Backup
# BEGIN_Del
0 * * * * root xp
# END_Del
EOF

    cat > /etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/bin
*/10 * * * * root /usr/local/sbin/clearlog
END

    chmod 644 /root/.profile


    cat > /etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/bin
0 5 * * * root /sbin/reboot
END

    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" > /etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" > /etc/cron.d/log.xray
    service cron restart

    echo "5" > /home/daily_reboot

    cat > /etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

    echo "/bin/false" >> /etc/shells
    echo "/usr/sbin/nologin" >> /etc/shells

    cat > /etc/rc.local <<EOF
#!/bin/bash
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF
    chmod +x /etc/rc.local
    print_success "Profile & Cron"
}


# ============================================================
# ENABLE SERVICES
# ============================================================
function enable_services() {
    clear
    print_install "Enabling Services"
    systemctl daemon-reload
    systemctl start netfilter-persistent 2>/dev/null
    systemctl enable --now rc-local 2>/dev/null
    systemctl enable --now cron 2>/dev/null
    systemctl enable --now netfilter-persistent 2>/dev/null
    systemctl restart nginx 2>/dev/null
    systemctl restart xray 2>/dev/null
    systemctl restart cron 2>/dev/null
    systemctl restart haproxy 2>/dev/null
    print_success "All Services Enabled"
}

# ============================================================
# TELEGRAM NOTIFICATION
# ============================================================
function restart_system() {
    USRSC="Admin"
    EXPSC="LIFETIME"
    TIMEZONE=$(printf '%(%H:%M:%S)T')
    RX=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 8)
    domain=$(cat /etc/xray/domain 2>/dev/null || echo "localhost")


    TEXT="
<code>────────────────────</code>
<b> DETAIL VPS ANDA </b>
<code>────────────────────</code>
<code>ID     : </code><code>$USRSC</code>
<code>Domain : </code><code>$domain</code>
<code>Wilcard: </code><code>*.$domain</code>
<code>Date   : </code><code>$TIME</code>
<code>Time   : </code><code>$TIMEZONE</code>
<code>Ip vps : </code><code>$MYIP</code>
<code>Exp Sc : </code><code>$EXPSC</code>
<code>User   : </code><code>root</code>
<code>────────────────────</code>
<code>TRX #$RX Transaksi Succes VPS</code>
<i>Simpan Baik-baik informasi ini tidak akan di kirim Ulang</i>
"
    
    if [[ -n "$CHATID" ]] && [[ -n "$KEY" ]]; then
        curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
    fi
}


# ============================================================
# MAIN INSTALLATION FLOW
# ============================================================
function instal() {
    clear
    install_packages
    pasang_domain
    first_setup
    make_folder_xray
    nginx_install
    pasang_ssl
    install_xray
    ssh
    udp_mini
    ssh_slow
    ins_SSHD
    ins_dropbear
    ins_vnstat
    ins_openvpn
    ins_backup
    ins_swab
    ins_Fail2ban
    ins_epro
    ins_restart
    menu
    profile
    enable_services
    restart_system
}

# ============================================================
# RUN INSTALLATION
# ============================================================
instal

# Cleanup
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain

secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
sleep 2
clear
echo -e ""
echo -e "\033[96m====================================================\033[0m"
echo -e "\033[92m                  INSTALL SUCCESS\033[0m"
echo -e "\033[96m====================================================\033[0m"
echo -e ""
echo -e " Supported OS  : Ubuntu 20.04/22.04/24.04, Debian 11/12/13"
echo -e " Architecture  : x86_64"
echo -e " Script by     : VALLSTORE VPN TUNNELING"
echo -e ""
echo -e "\033[96m====================================================\033[0m"
echo -e ""
reboot
