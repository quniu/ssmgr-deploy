#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#
# Auto install shadowsocks/shadowsocks-libev Server
#
# Copyright (C) 2017-2018 QUNIU <https://github.com/quniu>
#
# System Required:  CentOS 6+, Debian7+, Ubuntu12+
#
# Reference URL:
# https://github.com/shadowsocks/shadowsocks
# https://github.com/shadowsocks/shadowsocks-libev
# https://github.com/shadowsocks/shadowsocks-windows
#
# 
# Intro:  https://github.com/quniu
#

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

cur_dir=$( pwd )

libsodium_file="libsodium-1.0.16"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"

mbedtls_file="mbedtls-2.12.0"
mbedtls_url="https://tls.mbed.org/download/mbedtls-2.12.0-gpl.tgz"

# shadowsocks libev
shadowsocks_manager_name="shadowsocks-manager"
shadowsocks_libev_init="/etc/init.d/shadowsocks-manager"
shadowsocks_libev_config="/etc/shadowsocks-manager/config.json"
shadowsocks_libev_centos="https://raw.githubusercontent.com/quniu/ssmgr-deploy/master/service/shadowsocks-manager"
shadowsocks_libev_debian="https://raw.githubusercontent.com/quniu/ssmgr-deploy/master/service/shadowsocks-manager-debian"

# Stream Ciphers
common_ciphers=(
aes-256-gcm
aes-192-gcm
aes-128-gcm
aes-256-ctr
aes-192-ctr
aes-128-ctr
aes-256-cfb
aes-192-cfb
aes-128-cfb
camellia-128-cfb
camellia-192-cfb
camellia-256-cfb
xchacha20-ietf-poly1305
chacha20-ietf-poly1305
chacha20-ietf
chacha20
salsa20
rc4-md5
)

# obfs
obfs=(
plain
http_simple
http_simple_compatible
http_post
http_post_compatible
tls1.2_ticket_auth
tls1.2_ticket_auth_compatible
tls1.2_ticket_fastauth
tls1.2_ticket_fastauth_compatible
)

# libev obfuscating
obfs_libev=(
http
tls
)

# initialization parameter
libev_obfs=""

disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

version_gt(){
    test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
}

check_kernel_version(){
    local kernel_version=$(uname -r | cut -d- -f1)
    if version_gt ${kernel_version} 3.7.0; then
        return 0
    else
        return 1
    fi
}

check_kernel_headers(){
    if check_sys packageManager yum; then
        if rpm -qa | grep -q headers-$(uname -r); then
            return 0
        else
            return 1
        fi
    elif check_sys packageManager apt; then
        if dpkg -s linux-headers-$(uname -r) > /dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    fi
    return 1
}

getversion(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

centosversion(){
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

autoconf_version(){
    if [ ! "$(command -v autoconf)" ]; then
        echo -e "[${green}Info${plain}] Starting install package autoconf"
        if check_sys packageManager yum; then
            yum install -y autoconf > /dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf"
        elif check_sys packageManager apt; then
            apt-get -y update > /dev/null 2>&1
            apt-get -y install autoconf > /dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf"
        fi
    fi
    local autoconf_ver=$(autoconf --version | grep autoconf | grep -oE "[0-9.]+")
    if version_ge ${autoconf_ver} 2.67; then
        return 0
    else
        return 1
    fi
}

get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    echo ${IP}
}

get_ipv6(){
    local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    [ -z ${ipv6} ] && return 1 || return 0
}

get_libev_ver(){
    libev_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${libev_ver} ] && echo -e "[${red}Error${plain}] Get shadowsocks-libev latest version failed" && exit 1
}
get_manager_ver(){
    manager_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/quniu/shadowsocks-manager/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${manager_ver} ] && echo -e "[${red}Error${plain}] Get shadowsocks-manager latest version failed" && exit 1
}

get_opsy(){
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

is_64bit(){
    if [ `getconf WORD_BIT` = '32' ] && [ `getconf LONG_BIT` = '64' ] ; then
        return 0
    else
        return 1
    fi
}

debianversion(){
    if check_sys sysRelease debian;then
        local version=$( get_opsy )
        local code=${1}
        local main_ver=$( echo ${version} | sed 's/[^0-9]//g')
        if [ "${main_ver}" == "${code}" ];then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

init_swapfile(){
    cd ${cur_dir}
    if [ -f /usr/local/swapfile.json ]; then
        if [ $? -eq 0 ]; then
            echo -e "[${green}Info${plain}] Swapfile already exists."
        fi
    else
        dd if=/dev/zero of=/tmp/swapfile bs=1M count=1024
        mkswap /tmp/swapfile
        swapon /tmp/swapfile
        echo "/tmp/swapfile swap swap defaults 0 0" >> /etc/fstab

        echo -e "[${green}Info${plain}] add swapfile completed."
        add_swapfile
    fi
}

add_swapfile(){
    cat > /usr/local/swapfile.json<<-EOF
{
    "server":$(get_ip)
}
EOF
}

download(){
    local filename=$(basename $1)
    if [ -f ${1} ]; then
        echo "${filename} [found]"
    else
        echo "${filename} not found, download now..."
        wget --no-check-certificate -c -t3 -T60 -O ${1} ${2}
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Download ${filename} failed."
            exit 1
        fi
    fi
}

download_files(){
    cd ${cur_dir}
    if [ ! -d "/usr/local/${shadowsocks_manager_name}" ]; then
        get_manager_ver
        shadowsocks_manager_file="shadowsocks-manager-$(echo ${manager_ver} | sed -e 's/^[a-zA-Z]//g')"
        shadowsocks_manager_url="https://github.com/quniu/shadowsocks-manager/releases/download/${manager_ver}/${shadowsocks_manager_file}.tar.gz"
        download "${shadowsocks_manager_file}.tar.gz" "${shadowsocks_manager_url}"
    else
        echo -e "[${green}Info${plain}] shadowsocks-manager already installed."
    fi  

    get_libev_ver
    shadowsocks_libev_file="shadowsocks-libev-$(echo ${libev_ver} | sed -e 's/^[a-zA-Z]//g')"
    shadowsocks_libev_url="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${libev_ver}/${shadowsocks_libev_file}.tar.gz"

    download "${shadowsocks_libev_file}.tar.gz" "${shadowsocks_libev_url}"
    if check_sys packageManager yum; then
        download "${shadowsocks_libev_init}" "${shadowsocks_libev_centos}"
    elif check_sys packageManager apt; then
        download "${shadowsocks_libev_init}" "${shadowsocks_libev_debian}"
    fi
}

get_char(){
    SAVEDSTTY=$(stty -g)
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

error_detect_depends(){
    local command=$1
    local depend=`echo "${command}" | awk '{print $4}'`
    echo -e "[${green}Info${plain}] Starting to install package ${depend}"
    ${command} > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Failed to install ${red}${depend}${plain}"
        exit 1
    fi
}

config_firewall(){
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "[${green}Info${plain}] port ${green}${shadowsocksport}${plain} already be enabled."
            fi
        else
            echo -e "[${yellow}Warning${plain}] iptables looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/tcp
            firewall-cmd --permanent --zone=public --add-port=${shadowsocksport}/udp
            firewall-cmd --reload
        else
            echo -e "[${yellow}Warning${plain}] firewalld looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
        fi
    fi
}

config_shadowsocks(){
    if check_kernel_version && check_kernel_headers; then
        fast_open="true"
    else
        fast_open="false"
    fi

    local server_value="\"0.0.0.0\""
    if get_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    fi

    if [ ! -d "$(dirname ${shadowsocks_libev_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_libev_config})
    fi

    if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
        cat > ${shadowsocks_libev_config}<<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=${shadowsocklibev_obfs}"
}
EOF
    else
        cat > ${shadowsocks_libev_config}<<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
    fi
}

install_dependencies(){
    if check_sys packageManager yum; then
        echo -e "[${green}Info${plain}] Checking the EPEL repository..."
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum install -y epel-release > /dev/null 2>&1
        fi
        [ ! -f /etc/yum.repos.d/epel.repo ] && echo -e "[${red}Error${plain}] Install EPEL repository failed, please check it." && exit 1
        [ ! "$(command -v yum-config-manager)" ] && yum install -y yum-utils > /dev/null 2>&1
        [ x"$(yum-config-manager epel | grep -w enabled | awk '{print $3}')" != x"True" ] && yum-config-manager --enable epel > /dev/null 2>&1
        echo -e "[${green}Info${plain}] Checking the EPEL repository complete..."

        yum_depends=(
            unzip gzip openssl openssl-devel gcc python python-devel python-setuptools pcre pcre-devel libtool libevent
            autoconf automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel libev-devel c-ares-devel git screen
        )
        for depend in ${yum_depends[@]}; do
            error_detect_depends "yum -y install ${depend}"
        done
    elif check_sys packageManager apt; then
        apt_depends=(
            gettext build-essential unzip gzip python python-dev python-setuptools curl openssl libssl-dev
            autoconf automake libtool gcc make perl cpio libpcre3 libpcre3-dev zlib1g-dev libev-dev libc-ares-dev git screen
        )

        apt-get -y update
        for depend in ${apt_depends[@]}; do
            error_detect_depends "apt-get -y install ${depend}"
        done
    fi
}

update_nodejs(){
    # update nodejs
    echo -e "[${green}Info${plain}] Starting to update nodejs EPEL..."
    if check_sys packageManager yum; then
        yum -y remove nodejs > /dev/null 2>&1
        curl --silent --location https://rpm.nodesource.com/setup_8.x | sudo bash - > /dev/null 2>&1
    elif check_sys packageManager apt; then
        apt-get -y remove nodejs > /dev/null 2>&1
        curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash - > /dev/null 2>&1
    fi
    echo -e "[${green}Info${plain}] update nodejs EPEL complete!"

    # Install nodejs
    if check_sys packageManager yum; then
        yum -y install nodejs > /dev/null 2>&1
    elif check_sys packageManager apt; then
        apt-get -y update
        apt-get -y install nodejs > /dev/null 2>&1
    fi

    if [ $? -eq 0 ]; then
        echo -e "[${green}Info${plain}] nodejs install complete!"
    else
        echo -e "[${yellow}Warning${plain}]  nodejs install failed!"
        exit 1
    fi
}

update_npm(){
    echo -e "[${green}Info${plain}] Starting to update npm..."
    npm i npm@latest -g > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "[${green}Info${plain}] npm update complete!"
    else
        echo -e "[${yellow}Warning${plain}] npm update failed!"
    fi
}

install_pm2(){
    echo -e "[${green}Info${plain}] Starting to install PM2..."
    npm install pm2 -g > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "[${green}Info${plain}] PM2 install complete!"
    else
        echo -e "[${yellow}Warning${plain}] PM2 install failed!"
    fi
}

install_check(){
    if check_sys packageManager yum || check_sys packageManager apt; then
        if centosversion 5; then
            return 1
        fi
        return 0
    else
        return 1
    fi
}

install_prepare_password(){
    echo -e "Please enter password for shadowsocks-libev:"
    read -p "(Default password: abc123456):" shadowsockspwd
    [ -z "${shadowsockspwd}" ] && shadowsockspwd="abc123456"
    echo "--------------------------------------"
    echo -e "[${green}Info${plain}] password = ${shadowsockspwd}"
    echo "--------------------------------------"
}

install_prepare_port() {
    while true
    do
    dport=$(shuf -i 9000-9999 -n 1)
    echo -e "Please enter a port for shadowsocks-libev:"
    read -p "(Default port: ${dport}):" shadowsocksport
    [ -z "${shadowsocksport}" ] && shadowsocksport=${dport}
    expr ${shadowsocksport} + 1 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
            echo "--------------------------------------"
            echo -e "[${green}Info${plain}] port = ${shadowsocksport}"
            echo "--------------------------------------"
            break
        fi
    fi
    echo -e "[${red}Error${plain}] Please enter a correct number [1-65535]"
    done
}

install_prepare_cipher(){
    while true
    do
    echo -e "Please select stream cipher for shadowsocks-libev:"

    for ((i=1;i<=${#common_ciphers[@]};i++ )); do
        hint="${common_ciphers[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "Which cipher you'd select(Default: ${common_ciphers[6]}):" pick
    [ -z "$pick" ] && pick=7
    expr ${pick} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Please enter a number"
        continue
    fi
    if [[ "$pick" -lt 1 || "$pick" -gt ${#common_ciphers[@]} ]]; then
        echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#common_ciphers[@]}"
        continue
    fi
    shadowsockscipher=${common_ciphers[$pick-1]}

    echo "--------------------------------------"
    echo -e "[${green}Info${plain}] cipher = ${shadowsockscipher}"
    echo "--------------------------------------"
    break
    done
}

install_prepare_libev_obfs(){
    if autoconf_version || centosversion 6; then
        while true
        do
        echo -e "Do you want install simple-obfs for shadowsocks-libev? [y/n]"
        read -p "(default: n):" libev_obfs
        [ -z "$libev_obfs" ] && libev_obfs=n
        case "${libev_obfs}" in
            y|Y|n|N)
            echo "--------------------------------------"
            echo -e "[${green}Info${plain}] You choose = ${libev_obfs}"
            echo "--------------------------------------"
            break
            ;;
            *)
            echo -e "[${red}Error${plain}] Please only enter [y/n]"
            ;;
        esac
        done

        if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
            while true
            do
            echo -e "Please select obfs for simple-obfs:"
            for ((i=1;i<=${#obfs_libev[@]};i++ )); do
                hint="${obfs_libev[$i-1]}"
                echo -e "${green}${i}${plain}) ${hint}"
            done
            read -p "Which obfs you'd select(Default: ${obfs_libev[0]}):" r_libev_obfs
            [ -z "$r_libev_obfs" ] && r_libev_obfs=1
            expr ${r_libev_obfs} + 1 &>/dev/null
            if [ $? -ne 0 ]; then
                echo -e "[${red}Error${plain}] Please enter a number"
                continue
            fi
            if [[ "$r_libev_obfs" -lt 1 || "$r_libev_obfs" -gt ${#obfs_libev[@]} ]]; then
                echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#obfs_libev[@]}"
                continue
            fi
            shadowsocklibev_obfs=${obfs_libev[$r_libev_obfs-1]}
            echo "--------------------------------------"
            echo -e "[${green}Info${plain}] obfs = ${shadowsocklibev_obfs}"
            echo "--------------------------------------"
            break
            done
        fi
    else
        echo -e "[${green}Info${plain}] autoconf version is less than 2.67, simple-obfs for shadowsocks-libev installation has been skipped"
    fi
}

install_prepare(){
    install_prepare_password
    install_prepare_port
    install_prepare_cipher
    install_prepare_libev_obfs
    install_shadowsocks_manager_prepare
    echo "Press any key to start or Press Ctrl+C to cancel. Please continue!"
    char=`get_char`
}

install_libsodium(){
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${cur_dir}
        download "${libsodium_file}.tar.gz" "${libsodium_url}"
        tar zxf ${libsodium_file}.tar.gz
        cd ${libsodium_file}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${libsodium_file} install failed."
            install_cleanup
            exit 1
        fi
    else
        echo -e "[${green}Info${plain}] ${libsodium_file} already installed."
    fi
}

install_mbedtls(){
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        cd ${cur_dir}
        download "${mbedtls_file}-gpl.tgz" "${mbedtls_url}"
        tar xf ${mbedtls_file}-gpl.tgz
        cd ${mbedtls_file}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${mbedtls_file} install failed."
            install_cleanup
            exit 1
        fi
    else
        echo -e "[${green}Info${plain}] ${mbedtls_file} already installed."
    fi
}

install_shadowsocks_manager(){
    cd ${cur_dir}
    if [ ! -d "/usr/local/${shadowsocks_manager_name}" ]; then
        tar zxf ${shadowsocks_manager_file}.tar.gz
        mv ${shadowsocks_manager_file} /usr/local/${shadowsocks_manager_name}
        cd /usr/local/${shadowsocks_manager_name}
        npm install --unsafe-perm
        if [ $? -eq 0 ]; then
            mkdir -p ~/.ssmgr
            config_shadowsocks_manager
            echo -e "[${green}Info${plain}] shadowsocks-manager install success!"
        else
            echo -e "[${red}Error${plain}] shadowsocks-manager install failed!"
            exit 1
        fi
        cd ${cur_dir}
    else
        echo -e "[${green}Info${plain}] shadowsocks-manager already installed."
    fi  
}


config_shadowsocks_manager(){
    cat > ~/.ssmgr/default.yml<<-EOF
type: s

shadowsocks:
  address: 127.0.0.1:6001

manager:
  address: 0.0.0.0:${manager_port}
  password: '${manager_password}'

db: 'db.sqlite'
EOF
}

install_shadowsocks_manager_prepare(){
    while true
    do
    #manager_password
    echo -e "Please enter the Manager password:"
    read -p "(Default password: 123456):" manager_password
    [ -z "${manager_password}" ] && manager_password="123456"
    expr ${manager_password} + 1 &>/dev/null

    #manager_port
    echo -e "Please enter the Manager port:"
    read -p "(Default port: 6002):" manager_port
    [ -z "${manager_port}" ] && manager_port="6002"
    expr ${manager_port} + 1 &>/dev/null

    echo -e "-----------------------------------------------------"
    echo -e "The Manager Configuration has been completed!        "
    echo -e "-----------------------------------------------------"
    echo -e "Your Manager Port      : ${manager_port}             "
    echo -e "Your Manager Password  : ${manager_password}         "
    echo -e "-----------------------------------------------------"
    break
    done
}

start_pm2_manager(){
    cd /usr/local/${shadowsocks_manager_name}

    pm2 --name "ss-libev" -f start server.js -x -- -c default.yml

    if [ $? -eq 0 ]; then
        echo -e "[${green}Info${plain}] PM2 start service success!"
    else
        echo -e "[${red}Error${plain}] PM2 start service failed!"
        exit 1
    fi

    pm2 startup > /dev/null 2>&1
    pm2 save > /dev/null 2>&1
    echo -e "[${green}Info${plain}] PM2 save service success!"
    cd ${cur_dir} 
    install_cleanup   
}

deploy_shadowsocks_libev(){
    cd ${cur_dir}
    tar zxf ${shadowsocks_libev_file}.tar.gz
    cd ${shadowsocks_libev_file}
    ./configure --prefix=/usr/local --disable-documentation && make && make install
    if [ $? -eq 0 ]; then
        chmod +x ${shadowsocks_libev_init}
        local service_name=$(basename ${shadowsocks_libev_init})
        if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
        fi
        install_shadowsocks_libev_obfs
        ldconfig

        [ -f /usr/local/bin/ss-local ] && ln -s /usr/local/bin/ss-local /usr/bin
        [ -f /usr/local/bin/ss-tunnel ] && ln -s /usr/local/bin/ss-tunnel /usr/bin
        [ -f /usr/local/bin/ss-server ] && ln -s /usr/local/bin/ss-server /usr/bin
        [ -f /usr/local/bin/ss-manager ] && ln -s /usr/local/bin/ss-manager /usr/bin
        [ -f /usr/local/bin/ss-redir ] && ln -s /usr/local/bin/ss-redir /usr/bin
        [ -f /usr/local/bin/ss-nat ] && ln -s /usr/local/bin/ss-nat /usr/bin

        ${shadowsocks_libev_init} start
        if [ $? -eq 0 ]; then

            start_pm2_manager

            echo
            echo -e "[${green}Info${plain}] ${service_name} start success!"
            echo
            echo "------------------------------------------------------------------"
            echo -e "Congratulations, shadowsocks-libev server install completed!   "
            echo -e "Your Server IP        : $(get_ip)                              "
            echo -e "Your Server Port      : ${shadowsocksport}                     "
            echo -e "Your Password         : ${shadowsockspwd}                      "
            if [ "$(command -v obfs-server)" ]; then
            echo -e "Your obfs             : ${shadowsocklibev_obfs}                "
            fi
            echo -e "Your Encryption Method: ${shadowsockscipher}                   "
            echo "---------------------------Enjoy it!------------------------------"
            echo
        else
            echo "------------------------------------------------------------------"
            echo -e "[${red}Error${plain}]  ${shadowsocks_libev_init} start failed. "
            echo "------------------------------------------------------------------"
        fi
    else
        echo
        echo -e "[${red}Error${plain}] shadowsocks-libev install failed."
        install_cleanup
        exit 1
    fi
}

install_shadowsocks_libev_obfs(){
    if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
        cd ${cur_dir}
        git clone https://github.com/shadowsocks/simple-obfs.git
        [ -d simple-obfs ] && cd simple-obfs || echo -e "[${red}Error:${plain}] Failed to git clone simple-obfs."
        git submodule update --init --recursive
        if centosversion 6; then
            if [ ! "$(command -v autoconf268)" ]; then
                echo -e "[${green}Info${plain}] Starting install autoconf268..."
                yum install -y autoconf268 > /dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf268."
            fi
            # replace command autoreconf to autoreconf268
            sed -i 's/autoreconf/autoreconf268/' autogen.sh
            # replace #include <ev.h> to #include <libev/ev.h>
            sed -i 's@^#include <ev.h>@#include <libev/ev.h>@' src/local.h
            sed -i 's@^#include <ev.h>@#include <libev/ev.h>@' src/server.h
        fi
        ./autogen.sh
        ./configure --prefix=/usr/local --disable-documentation && make && make install
        if [ ! "$(command -v obfs-server)" ]; then
            echo -e "[${red}Error${plain}] simple-obfs for shadowsocks-libev install failed."
            install_cleanup
            exit 1
        fi
        [ -f /usr/local/bin/obfs-server ] && ln -s /usr/local/bin/obfs-server /usr/bin
        [ -f /usr/local/bin/obfs-local ] && ln -s /usr/local/bin/obfs-local /usr/bin
    fi
}

install_cleanup(){
    cd ${cur_dir}
    rm -rf simple-obfs
    rm -rf ${libsodium_file} ${libsodium_file}.tar.gz
    rm -rf ${mbedtls_file} ${mbedtls_file}-gpl.tgz
    rm -rf ${shadowsocks_libev_file} ${shadowsocks_libev_file}.tar.gz
    rm -rf ${shadowsocks_manager_file} ${shadowsocks_manager_file}.tar.gz
}

install_main(){
    modify_time
    disable_selinux
    update_nodejs
    update_npm
    install_pm2
    init_swapfile
    install_prepare
    install_dependencies
    download_files
    config_shadowsocks
    if check_sys packageManager yum; then
        config_firewall
    fi

    install_libsodium
    if ! ldconfig -p | grep -wq "/usr/lib"; then
        echo "/usr/lib" > /etc/ld.so.conf.d/lib.conf
    fi
    ldconfig
    install_shadowsocks_manager
}

install_shadowsocks_libev(){
    if [ -f ${shadowsocks_libev_init} ]; then
        echo -e "[${red}Error${plain}] shadowsocks-libev has been installed."
        exit 1
    else
        install_main
        install_mbedtls
        deploy_shadowsocks_libev
    fi
}

uninstall_shadowsocks_libev(){
    if [ -f ${shadowsocks_libev_init} ]; then
        printf "Are you sure uninstall shadowsocks-libev? [y/n]\n"
        read -p "(default: n):" answer
        [ -z ${answer} ] && answer="n"
        if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
            ${shadowsocks_libev_init} status > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                ${shadowsocks_libev_init} stop
            fi
            local service_name=$(basename ${shadowsocks_libev_init})
            if check_sys packageManager yum; then
                chkconfig --del ${service_name}
            elif check_sys packageManager apt; then
                update-rc.d -f ${service_name} remove
            fi
            rm -fr $(dirname ${shadowsocks_libev_config})
            rm -f /usr/local/bin/ss-local
            rm -f /usr/local/bin/ss-tunnel
            rm -f /usr/local/bin/ss-server
            rm -f /usr/local/bin/ss-manager
            rm -f /usr/local/bin/ss-redir
            rm -f /usr/local/bin/ss-nat
            rm -f /usr/local/bin/obfs-local
            rm -f /usr/local/bin/obfs-server
            rm -f /usr/bin/ss-local
            rm -f /usr/bin/ss-tunnel
            rm -f /usr/bin/ss-server
            rm -f /usr/bin/ss-manager
            rm -f /usr/bin/ss-redir
            rm -f /usr/bin/ss-nat
            rm -f /usr/bin/obfs-local
            rm -f /usr/bin/obfs-server
            rm -f /usr/local/lib/libshadowsocks-libev.a
            rm -f /usr/local/lib/libshadowsocks-libev.la
            rm -f /usr/local/include/shadowsocks.h
            rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
            rm -f /usr/local/share/man/man1/ss-local.1
            rm -f /usr/local/share/man/man1/ss-tunnel.1
            rm -f /usr/local/share/man/man1/ss-server.1
            rm -f /usr/local/share/man/man1/ss-manager.1
            rm -f /usr/local/share/man/man1/ss-redir.1
            rm -f /usr/local/share/man/man1/ss-nat.1
            rm -f /usr/local/share/man/man8/shadowsocks-libev.8
            rm -fr /usr/local/share/doc/shadowsocks-libev
            rm -f ${shadowsocks_libev_init}

            pm2 stop ss-libev > /dev/null 2>&1
            pm2 delete ss-libev > /dev/null 2>&1
            rm -fr /usr/local/${shadowsocks_manager_name}
            rm -rf ~/.ssmgr

            echo -e "[${green}Info${plain}] shadowsocks-libev uninstall success"
        else
            echo
            echo -e "[${green}Info${plain}] shadowsocks-libev uninstall cancelled, nothing to do..."
            echo
        fi
    else
        echo -e "[${red}Error${plain}] shadowsocks-libev not installed, please check it and try again."
        exit 1
    fi
}
# Modify time zone
modify_time(){
    # set time zone
    if check_sys packageManager yum; then
       ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    elif check_sys packageManager apt; then
       ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    fi
    # status info
    if [ $? -eq 0 ]; then
        echo -e "[${green}Info${plain}] Modify the time zone success!"
    else
        echo -e "[${yellow}Warning${plain}] Modify the time zone failure!"
    fi
}
# Automatic restart system
auto_restart_system(){
    cd ${cur_dir}
    if [ -f ${shadowsocks_libev_init} ]; then
        if [ $? -eq 0 ]; then
            #hour
            echo -e "Please enter the hour now(0-23):"
            read -p "(Default hour: 5):" auto_hour
            [ -z "${auto_hour}" ] && auto_hour="5"
            expr ${auto_hour} + 1 &>/dev/null

            #minute
            echo -e "Please enter the minute now(0-59):"
            read -p "(Default hour: 30):" auto_minute
            [ -z "${auto_minute}" ] && auto_minute="30"
            expr ${auto_minute} + 1 &>/dev/null

            echo -e "[${green}Info${plain}] The time has been set, then install crontab!"

            # Install crontabs
            if check_sys packageManager yum; then
                yum install -y vixie-cron cronie
            elif check_sys packageManager apt; then
                apt-get -y update
                apt-get -y install cron
            fi

            echo "$auto_minute $auto_hour * * * root /sbin/reboot" >> /etc/crontab

            # start crontabs
            if check_sys packageManager yum; then
                chkconfig crond on
                service crond restart
            elif check_sys packageManager apt; then
                /etc/init.d/cron restart
            fi
  
            if [ $? -eq 0 ]; then
                echo -e "[${green}Info${plain}] crontab start success!"
            else
                echo -e "[${yellow}Warning${plain}] crontab start failure!"
            fi

            echo -e "[${green}Info${plain}] Has been installed successfully!"
            echo -e "------------------------------------------------------------"
            echo -e "The time for automatic restart has been set!                "
            echo -e "------------------------------------------------------------"
            echo -e "hour       : ${auto_hour}                                   "
            echo -e "minute     : ${auto_minute}                                 "
            echo -e "Restart the system at ${auto_hour}:${auto_minute} every day!"
            echo -e "------------------------------------------------------------"

        else
            echo
            echo -e "[${red}Error${plain}] Can't set automatic restart shadowsocks service!"
            exit 1
        fi

    else
        echo
        echo -e "[${red}Error${plain}] Can't find shadowsocks service"
        exit 1
    fi
}


# Initialization step
commands=(
Install\ Shadowsocks-libev
Uninstall\ Shadowsocks-libev
Auto\ Restart\ System
)

# Choose command
choose_command(){
    if ! install_check; then
        echo -e "[${red}Error${plain}] Your OS is not supported to run it!"
        echo "Please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
        exit 1
    fi

    clear
    while true
    do
    echo 
    echo -e "Welcome! Please select command to start:"
    echo -e "-------------------------------------------"
    for ((i=1;i<=${#commands[@]};i++ )); do
        hint="${commands[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    echo -e "-------------------------------------------"
    read -p "Which command you'd select(Default: ${commands[0]}):" order_num
    [ -z "$order_num" ] && order_num=1
    expr ${order_num} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo 
        echo -e "[${red}Error${plain}] Please enter a number"
        continue
    fi
    if [[ "$order_num" -lt 1 || "$order_num" -gt ${#commands[@]} ]]; then
        echo 
        echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#commands[@]}"
        continue
    fi
    break
    done

    echo -e  "[${green}Info${plain}] You select command ${order_num}"

    case $order_num in
        1)
        install_shadowsocks_libev
        ;;
        2)
        uninstall_shadowsocks_libev
        ;;
        3)
        auto_restart_system
        ;;
        *)
        exit 1
        ;;
    esac
}
# start
cd ${cur_dir}
choose_command
