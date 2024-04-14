#!/bin/bash
#
#一键部署 hysteria2
#Copyright (c) 2023 - 梦初雪

# 定义红色和重置颜色的 ANSI 转义序列
red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
no_color='\033[0m'

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    echo "请以 root 权限运行此脚本"
    exit
fi

clear
echo "##################################################"
echo -e "#            ${red}Hysteria 2 一键部署脚本${no_color}             #"
echo -e "#                 ${green}作者${no_color}: 梦初雪                   #"
echo -e "#        ${blue}电报:https://t.me/dreamfirstsnow${no_color}        #"
echo "##################################################"

# 获取 Linux 发行版信息
OS=$(awk -F= '/^ID/{print $2}' /etc/os-release)

# 根据不同的发行版，使用不同的包管理器安装 iptables 和 curl
if [[ $OS == *"ubuntu"* ]] || [[ $OS == *"debian"* ]] || [[ $OS == *"kali"* ]]; then
    sudo apt-get update && sudo apt-get install iptables curl -y
elif [[ $OS == *"centos"* ]] || [[ $OS == *"fedora"* ]] || [[ $OS == *"rhel"* ]]; then
    sudo yum update && sudo yum install iptables curl -y
elif [[ $OS == *"arch"* ]] || [[ $OS == *"manjaro"* ]]; then
    sudo pacman -Syu iptables curl
elif [[ $OS == *"opensuse"* ]]; then
    sudo zypper refresh && sudo zypper install iptables curl
else
    echo "不支持的 Linux 发行版"
    exit
fi

ip_get() {
  # 获取 eth0 网卡的 IPv4 地址，过滤掉回环地址
  ip_v4=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1')

  # 如果 eth0 网卡的 IPv4 地址为空，则获取 eth0 网卡的 IPv6 地址且安装warp，过滤掉回环地址和链接本地地址
  if [ -z "$ip_v4" ]; then
    ip_v6=$(ip -6 addr show eth0 | grep -oP '(?<=inet6\s)[\da-f:]+' | grep -v '^fe80')
    echo "$ip_v6"
  else
    echo "$ip_v4"
  fi
}

if [[ $(ip_get) == *":"* ]]; then
  # IP 地址包含 ":"，说明是 IPv6 地址，需要安装 warp
  curl -O https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh

  # 检查 curl 命令是否成功执行
  if [ $? -ne 0 ]; then
      echo -e "${red}下载 warp 安装脚本失败！${no_color}"
      exit 1
  fi

  # 执行下载的脚本
  bash menu.sh [option] [lisence/url/token]

  # 检查 bash 命令是否成功执行
  if [ $? -ne 0 ]; then
      echo -e "${red}安装warp失败！${no_color}"
      exit 1
  fi
fi

# 将发送、接收两个缓冲区都设置为 16 MB
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216

#部署Hysteria2
bash <(curl -fsSL https://get.hy2.sh/)

#设置开机启动
systemctl enable hysteria-server.service

# 如果用户没有输入端口号，生成一个随机的、未被占用的端口号
while :
  do
    # 生成一个在1024到65535之间的随机端口号
    rand_port=$(shuf -i 40000-65535 -n 1)
    # 检查端口号是否被占用
    ss -ltn | grep -q ":$rand_port "
  if [ $? -ne 0 ]; then
    break
  fi
done

# 提示用户输入端口号
printf "请输入你想要使用的端口号（如果为空则使用 \"${red}${rand_port}${no_color}\" 端口）："
read user_port

# 未输入端口号则使用随机的端口号
if [ -z "$user_port" ]; then
  user_port=$rand_port
fi

# 使用 iptables 命令放行该端口的全部流量
sudo iptables -A INPUT -p tcp --dport $user_port -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport $user_port -j ACCEPT
sudo iptables -A INPUT -p udp --dport $user_port -j ACCEPT
sudo iptables -A OUTPUT -p udp --sport $user_port -j ACCEPT

# 安装 iptables-persistent 包
sudo apt-get install iptables-persistent -y

# 保存规则
sudo bash -c "iptables-save > /etc/iptables.rules"

# 使用 netfilter-persistent 保存和加载规则
sudo netfilter-persistent save
sudo netfilter-persistent reload

# 在 /etc/rc.local 文件中添加以下内容以在系统启动时加载规则
echo "正在将 iptables 规则保存到 /etc/iptables.rules 文件，并设置系统启动时自动加载这些规则..."
echo -e '#!/bin/sh -e\n/sbin/iptables-restore < /etc/iptables.rules\nexit 0' | sudo tee /etc/rc.local

# 使 /etc/rc.local 文件可执行
sudo chmod +x /etc/rc.local

# 提示用户输入域名
printf "使用acme申请域名(填写用来申请证书的域名,如果为空则使用${red}自签证书${no_color})："
read domain

# 生成一个随机密码
rand_password=$(openssl rand -hex 18)

# 提示用户输入密码
printf "hysteria2连接密码,如果为空则使用${red}\"${rand_password}\"${no_color})："
read password

# 未输入密码则使用随机的密码
if [ -z "$password" ]; then
  password=$rand_password
fi

if [ -z "$domain" ]; then
# 如果用户没有输入域名，使用自签证书

# 创建一个临时文件
tmpfile=$(mktemp)

# 生成 EC 参数并保存到临时文件中
openssl ecparam -name prime256v1 -out "$tmpfile"

# 使用临时文件生成证书
openssl req -x509 -nodes -newkey ec:"$tmpfile" -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt -subj "/CN=www.kali.org" -days 36500

# 改变证书文件的所有者
sudo chown hysteria /etc/hysteria/server.key
sudo chown hysteria /etc/hysteria/server.crt

# 删除临时文件
rm -f "$tmpfile"

cat << EOF > /etc/hysteria/config.yaml
listen: :$user_port

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

quic:
  initStreamReceiveWindow: 8388608 
  maxStreamReceiveWindow: 8388608 
  initConnReceiveWindow: 20971520 
  maxConnReceiveWindow: 20971520 

bandwidth:
  up: 0gbps
  down: 0gbps

auth:
  type: password
  password: $password

masquerade:
  type: proxy
  proxy:
    url: https://www.kali.org
    rewriteHost: true
EOF
else
    # 如果用户输入了域名，使用ACME申请证书
cat << EOF > /etc/hysteria/config.yaml
listen: :$user_port

acme:
  domains:
    - $domain #你的域名，需要先解析到服务器ip
  email: admin@admin.com

quic:
  initStreamReceiveWindow: 8388608 
  maxStreamReceiveWindow: 8388608 
  initConnReceiveWindow: 20971520 
  maxConnReceiveWindow: 20971520 

bandwidth:
  up: 0gbps
  down: 0gbps

auth:
  type: password
  password: $password

masquerade:
  type: proxy
  proxy:
    url: https://www.kali.org
    rewriteHost: true
EOF
fi

#重启Hysteria2
sudo systemctl restart hysteria-server.service

#创建配置目录
sudo mkdir -p /root/Hysteria2

if [ -z "$domain" ]; then
  # 使用自签证书
cat << EOF > /root/Hysteria2/Hysteria2-client.yaml
server: $(ip_get):$user_port

auth: $password

tls:
  sni: www.kali.org
  insecure: true

quic:
  initStreamReceiveWindow: 8388608 
  maxStreamReceiveWindow: 8388608 
  initConnReceiveWindow: 20971520 
  maxConnReceiveWindow: 20971520 

fastOpen: true

socks5:
  listen: 127.0.0.1:5080

transport:
  udp:
    hopInterval: 30s 
EOF
cat <<EOF > /root/Hysteria2/clash-meta.yaml
mixed-port: 7890
external-controller: 127.0.0.1:9090
allow-lan: false
mode: rule
log-level: debug
ipv6: true
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
    - 1.1.1.1
    - 114.114.114.114
proxies:
  - name: Hysteria2
    type: hysteria2
    server: $(ip_get)
    port: $user_port
    password: $password
    sni: www.kali.org
    skip-cert-verify: true
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Hysteria2
      
rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
  link="hysteria2://$password@[$(ip_get)]:$user_port/?insecure=1&sni=www.kali.org#Hysteria2"
else
  # 使用acme申请的证书
cat << EOF > /root/Hysteria2/Hysteria2-client.yaml
server: $(ip_get):$user_port

auth: $password

tls:
  sni: $domain
  insecure: false

quic:
  initStreamReceiveWindow: 8388608 
  maxStreamReceiveWindow: 8388608 
  initConnReceiveWindow: 20971520 
  maxConnReceiveWindow: 20971520 

fastOpen: true

socks5:
  listen: 127.0.0.1:5080

transport:
  udp:
    hopInterval: 30s 
EOF
cat <<EOF > /root/Hysteria2/clash-meta.yaml
mixed-port: 7890
external-controller: 127.0.0.1:9090
allow-lan: false
mode: rule
log-level: debug
ipv6: true
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  nameserver:
    - 8.8.8.8
    - 1.1.1.1
    - 114.114.114.114
proxies:
  - name: Hysteria2
    type: hysteria2
    server: $(ip_get)
    port: $user_port
    password: $password
    sni: $domain
    skip-cert-verify: false
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Hysteria2
      
rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF
  link="hysteria2://$password@[$domain]:$user_port/?insecure=0&sni=$domain#Hysteria2"
fi

# 打印分享链接
echo -e "${green}您的Hysteria2的分享链接为：$link${no_color}"
# 将分享链接写入文件
echo "$link" > /root/Hysteria2/分享链接.txt
echo "所有配置文件已保存到 /root/Hysteria2 目录中"

#导出日志
journalctl -u hysteria-server.service >> /root/Hysteria2/Hysteria2_Server.log
