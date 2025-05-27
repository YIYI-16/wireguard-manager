#!/bin/bash

# 配置变量
SERVER_CONFIG="/etc/wireguard/wg0.conf"
CLIENT_DIR="/etc/wireguard/clients"
CONFIG_FILE="/etc/wireguard/wg_manager_config"
SERVER_IP="10.0.0.1"
CLIENT_IP_START="10.0.0.2"
DEFAULT_VPN_PORT="51820"
SERVER_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)

# 颜色定义，让输出更美观
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 检查是否为root用户 - WireGuard配置需要管理员权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本需要root权限运行${NC}"
        echo "请使用: sudo $0"
        exit 1
    fi
}

# 显示带颜色的状态信息
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[提示]${NC} $1"
}

# 保存配置到文件
save_config() {
    cat > "$CONFIG_FILE" << EOF
VPN_PORT=$VPN_PORT
DDNS_DOMAIN=$DDNS_DOMAIN
ENDPOINT_TYPE=$ENDPOINT_TYPE
PUBLIC_IP=$PUBLIC_IP
EOF
}

# 加载配置文件
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        return 0
    else
        return 1
    fi
}

# 获取公网IP地址
get_public_ip() {
    local public_ip=""
    
    # 尝试多个服务获取公网IP
    for service in "curl -s ifconfig.me" "curl -s ipinfo.io/ip" "curl -s icanhazip.com" "curl -s ident.me"; do
        public_ip=$(eval $service 2>/dev/null)
        if [[ $public_ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "$public_ip"
            return 0
        fi
    done
    
    return 1
}

# 验证IP地址格式
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        local parts=($ip)
        for part in "${parts[@]}"; do
            if (( part > 255 )); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# 验证域名格式
validate_domain() {
    local domain=$1
    if [[ $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi
    return 1
}

# 验证端口号
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && [ $port -ge 1 ] && [ $port -le 65535 ]; then
        return 0
    fi
    return 1
}

# 配置端口和域名
configure_connection() {
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           连接配置设置                 ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo ""
    
    # 配置端口
    while true; do
        echo -e "${CYAN}请设置WireGuard监听端口:${NC}"
        read -p "输入端口号 (直接回车使用默认 $DEFAULT_VPN_PORT): " input_port
        
        if [ -z "$input_port" ]; then
            VPN_PORT=$DEFAULT_VPN_PORT
            break
        elif validate_port "$input_port"; then
            VPN_PORT=$input_port
            break
        else
            print_error "无效的端口号，请输入1-65535之间的数字"
        fi
    done
    
    print_status "已设置端口: $VPN_PORT"
    echo ""
    
    # 配置连接方式
    while true; do
        echo -e "${CYAN}请选择客户端连接方式:${NC}"
        echo "  1) 使用公网IP地址"
        echo "  2) 使用局域网IP地址 (需要客户端在同一网络)"
        echo "  3) 使用自定义域名/DDNS"
        echo ""
        read -p "请选择 (1-3): " endpoint_choice
        
        case $endpoint_choice in
            1)
                print_status "正在获取公网IP地址..."
                PUBLIC_IP=$(get_public_ip)
                if [ $? -eq 0 ] && [ -n "$PUBLIC_IP" ]; then
                    DDNS_DOMAIN=$PUBLIC_IP
                    ENDPOINT_TYPE="public_ip"
                    print_status "检测到公网IP: $PUBLIC_IP"
                    break
                else
                    print_error "无法获取公网IP地址，请检查网络连接或选择其他方式"
                fi
                ;;
            2)
                # 获取本机局域网IP
                local_ip=$(ip route get 8.8.8.8 | grep -oP 'src \K\S+' 2>/dev/null)
                if [ -z "$local_ip" ]; then
                    local_ip=$(hostname -I | awk '{print $1}')
                fi
                
                if [ -n "$local_ip" ]; then
                    print_info "检测到本机IP: $local_ip"
                    echo "您可以直接使用检测到的IP，或手动输入其他局域网IP"
                    read -p "输入局域网IP地址 (直接回车使用 $local_ip): " input_ip
                    
                    if [ -z "$input_ip" ]; then
                        DDNS_DOMAIN=$local_ip
                    else
                        if validate_ip "$input_ip"; then
                            DDNS_DOMAIN=$input_ip
                        else
                            print_error "无效的IP地址格式"
                            continue
                        fi
                    fi
                else
                    read -p "请输入局域网IP地址: " input_ip
                    if validate_ip "$input_ip"; then
                        DDNS_DOMAIN=$input_ip
                    else
                        print_error "无效的IP地址格式"
                        continue
                    fi
                fi
                
                ENDPOINT_TYPE="local_ip"
                PUBLIC_IP=$DDNS_DOMAIN
                print_status "已设置局域网IP: $DDNS_DOMAIN"
                print_warning "注意: 使用局域网IP时，客户端必须在同一网络内才能连接"
                break
                ;;
            3)
                read -p "请输入自定义域名或DDNS地址: " input_domain
                if [ -n "$input_domain" ] && validate_domain "$input_domain"; then
                    DDNS_DOMAIN=$input_domain
                    ENDPOINT_TYPE="custom_domain"
                    # 尝试解析域名获取IP
                    resolved_ip=$(nslookup "$input_domain" 2>/dev/null | grep -A1 "Name:" | tail -n1 | awk '{print $2}')
                    if validate_ip "$resolved_ip"; then
                        PUBLIC_IP=$resolved_ip
                        print_status "域名解析成功: $input_domain -> $resolved_ip"
                    else
                        print_warning "无法解析域名，请确保域名配置正确"
                        PUBLIC_IP=""
                    fi
                    break
                else
                    print_error "无效的域名格式"
                fi
                ;;
            *)
                print_error "无效选项，请选择1-3"
                ;;
        esac
    done
    
    echo ""
    print_status "连接配置完成:"
    print_status "  端口: $VPN_PORT"
    print_status "  连接地址: $DDNS_DOMAIN"
    print_status "  连接类型: $ENDPOINT_TYPE"
    echo ""
    
    # 保存配置
    save_config
    
    read -p "按回车键继续安装..."
}

# 安装WireGuard - 检测系统版本并使用合适的包管理器
install_wireguard() {
    print_status "开始安装 WireGuard..."
    
    # 检查是否已经配置过
    if ! load_config; then
        configure_connection
    else
        print_status "使用已保存的配置:"
        print_status "  端口: $VPN_PORT"
        print_status "  连接地址: $DDNS_DOMAIN"
        print_status "  连接类型: $ENDPOINT_TYPE"
        echo ""
        read -p "是否重新配置连接设置? (y/n): " reconfig
        if [[ $reconfig =~ ^[Yy]$ ]]; then
            configure_connection
        fi
    fi
    
    # 更新软件包列表
    apt update
    
    # 安装WireGuard和相关工具
    apt install -y wireguard wireguard-tools qrencode
    
    if [ $? -eq 0 ]; then
        print_status "WireGuard 安装成功"
    else
        print_error "WireGuard 安装失败"
        exit 1
    fi
    
    # 启用IP转发 - 这是VPN服务器的关键配置
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # 创建客户端配置存储目录
    mkdir -p "$CLIENT_DIR"
    
    print_status "生成服务器密钥对..."
    # 生成服务器的私钥和公钥
    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
    
    # 创建服务器配置文件
    create_server_config
    
    # 配置防火墙规则，允许VPN流量通过
    setup_firewall
    
    # 启动并启用WireGuard服务
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    print_status "WireGuard 服务器安装并配置完成！"
    print_status "服务器公钥: $SERVER_PUBLIC_KEY"
    
    # 显示连接信息摘要
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           安装完成摘要                 ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    echo -e "端口: ${CYAN}$VPN_PORT${NC}"
    echo -e "连接地址: ${CYAN}$DDNS_DOMAIN${NC}"
    case $ENDPOINT_TYPE in
        "public_ip")
            echo -e "连接类型: ${CYAN}公网IP${NC}"
            ;;
        "local_ip")
            echo -e "连接类型: ${CYAN}局域网IP${NC}"
            echo -e "${YELLOW}注意: 客户端需在同一网络内${NC}"
            ;;
        "custom_domain")
            echo -e "连接类型: ${CYAN}自定义域名${NC}"
            ;;
    esac
    echo ""
}

# 创建服务器配置文件
create_server_config() {
    cat > "$SERVER_CONFIG" << EOF
[Interface]
# 服务器私钥
PrivateKey = $SERVER_PRIVATE_KEY
# 服务器在VPN网络中的IP地址
Address = $SERVER_IP/24
# VPN服务监听端口
ListenPort = $VPN_PORT
# 启动后执行的命令 - 配置NAT转发
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_INTERFACE -j MASQUERADE
# 关闭前执行的命令 - 清理NAT规则
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_INTERFACE -j MASQUERADE

EOF
    print_status "服务器配置文件已创建: $SERVER_CONFIG"
}

# 配置防火墙 - 开放WireGuard端口
setup_firewall() {
    print_status "配置防火墙规则..."
    
    # 使用ufw防火墙（Ubuntu/Debian默认）
    if command -v ufw >/dev/null 2>&1; then
        ufw allow $VPN_PORT/udp
        print_status "UFW防火墙规则已添加 (端口 $VPN_PORT/udp)"
    fi
    
    # 使用iptables直接配置（通用方法）
    iptables -A INPUT -p udp --dport $VPN_PORT -j ACCEPT
    
    # 保存iptables规则
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
}

# 获取下一个可用的客户端IP地址
get_next_client_ip() {
    local base_ip="10.0.0"
    local start_num=2
    local current_num=$start_num
    
    # 检查已使用的IP地址，避免重复分配
    while true; do
        local test_ip="$base_ip.$current_num"
        
        # 检查服务器配置文件中是否已存在此IP
        if ! grep -q "AllowedIPs = $test_ip/32" "$SERVER_CONFIG" 2>/dev/null; then
            echo "$test_ip"
            return
        fi
        
        current_num=$((current_num + 1))
        
        # 防止无限循环，最多支持250个客户端
        if [ $current_num -gt 254 ]; then
            print_error "已达到最大客户端数量限制"
            exit 1
        fi
    done
}

# 创建新的客户端配置
create_client() {
    # 加载配置
    if ! load_config; then
        print_error "请先安装 WireGuard 服务器"
        return
    fi
    
    print_status "创建新的WireGuard客户端..."
    
    # 获取客户端名称
    read -p "请输入客户端名称 (例如: phone, laptop): " CLIENT_NAME
    
    if [ -z "$CLIENT_NAME" ]; then
        print_error "客户端名称不能为空"
        return
    fi
    
    # 检查客户端是否已存在
    if [ -f "$CLIENT_DIR/$CLIENT_NAME.conf" ]; then
        print_error "客户端 '$CLIENT_NAME' 已存在"
        return
    fi
    
    # 生成客户端密钥对
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    
    # 自动分配客户端IP
    CLIENT_IP=$(get_next_client_ip)
    
    print_status "为客户端分配IP地址: $CLIENT_IP"
    
    # 获取服务器公钥
    SERVER_PUBLIC_KEY=$(grep PrivateKey "$SERVER_CONFIG" | cut -d' ' -f3 | wg pubkey)
    
    # 创建客户端配置文件
    cat > "$CLIENT_DIR/$CLIENT_NAME.conf" << EOF
[Interface]
# 客户端私钥
PrivateKey = $CLIENT_PRIVATE_KEY
# 客户端在VPN网络中的IP地址
Address = $CLIENT_IP/24
# DNS服务器 - 使用公共DNS
DNS = 119.29.29.29, 8.8.8.8, 223.5.5.5

[Peer]
# 服务器公钥
PublicKey = $SERVER_PUBLIC_KEY
# 服务器地址和端口
Endpoint = $DDNS_DOMAIN:$VPN_PORT
# 允许的IP范围 - 仅局域网流经VPN
AllowedIPs = 192.168.0.0/16, 10.0.0.0/24, 172.16.0.0/12
# 保持连接活跃
PersistentKeepalive = 25
EOF

    # 将客户端添加到服务器配置
    cat >> "$SERVER_CONFIG" << EOF

# 客户端: $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP/32
EOF

    # 重启WireGuard服务以应用新配置
    systemctl restart wg-quick@wg0
    
    print_status "客户端 '$CLIENT_NAME' 创建成功！"
    print_status "配置文件位置: $CLIENT_DIR/$CLIENT_NAME.conf"
    print_status "客户端IP: $CLIENT_IP"
    
    # 显示连接信息
    echo ""
    print_info "连接信息:"
    print_info "  服务器地址: $DDNS_DOMAIN"
    print_info "  端口: $VPN_PORT"
    if [ "$ENDPOINT_TYPE" = "local_ip" ]; then
        print_warning "  注意: 使用局域网IP，客户端需在同一网络内"
    fi
    
    # 询问是否生成二维码
    read -p "是否生成二维码用于手机客户端? (y/n): " generate_qr
    if [[ $generate_qr =~ ^[Yy]$ ]]; then
        generate_qr_code "$CLIENT_NAME"
    fi
    
    # 显示客户端配置内容
    echo ""
    print_status "客户端配置内容:"
    echo "----------------------------------------"
    cat "$CLIENT_DIR/$CLIENT_NAME.conf"
    echo "----------------------------------------"
}

# 生成二维码 - 方便手机客户端扫描导入
generate_qr_code() {
    local client_name="$1"
    local config_file="$CLIENT_DIR/$client_name.conf"
    
    if [ ! -f "$config_file" ]; then
        print_error "客户端配置文件不存在: $config_file"
        return
    fi
    
    print_status "生成二维码..."
    qrencode -t ansiutf8 < "$config_file"
    
    # 同时保存二维码到文件
    qrencode -t png -o "$CLIENT_DIR/${client_name}_qr.png" < "$config_file"
    print_status "二维码已保存到: $CLIENT_DIR/${client_name}_qr.png"
}

# 列出所有客户端
list_clients() {
    print_status "当前所有客户端:"
    echo ""
    
    if [ ! -d "$CLIENT_DIR" ] || [ -z "$(ls -A "$CLIENT_DIR" 2>/dev/null)" ]; then
        print_warning "暂无客户端"
        return
    fi
    
    # 显示表格头部
    printf "%-20s %-15s %-10s\n" "客户端名称" "IP地址" "状态"
    echo "=================================================="
    
    # 遍历所有客户端配置文件
    for config_file in "$CLIENT_DIR"/*.conf; do
        if [ -f "$config_file" ]; then
            local client_name=$(basename "$config_file" .conf)
            local client_ip=$(grep "Address" "$config_file" | cut -d' ' -f3 | cut -d'/' -f1)
            
            # 检查客户端是否在服务器配置中
            if grep -q "$client_ip/32" "$SERVER_CONFIG"; then
                local status="活跃"
            else
                local status="已禁用"
            fi
            
            printf "%-20s %-15s %-10s\n" "$client_name" "$client_ip" "$status"
        fi
    done
}

# 删除客户端
remove_client() {
    print_status "删除客户端配置"
    
    # 先显示现有客户端
    list_clients
    echo ""
    
    read -p "请输入要删除的客户端名称: " CLIENT_NAME
    
    if [ -z "$CLIENT_NAME" ]; then
        print_error "客户端名称不能为空"
        return
    fi
    
    local config_file="$CLIENT_DIR/$CLIENT_NAME.conf"
    
    if [ ! -f "$config_file" ]; then
        print_error "客户端 '$CLIENT_NAME' 不存在"
        return
    fi
    
    # 获取客户端IP用于从服务器配置中删除
    local client_ip=$(grep "Address" "$config_file" | cut -d' ' -f3 | cut -d'/' -f1)
    
    # 确认删除
    read -p "确定要删除客户端 '$CLIENT_NAME' ($client_ip) 吗? (y/n): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        print_status "取消删除操作"
        return
    fi
    
    # 从服务器配置中移除客户端相关配置
    # 使用临时文件来安全地编辑配置
    local temp_file=$(mktemp)
    local skip_next=false
    local in_peer_section=false
    
    while IFS= read -r line; do
        if [[ $line =~ ^#.*客户端:.*$CLIENT_NAME ]]; then
            # 找到客户端注释行，标记开始跳过
            skip_next=true
            continue
        elif [[ $line =~ ^\[Peer\]$ ]] && $skip_next; then
            # 进入对应的Peer段
            in_peer_section=true
            continue
        elif [[ $line =~ ^AllowedIPs.*$client_ip/32 ]] && $in_peer_section; then
            # 找到对应的AllowedIPs行，跳过并结束
            skip_next=false
            in_peer_section=false
            continue
        elif [[ $line =~ ^\[.*\]$ ]] && $in_peer_section; then
            # 遇到新的段落，结束跳过
            skip_next=false
            in_peer_section=false
            echo "$line" >> "$temp_file"
        elif ! $skip_next && ! $in_peer_section; then
            # 保留其他行
            echo "$line" >> "$temp_file"
        fi
    done < "$SERVER_CONFIG"
    
    # 替换原配置文件
    mv "$temp_file" "$SERVER_CONFIG"
    
    # 删除客户端配置文件和二维码
    rm -f "$config_file"
    rm -f "$CLIENT_DIR/${CLIENT_NAME}_qr.png"
    
    # 重启WireGuard服务
    systemctl restart wg-quick@wg0
    
    print_status "客户端 '$CLIENT_NAME' 已删除"
}

# 显示服务器状态
show_status() {
    print_status "WireGuard 服务器状态:"
    echo ""
    
    # 加载配置
    if load_config; then
        echo "配置信息:"
        echo "  端口: $VPN_PORT"
        echo "  连接地址: $DDNS_DOMAIN"
        case $ENDPOINT_TYPE in
            "public_ip")
                echo "  连接类型: 公网IP"
                ;;
            "local_ip")
                echo "  连接类型: 局域网IP"
                ;;
            "custom_domain")
                echo "  连接类型: 自定义域名"
                ;;
        esac
        echo ""
    fi
    
    # 检查服务状态
    if systemctl is-active --quiet wg-quick@wg0; then
        echo -e "服务状态: ${GREEN}运行中${NC}"
    else
        echo -e "服务状态: ${RED}已停止${NC}"
    fi
    
    # 显示网络接口信息
    if ip link show wg0 >/dev/null 2>&1; then
        echo -e "网络接口: ${GREEN}wg0 已创建${NC}"
        echo "接口详情:"
        ip addr show wg0 | sed 's/^/  /'
    else
        echo -e "网络接口: ${RED}wg0 未创建${NC}"
    fi
    
    echo ""
    echo "服务器配置:"
    echo "  服务器IP: $SERVER_IP"
    
    # 显示连接的客户端
    echo ""
    print_status "当前连接的客户端:"
    if command -v wg >/dev/null 2>&1; then
        wg show 2>/dev/null || echo "  暂无活跃连接"
    else
        echo "  WireGuard工具未安装"
    fi
}

# 重启WireGuard服务
restart_service() {
    print_status "重启 WireGuard 服务..."
    systemctl restart wg-quick@wg0
    
    if systemctl is-active --quiet wg-quick@wg0; then
        print_status "WireGuard 服务重启成功"
    else
        print_error "WireGuard 服务重启失败"
        systemctl status wg-quick@wg0
    fi
}

# 重置WireGuard配置
reset_wireguard() {
    print_warning "警告: 此操作将删除所有WireGuard配置和客户端！"
    read -p "确定要重置吗? 输入 'RESET' 确认: " confirm
    
    if [ "$confirm" != "RESET" ]; then
        print_status "取消重置操作"
        return
    fi
    
    print_status "开始重置 WireGuard..."
    
    # 停止服务
    systemctl stop wg-quick@wg0 2>/dev/null || true
    systemctl disable wg-quick@wg0 2>/dev/null || true
    
    # 删除配置文件
    rm -f "$SERVER_CONFIG"
    rm -rf "$CLIENT_DIR"
    rm -f "$CONFIG_FILE"
    
    # 删除网络接口
    ip link delete wg0 2>/dev/null || true
    
    print_status "WireGuard 已重置，请重新安装配置"
}

# 完全卸载WireGuard
uninstall_wireguard() {
    print_warning "警告: 此操作将完全卸载WireGuard！"
    read -p "确定要卸载吗? 输入 'UNINSTALL' 确认: " confirm
    
    if [ "$confirm" != "UNINSTALL" ]; then
        print_status "取消卸载操作"
        return
    fi
    
    print_status "开始卸载 WireGuard..."
    
    # 加载配置以获取端口信息
    load_config
    
    # 停止并禁用服务
    systemctl stop wg-quick@wg0 2>/dev/null || true
    systemctl disable wg-quick@wg0 2>/dev/null || true
    
    # 删除网络接口
    ip link delete wg0 2>/dev/null || true
    
    # 删除配置文件
    rm -rf "/etc/wireguard"
    
    # 卸载软件包
    apt remove --purge -y wireguard wireguard-tools qrencode
    apt autoremove -y
    
    # 清理防火墙规则
    if [ -n "$VPN_PORT" ]; then
        ufw delete allow $VPN_PORT/udp 2>/dev/null || true
    fi
    
    print_status "WireGuard 已完全卸载"
}

# 修改连接配置
modify_connection() {
    if ! load_config; then
        print_error "请先安装 WireGuard 服务器"
        return
    fi
    
    print_status "当前连接配置:"
    print_status "  端口: $VPN_PORT"
    print_status "  连接地址: $DDNS_DOMAIN"
    print_status "  连接类型: $ENDPOINT_TYPE"
    echo ""
    
    print_warning "修改连接配置将影响所有现有客户端连接"
    read -p "确定要修改吗? (y/n): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        print_status "取消修改操作"
        return
    fi
    
    # 备份当前配置
    OLD_VPN_PORT=$VPN_PORT
    OLD_DDNS_DOMAIN=$DDNS_DOMAIN
    
    # 重新配置
    configure_connection
    
    # 更新服务器配置文件中的端口
    if [ "$OLD_VPN_PORT" != "$VPN_PORT" ]; then
        sed -i "s/^ListenPort = $OLD_VPN_PORT/ListenPort = $VPN_PORT/" "$SERVER_CONFIG"
        
        # 更新防火墙规则
        if command -v ufw >/dev/null 2>&1; then
            ufw delete allow $OLD_VPN_PORT/udp 2>/dev/null || true
            ufw allow $VPN_PORT/udp
        fi
        
        print_status "已更新服务器端口配置"
    fi
    
    # 更新所有客户端配置文件
    if [ "$OLD_DDNS_DOMAIN" != "$DDNS_DOMAIN" ] || [ "$OLD_VPN_PORT" != "$VPN_PORT" ]; then
        print_status "正在更新客户端配置文件..."
        
        for config_file in "$CLIENT_DIR"/*.conf; do
            if [ -f "$config_file" ]; then
                local client_name=$(basename "$config_file" .conf)
                sed -i "s/^Endpoint = .*/Endpoint = $DDNS_DOMAIN:$VPN_PORT/" "$config_file"
                print_status "已更新客户端: $client_name"
            fi
        done
    fi
    
    # 重启服务
    systemctl restart wg-quick@wg0
    
    print_status "连接配置修改完成！"
    print_warning "请重新分发客户端配置文件或重新生成二维码"
}

# 显示主菜单
show_menu() {
    clear
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════╗"
    echo "║        WireGuard 管理脚本              ║"
    echo "╚════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "请选择操作："
    echo ""
    echo "  1) 安装 WireGuard"
    echo "  2) 创建客户端"
    echo "  3) 列出客户端"
    echo "  4) 删除客户端"
    echo "  5) 生成二维码"
    echo "  6) 查看状态"
    echo "  7) 重启服务"
    echo "  8) 修改连接配置"
    echo "  9) 重置配置"
    echo " 10) 卸载 WireGuard"
    echo "  0) 退出"
    echo ""
}

# 生成现有客户端的二维码
generate_existing_qr() {
    print_status "为现有客户端生成二维码"
    
    list_clients
    echo ""
    
    read -p "请输入客户端名称: " CLIENT_NAME
    
    if [ -z "$CLIENT_NAME" ]; then
        print_error "客户端名称不能为空"
        return
    fi
    
    if [ ! -f "$CLIENT_DIR/$CLIENT_NAME.conf" ]; then
        print_error "客户端 '$CLIENT_NAME' 不存在"
        return
    fi
    
    generate_qr_code "$CLIENT_NAME"
}

# 主程序循环
main() {
    check_root
    
    while true; do
        show_menu
        read -p "请输入选项 (0-10): " choice
        
        case $choice in
            1)
                install_wireguard
                read -p "按回车键继续..."
                ;;
            2)
                if [ ! -f "$SERVER_CONFIG" ]; then
                    print_error "请先安装 WireGuard 服务器"
                else
                    create_client
                fi
                read -p "按回车键继续..."
                ;;
            3)
                list_clients
                read -p "按回车键继续..."
                ;;
            4)
                if [ ! -f "$SERVER_CONFIG" ]; then
                    print_error "请先安装 WireGuard 服务器"
                else
                    remove_client
                fi
                read -p "按回车键继续..."
                ;;
            5)
                generate_existing_qr
                read -p "按回车键继续..."
                ;;
            6)
                show_status
                read -p "按回车键继续..."
                ;;
            7)
                restart_service
                read -p "按回车键继续..."
                ;;
            8)
                modify_connection
                read -p "按回车键继续..."
                ;;
            9)
                reset_wireguard
                read -p "按回车键继续..."
                ;;
            10)
                uninstall_wireguard
                read -p "按回车键继续..."
                ;;
            0)
                print_status "感谢使用 WireGuard 管理脚本！"
                exit 0
                ;;
            *)
                print_error "无效选项，请选择 0-10"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 运行主程序
main