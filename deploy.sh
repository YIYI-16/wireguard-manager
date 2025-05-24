#!/bin/bash

# 下载 WireGuard 管理脚本到本地系统目录
curl -fsSL -o /usr/local/bin/wireguard-manager.sh https://raw.githubusercontent.com/YIYI-16/wireguard-manager/main/wireguard-manager.sh

# 给下载的脚本添加执行权限
chmod +x /usr/local/bin/wireguard-manager.sh

# 创建快捷访问命令 'wireguard'
 tee /usr/local/bin/wireguard << 'EOF'
#!/bin/bash
sudo /usr/local/bin/wireguard-manager.sh
EOF

chmod +x /usr/local/bin/wireguard
/usr/local/bin/wireguard-manager.sh