# WireGuard VPN 管理脚本

![GitHub License](https://img.shields.io/github/license/YIYI-16/wireguard-manager)
![GitHub top language](https://img.shields.io/github/languages/top/YIYI-16/wireguard-manager)


本项目是一个基于 Bash 的 WireGuard VPN 服务器管理脚本，提供便捷的安装配置和客户端管理功能。

## ✨ 核心功能

- 🚀 **一键部署**：全自动安装 WireGuard 及相关依赖
- 🔑 **密钥管理**：自动生成服务器/客户端密钥对
- 📱 **客户端管理**：支持创建/删除客户端配置
- 📡 **DDNS 支持**：内置动态域名配置
- 📶 **二维码生成**：手机端扫码快速配置
- 🛡️ **防火墙配置**：自动配置 ufw/iptables 规则
- 📊 **状态监控**：实时查看连接状态和流量统计

## 🚀 快速开始

### 环境要求
- Linux 系统（推荐 Ubuntu/Debian/CentOS）
- Root 权限
- Bash 4.0+

### 一键安装脚本
```bash
curl -fsSL https://raw.githubusercontent.com/YIYI-16/wireguard-manager/main/deploy.sh -o deploy.sh && bash deploy.sh
```

### 源码安装
```bash
# 克隆仓库
git clone https://github.com/YIYI-16/wireguard-manager.git
cd wireguard-manager

# 授予执行权限
chmod +x deploy.sh

# 启动管理脚本
sudo ./deploy.sh
```

## 🖥️ 使用说明

### 主菜单界面
```text
╔════════════════════════════════════════╗
║        WireGuard 管理脚本               ║
╚════════════════════════════════════════╝

1) 安装 WireGuard
2) 创建客户端
3) 列出客户端
4) 删除客户端
5) 生成二维码
6) 查看状态
7) 重启服务
8) 重置配置
9) 卸载 WireGuard
0) 退出
```

### 常用功能示例
**创建客户端**：
```bash
请输入客户端名称 (例如: phone, laptop):
分配IP地址:
配置文件生成位置: /etc/wireguard/clients/office-pc.conf
```

## 🛠️ 高级配置

### 网络拓扑
```text
                +-----------------+
                |   VPN Server    |
                | (10.0.0.1/24)   |
                +-------+---------+
                        |
         +--------------+--------------+
         |              |              |
+--------+------+ +-----+-------+ +----+--------+
|  Client 1     | |  Client 2   | |  Client 3   |
| (10.0.0.2)    | | (10.0.0.3)  | | (10.0.0.4)  |
+---------------+ +-------------+ +-------------+
```

### 防火墙规则
脚本自动配置以下规则：
```bash
# 开放VPN端口（默认51820）
ufw allow 51820/udp
```

## 📌 注意事项

1. 建议使用 **Ubuntu 20.04 LTS** 以上版本
2. 默认使用 **119.29.29.29** 和 **8.8.8.8** 作为DNS
3. 客户端IP池范围为 **10.0.0.2-254**
4. 配置文件自动备份在 `/etc/wireguard/backups`

## 🤝 参与贡献

欢迎通过 Issue 提交问题或 Pull Request 贡献代码：
1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/your-feature`)
3. 提交更改 (`git commit -m 'Add some feature'`)
4. 推送分支 (`git push origin feature/your-feature`)
5. 创建 Pull Request

## 📜 许可证

本项目采用 MIT 许可证 - 详情请见 [LICENSE](LICENSE) 文件

> 本工具仅供学习交流使用，禁止用于任何非法用途。使用者应对自身行为负全部责任。[1][2]
