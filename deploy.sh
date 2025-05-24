#!/bin/bash

sudo curl -fsSL -o /usr/local/bin/wireguard_manager.sh https://raw.githubusercontent.com/YIYI-16/wireguard-manager/main/wireguard_manager.sh
sudo chmod +x /usr/local/bin/wireguard_manager.sh
sudo tee /usr/local/bin/wireguard << 'EOF'
#!/bin/bash
sudo /usr/local/bin/wireguard_manager.sh
EOF

sudo chmod +x /usr/local/bin/wireguard
