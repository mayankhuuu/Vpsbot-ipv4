```markdown
# DXD VPS Manager Bot

A Discord bot that deploys and manages **LXC-based VPS containers**, with full
`systemctl` support, **direct root SSH access** (real IP, port, username, and
root password — works with Termius, PuTTY, or plain `ssh`), a **redeem code**
system, **SSHX browser-based SSH**, **TMATE backup SSH**, and a **multi-node**
system so you can host VPS across more than one physical server, all from one bot.

---

## ✨ Features

- 🐉 1-click VPS deploy from Discord (`/deploy` or `/create`)
- 🖥 Real Ubuntu/Debian containers with full `systemd` support
- 🔑 Direct root SSH — real IPv4 + NAT port + root password sent to the user's DM
- 🌐 **SSHX Browser SSH** — access your VPS from any browser without SSH client
- 🔄 **TMATE Backup SSH** — fallback access if direct SSH fails
- 🎟️ **Redeem codes** — generate one-time codes that let members claim their own VPS
- 📡 **Multi-node support** — connect other physical servers as "nodes" and deploy VPS on any of them
- 📊 Live status: `DXD | {n} VPS Running`
- 🔄 Start / stop / restart / reinstall / regen-ssh commands
- ⏰ Optional auto-expiry / auto-suspend
- 🛡 Admin-only management commands
- 🚫 **Anti-mining protection** — automatically detects and suspends mining activity
- 👑 **Admin Deploy** — admins can create VPS for any user

---

## 📋 Requirements

- A Linux server (Ubuntu 22.04/24.04 recommended) with a **public IP address** — this is your **main bot server**
- **LXC** installed and running on it
- **Python 3.10+**
- A **Discord Bot Token**
- (Optional) One or more **extra servers** if you want to run VPS across multiple machines ("nodes")

---

## 🚀 Setup — Main Bot — Step by Step

### 1. Clone the repository

```bash
git clone https://github.com/mayankhuuu/Vpsbot-ipv4.git
cd Vpsbot-ipv4
```

2. Install LXC

```bash
sudo apt-get update
sudo apt-get install -y lxc lxc-templates lxc-utils bridge-utils
```

3. Configure LXC Network

```bash
# Create LXC bridge
sudo brctl addbr lxcbr0
sudo ip addr add 10.0.3.1/24 dev lxcbr0
sudo ip link set lxcbr0 up

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf

# Configure LXC
sudo tee /etc/default/lxc-net > /dev/null <<'EOF'
USE_LXC_BRIDGE="true"
LXC_BRIDGE="lxcbr0"
LXC_ADDR="10.0.3.1"
LXC_NETMASK="255.255.255.0"
LXC_NETWORK="10.0.3.0/24"
LXC_DHCP_RANGE="10.0.3.2,10.0.3.254"
LXC_DHCP_MAX="253"
EOF

sudo systemctl restart lxc-net
sudo systemctl enable lxc-net
```

4. Install Python & dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

5. Create your Discord Bot

1. https://discord.com/developers/applications → New Application
2. Bot → Add Bot → enable Server Members Intent + Message Content Intent
3. Reset Token → copy it
4. OAuth2 → URL Generator → scopes bot, applications.commands; permissions Send Messages, Embed Links, Use Slash Commands
5. Open the generated URL and invite the bot to your server

6. Configure .env

```bash
cp .env.example .env
nano .env
```

Fill in at minimum:

```env
DISCORD_TOKEN=your_bot_token_here
ADMIN_ROLE_ID=your_admin_role_id
ADMIN_USER_IDS=your_discord_user_id
SERVER_IP=your_server_public_ip
```

Find your public IP with: curl -4 ifconfig.me

7. Open firewall ports

```bash
sudo ufw allow 20000:29999/tcp   # SSH range for deployed VPS
sudo ufw allow 8788/tcp          # AGENT_PORT — for remote nodes to connect
```

Also open both ranges in your cloud provider's Security Group / Firewall panel
if you're on AWS, GCP, Azure, Contabo, Hetzner, etc.

8. Run the bot

```bash
python3 bot.py
```

You should see:

```
Database ready.
Node-agent WebSocket server listening on 0.0.0.0:8788
Starting DXD VPS Manager (32GB RAM, 4 CPU, 80GB Disk)...
```

9. Keep it running 24/7

Create /etc/systemd/system/dxd.service:

```ini
[Unit]
Description=DXD VPS Manager Bot
After=lxc.service lxc-net.service network.target
Wants=network.target lxc-net.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/nethost
Environment="PATH=/opt/nethost/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/nethost/venv/bin/python3 /opt/nethost/bot.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/nethost/bot.log
StandardError=append:/var/log/nethost/bot-error.log
SyslogIdentifier=dxd

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable dxd
sudo systemctl start dxd
sudo systemctl status dxd
journalctl -u dxd -f     # live logs
```

---

💬 Commands

User commands

Command Description
/create Create your VPS (32GB RAM, 4 CPU, 80GB Disk)
/start <id> Start a stopped VPS
/stop <id> Stop a running VPS
/restart <id> Restart a VPS
/show-ssh Show your SSH credentials
/regen-ssh Regenerate SSH password + tmate session
/sshx Get SSHX browser SSH session
/regen-sshx Regenerate SSHX session
/my-vps List all your VPS instances
/delete-vps Delete your VPS (all data lost)
/commands Show all available commands

Admin commands

Command Description
/admin-create <user> [ram] [cpu] [disk] [os] [days] Create VPS for any user
/admin-add-user / /admin-remove-user Grant/revoke hosting access
/list-vps List every VPS on the node
/suspend-vps <id> Suspend a VPS
/unsuspend-vps <id> Unsuspend a VPS
/remove-vps <id> Delete a VPS
/container-status <id> Check container status
/mining-logs View mining detection logs
/resolve-mining <log_id> Mark mining as resolved

---

🎟️ Redeem Code System

⚠️ Note: Redeem code system is currently being updated. Coming soon!

---

📡 Multi-Node System

This lets you plug in other physical servers so VPS can be created on them
too, all managed from the one Discord bot. Each node runs a small agent script
that connects outbound to your main bot — the node itself doesn't need any
inbound ports open, only your main bot server does (the AGENT_PORT you opened
in Step 7).

Adding a node — Admin side

1. /node-create name:Node1 — registers the node (starts offline) and gives you a secure token internally.
2. /node-config name:Node1 — the bot replies with:
   · An install command to run on the new server (downloads node_agent.py)
   · A connect string — a short NodeName|token|ip|port code — to paste into the agent's menu

Adding a node — On the new server

Log into the new server (not your main bot server) and run the install command
the bot gave you:

```bash
coming soon
```

This shows a menu:

```
1. Install VPS Bot
2. Uninstall VPS Bot
3. Connect NODE
4. Exit
```

What each option does:

Option What happens
1. Install VPS Bot Installs LXC + the Python packages the agent needs on this machine. Run this first, once.
2. Uninstall VPS Bot Removes LXC and every container it created on this machine. Asks for confirmation first — this is destructive.
3. Connect NODE Asks you to paste the connect string from /node-config. Once pasted, this machine opens a live connection to your main bot and starts accepting VPS jobs. This process must keep running — see below.
4. Exit Quits the menu without doing anything.

Typical first-time flow on the new server:

```bash
sudo python3 node_agent.py
# choose 1 (Install VPS Bot) — wait for it to finish
sudo python3 node_agent.py
# choose 3 (Connect NODE) — paste the connect string — leave it running
```

Keeping the node agent running 24/7

Choosing "Connect NODE" starts a foreground process — closing the terminal
stops it (and the node goes offline). Use either:

tmux (quick):

```bash
tmux new -s dxd-agent
sudo python3 node_agent.py     # choose 3, paste connect string
# Ctrl+B then D to detach — it keeps running
```

systemd (recommended for production): create /etc/systemd/system/dxd-agent.service:

```ini
[Unit]
Description=DXD Node Agent
After=lxc.service network.target

[Service]
Type=simple
WorkingDirectory=/root
ExecStart=/usr/bin/python3 /root/node_agent.py
Restart=always
RestartSec=5
StandardInput=null

[Install]
WantedBy=multi-user.target
```

Note: the systemd unit skips the interactive menu on restart only if
node_config.json already exists from a prior "Connect NODE" run — run
option 3 manually once first, confirm it connects, Ctrl+C it, then
enable the systemd service so it reconnects automatically on boot/crash.

Using a node

· /node-list — see every node and whether it's 🟢 online or 🔴 offline
· /deploy or /create — pick the node from the dropdown/menu when creating a VPS (or leave it on "Local" to use your main bot server)
· /node-delete name:Node1 — removes a node record (blocked if it still has active VPS on it)

---

🔐 What the user receives

```
⚡ Your VPS is Ready

🔑 MAIN SSH:
ssh root@54.91.221.134 -p 21601
Password: AbCdEfGhIjKlMnOp

🔄 BACKUP SSH (tmate):
ssh xyz123@nyc1.tmate.io

🌐 SSHX (Browser SSH):
https://sshx.io/abc123

Specs:
• RAM: 32 GB (32768 MB)
• CPU: 4 Cores
• Disk: 80 GB

⚠️ Keep your password safe!
```

---

🧪 Verifying your setup

Run /check-network (admin only) any time. It checks LXC reachability,
whether .env SERVER_IP matches this machine's real public IP, and whether
your SSH port range is free to bind locally.

From a different machine, confirm ports are actually reachable:

```bash
nc -zv <SERVER_IP> <ssh_port>
nc -zv <SERVER_IP> 8788        # AGENT_PORT, if testing a node connection
```

Then test the real SSH command from your own machine:

```bash
ssh root@<SERVER_IP> -p <port>
```

---

🛠 Troubleshooting

"LXC not found" — sudo apt-get install lxc lxc-templates

"No route to host" / "Connection refused" — LXC bridge not set up properly. Run:

```bash
sudo brctl addbr lxcbr0
sudo ip addr add 10.0.3.1/24 dev lxcbr0
sudo ip link set lxcbr0 up
sudo sysctl -w net.ipv4.ip_forward=1
```

Users can't connect over SSH — double-check your firewall and cloud
provider security group both allow the SSH_PORT_START–SSH_PORT_END range.

Container has no IPv4 — Static IP is set to 10.0.3.x range. If not working:

```bash
lxc exec DXD-vps-0001 -- ip addr add 10.0.3.100/24 dev eth0
lxc exec DXD-vps-0001 -- ip link set eth0 up
lxc exec DXD-vps-0001 -- ip route add default via 10.0.3.1
```

A node stays 🔴 offline — the agent process on that machine isn't running
(closed terminal, no tmux/systemd), the connect string was mistyped, or
AGENT_PORT isn't open on your main bot server's firewall.

Bot doesn't respond to slash commands — can take up to an hour to sync
globally the first time; try kicking and re-inviting the bot.

"privileged message content intent is missing" — Enable Message Content Intent in Discord Developer Portal → Bot tab.

---

🔥 Anti-Mining Protection

The bot automatically detects and prevents cryptocurrency mining:

· Monitors CPU usage (threshold: 80%)
· Detects mining processes (xmrig, minerd, cpuminer, etc.)
· Auto-suspends VPS when mining is detected
· Notifies admin and user
· Logs all mining detections

Admin commands:

· /mining-logs — View mining detection logs
· /resolve-mining <log_id> — Mark mining as resolved

---

🔧 Environment Variables (.env)

```env
# Discord
DISCORD_TOKEN=your_bot_token_here
ADMIN_ROLE_ID=your_admin_role_id
ADMIN_USER_IDS=your_discord_user_id

# Server
SERVER_IP=your_server_public_ip
SSH_PORT_START=20000
SSH_PORT_END=29999

# LXC
LXC_STORAGE_POOL=default
LXC_NETWORK_BRIDGE=lxcbr0

# Default VPS Specs (32GB RAM, 4 CPU, 80GB Disk)
DEFAULT_RAM_MB=32768
DEFAULT_CPU_CORES=4
DEFAULT_DISK_GB=80

# Anti-Mining
ANTI_MINING_ENABLED=true
ANTI_MINING_CHECK_INTERVAL=300
ANTI_MINING_CPU_THRESHOLD=80.0
```

---

📄 License

For personal/internal use. Modify freely for your own hosting community.

---

🆘 Support

For issues, create a GitHub issue or contact the developer.

---

Made with ❤️ by Mayank
