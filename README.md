# VPN-Security-Infrastructure
Secure remote-access VPN infrastructure with WireGuard, OpenVPN, OPNsense, Suricata IDS, Fail2ban and AI monitoring agent

This is a proof-of-concept implementation of a secure remote-access VPN infrastructure with firewall hardening, intrusion mitigation, and AI-assisted security monitoring - built entirely with open-source tools

Developed for Apocalyptic Accounting Group Limited as part of the DMIT2034 Seminar for Emerging Technologies course.

---

## Overview

In the project, we replace a legacy commercial VPN solution with a zero-cost open-source stack that delivers superior security visibility and automated threat response. The solution addresses three critical gaps identified in a security audit; Absence of network intrusion detection, no automated responses to authentication failures, and insufficient logging for forensic investigation.

---

## Architecture

This project was built using and running three Virtual Machines in our virtual environment (VMWare Workstation):

| VM |                | OS (Operating System) |    | Role |   | IP address |
| OPNsense Firewall |  | FreeBSD |         | Perimeter firewall + Suricata IDS |  | 192.168.56.1 |
| VPN Server|         | Ubuntu 22.04 LTS |  | WireGuard + OpenVPN + Fail2ban + AI agent |  | 192.168.56.10 |
| Client |         | Ubuntu 22.04 |  | Remote worker simulation | | 192.168.56.20 |

All Virtual Machines communicate over a VMware host-only network (VMnet2) configuration at 192.168.56.0/24. The VPN server and OPNsense firewall have an additional NAT adapter for Internet access.

---

## Components

### WireGuard  - Primary VPN
- Kernel-native VPN protocol using ChaCha20 encryption
- Curve25519 key exchange
- All four keys generated server-side and are distributed via scp
- Configured as a persistent systemd service on the server
- PersistentKeepalive maintains tunnel through NAT

### OpenVPN - Fallback VPN
- TLS certificate-based authentication via private PKI (Easy-RSA 3)
- AES-256-GCM data channel encryption
- Certificate authority, server cert, client cert, and DH parameters
- Runs on UDP port 1194

### OPNsense Firewall
- Stateful packet inspection on WAN and LAN
- Default deny policy on WAN interface
- Suricata IDS running on LAN interface
- ET open/emerging-scan ruleset installed

### Suricata IDS
- PCAP live mode on LAN interface (em1)
- Emerging Threats open ruleset
- EVE JSON and syslog output enabled

### Fail2ban
- SSH jail - bans after 5 - 6 failed attempts for 1 hour
- OpenVPN jail - monitors /var/log/openvpn/openvpn.log
- iptables integration for kernel-level blocking

### AI Monitoring Agent
- Python script using Anthropic's Claude API (Claude-sonnet-4-20250514)
- Reads OpenVPN logs, WireGuard peer status, Fail2ban status
- Generates structured daily security digest
- Classified overall risk as ROUTINE / ELEVATED / CRITICAL
- Scheduled via cron at 7am daily
- Saves timestamped markdown repots to ~/vpn_agent/reports/

----

## Network Topology
Remote Client (192.168.56.20)
|
| WireGuard tunnel (UDP 51820) and OpenVPN (UDP 1194)
|
VPN Server (192.168.56.10)
|
| host-only network 192.168.56.0/24
|
OPNsense Firewall (192.168.56.1)
|
| NAT -> Internet

---

## important requirements

- VMWare Workstation or VMware Player
- Ubuntu server 22.04 LTS ISO (https://ubuntu.com/download/desktop) for VPN server
- Ubuntu 22.04 for Client
- OPNsense amd64 DVD ISO (opnsense.org)
- Host Machine with at least 8GB RAM; 16GB RAM is preferred for smooth operations of VMs
- Anthropic API key (console.anthropic.com); Will need to purchase the key

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/vpn-security-infrastructure.git
cd vpn-security-infrastructure
```

### 2. Set up your Primary VPN protocol (WireGuard)
Generate all keys on the server:
```bash
wg genkey | sudo tee /etc/wireguard/server_private.key | \
  wg pubkey | sudo tee /etc/wireguard/server_public.key
wg genkey | sudo tee /etc/wireguard/client_private.key | \
  wg pubkey | sudo tee /etc/wireguard/client_public.key
sudo chmod 600 /etc/wireguard/*.key
```

Copy the example config and fill in your keys:
```bash
sudo cp configs/wireguard/server-wg0.conf.example /etc/wireguard/wg0.conf
sudo nano /etc/wireguard/wg0.conf
```

### 3. Set up OpenVPN PKI (Fallback VPN protocol)
```bash
cp -r /usr/share/easy-rsa ~/openvpn-ca
cd ~/openvpn-ca
./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa gen-req server nopass
./easyrsa sign-req server server
./easyrsa gen-dh
./easyrsa gen-req Client1 nopass
./easyrsa sign-req client Client1
```

### 4. Deploy the AP monitoring agent
```bash
pip install anthropic --break-system-packages
mkdir -p ~/vpn_agent/reports
cp agent/agent.py ~/vpn_agent/
```

Set your API key:
```bash
echo 'export ANTHROPIC_API_KEY="your-key-here"' >> ~/.bashrc
source ~/.bashrc
```

Edit the username in agent.py:
```bash
nano ~/vpn_agent/agent.py
# Change REPORT_DIR to match your username
```

Test the agent:
```bash
python3 ~/vpn_agent/agent.py
```

Schedule daily at 7am:
```bash
crontab -e
# Add:
0 7 * * * ANTHROPIC_API_KEY=your-key /usr/bin/python3 \
  /home/yourusername/vpn_agent/agent.py >> /var/log/vpn_agent.log 2>&1
```

### 5. Set up Fail2ban
```bash
sudo apt install fail2ban -y
sudo cp configs/fail2ban/jail.local /etc/fail2ban/jail.local
sudo systemctl enable --now fail2ban
```

---
## Usage and Testing

### Start WireGuard 

```bash
# On the Server, input the below command into terminal
sudo systemctl start wg-quick@wg0
sudo wg show

# On the Client, input the below command into terminal
sudo wg-quick up wg0
sudo wg show
ping -c 4 10.8.0.1
```

### Switch to OpenVPN fallback
```bash
# On the Server, input the below command into terminal
sudo wg-quick down wg0
sudo systemctl start openvpn-server@server

# On the Client, input the below command into terminal
sudo wg-quick down wg0
sudo openvpn --config ~/client.ovpn --daemon
ip addr show tun1
```

### Run AI monitoring agent manually
```bash
python3 ~/vpn_agent/agent.py
cat ~/vpn_agent/reports/security_digest_$(date +%Y%m%d).md
```

### Test Fail2ban
```bash
# From client — simulate brute force
for i in {1..6}; do ssh wronguser@192.168.56.10; done

# From server — confirm ban
sudo fail2ban-client status sshd
```

---

## Security Notes

- Never commit real private keys or API keys to the repository
- All config files in this repo use placeholder values
- The `.gitignore` excludes key files and reports
- In production the AI agent should run as a dedicated service 
  account with minimal permissions
- WireGuard keys should be rotated periodically

---

## Tools and Technologies

| Tool | Version | Purpose |
|------|---------|---------|
| WireGuard | kernel 5.6+ | Primary VPN protocol |
| OpenVPN | 2.6.19 | Fallback VPN protocol |
| OPNsense | 24.x | Firewall and IDS platform |
| Suricata | 8.0.4 | Network intrusion detection |
| Fail2ban | 0.11.x | Automated IP blocking |
| Easy-RSA | 3.x | PKI and certificate management |
| Python | 3.12 | AI agent runtime |
| Anthropic Claude API | claude-sonnet-4-20250514 | Log analysis and reporting |
| VMware Workstation | 17.x | Virtualization platform |
| Ubuntu Server | 22.04 LTS | VPN server OS |

---

## Author

Chinaza Onuoha

Project Lead
— DMIT2034 Seminar for Emerging Technologies
