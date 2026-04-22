## Fail2ban Configuration

### Installation

```bash
sudo apt install fail2ban -y
sudo cp configs/fail2ban/jail.local /etc/fail2ban/jail.local
sudo systemctl enable --now fail2ban
```

### Verify jails are active

```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo fail2ban-client status openvpn
```

### Common commands

```bash
# Check banned IPs
sudo fail2ban-client status sshd

# Manually unban an IP
sudo fail2ban-client set sshd unbanip 192.168.56.20

# Manually ban an IP
sudo fail2ban-client set sshd banip 192.168.1.100

# Confirm iptables block rule
sudo iptables -n -L f2b-sshd

# Reload after config changes
sudo fail2ban-client reload

# Check Fail2ban logs
sudo tail -f /var/log/fail2ban.log
```

### Configuration notes
- `bantime` — how long an IP stays banned in seconds
- `findtime` — the window in which failures are counted in seconds
- `maxretry` — number of failures before ban triggers
- The openvpn filter requires a custom filter file if not present
- Backend is set to systemd for sshd on Ubuntu 22.04
- Do not use jail.conf directly — always use jail.local for overrides

### Testing Fail2ban

```bash
# From client VM — simulate brute force
for i in {1..6}; do ssh wronguser@192.168.56.10; done

# From server — confirm auto ban
sudo fail2ban-client status sshd
```

Expected result: client IP appears in Banned IP list after 6 attempts
