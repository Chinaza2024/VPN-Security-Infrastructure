## OpenVPN Configuration

### PKI Setup (run on VPN server)

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

### Copy certificates into place

```bash
sudo cp pki/ca.crt pki/issued/server.crt \
        pki/private/server.key pki/dh.pem \
        /etc/openvpn/server/
```

### Transfer client certificates to client VM

```bash
scp pki/ca.crt username@CLIENT_IP:~/
scp pki/issued/Client1.crt username@CLIENT_IP:~/
scp pki/private/Client1.key username@CLIENT_IP:~/
```

### Notes
- Common Name for CA: your organization name
- Common Name for server: vpn-server
- Common Name for client: Client1 (case sensitive)
- easy-rsa is case sensitive — be consistent with names throughout
- cipher AES-256-CBC is deprecated in OpenVPN 2.6 — use data-ciphers instead
