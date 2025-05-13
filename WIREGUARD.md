# WireGuard Integration for Marznode

This guide explains how to use the WireGuard protocol with your Marznode installation. WireGuard is a modern, high-performance VPN protocol that is both simple and efficient.

## Prerequisites

- sing-box version 1.11.0 or newer
- WireGuard tools installed for key generation (optional, but recommended)

## Configuration

### 1. Generate a WireGuard Key Pair for the Server

You can generate a server key pair using the `wg` command:

```bash
# Generate the private key
wg genkey > server_private.key
# Get the corresponding public key
cat server_private.key | wg pubkey > server_public.key
```

Or using sing-box:

```bash
sing-box generate wg-keypair
```

### 2. Configure the Endpoint in SingBox Config

Add a WireGuard endpoint to your sing-box configuration:

```json
{
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg-ep",
      "name": "wg0",  
      "mtu": 1408,
      "address": ["20.0.0.1/24"],  // Change to your desired subnet
      "private_key": "YOUR_SERVER_PRIVATE_KEY_HERE",
      "listen_port": 51820,  // Standard WireGuard port
      "peers": []  // Will be populated by Marznode
    }
  ]
}
```

Notes:
- `address` defines the subnet to be used. The first IP (e.g., 20.0.0.1) is assigned to the server.
- `private_key` should be the base64-encoded private key generated in step 1.
- `peers` should be left as an empty array; Marznode will populate this when users are added.

### 3. Setup on the Main Panel

1. Add a new inbound in the Marzban Panel with protocol set to "wireguard"
2. Configure the port to match what you set in the sing-box config
3. Add users to this inbound as you would for any other protocol

### 4. User Configuration

When a user is added to a WireGuard inbound, Marznode will:

1. Generate a unique key pair for the user
2. Assign an IP address from the specified subnet
3. Configure the WireGuard endpoint to accept connections from this user

Users will need a WireGuard client configuration that includes:
- The server's public key
- The server's endpoint (IP:PORT)
- Their own private key
- Their assigned IP address

## Troubleshooting

### IP Assignment Issues

If users can't connect, check:

1. Ensure there's no IP conflict in the assigned addresses
2. Verify the server's firewall allows UDP traffic on the WireGuard port
3. Check logs for any errors related to WireGuard

### Connection Problems

If users can connect but can't access the internet:

1. Ensure proper routing is configured in sing-box
2. Check that IP forwarding is enabled on the server:
   ```bash
   echo 1 > /proc/sys/net/ipv4/ip_forward
   ```

3. Verify NAT is properly set up:
   ```bash
   iptables -t nat -A POSTROUTING -s 20.0.0.0/24 -o eth0 -j MASQUERADE
   ```

## Example Client Configuration

Here's an example WireGuard client configuration:

```
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 20.0.0.2/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = SERVER_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = your-server-ip:51820
PersistentKeepalive = 25
```

## Advanced Configuration

### Custom IP Assignment

The default implementation assigns IPs from the same subnet as the server configuration. You can customize this behavior by modifying the `_assign_ip_from_config` method in the `WireGuardAccount` class.

### Multiple WireGuard Endpoints

You can configure multiple WireGuard endpoints with different subnets:

```json
{
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg-ep1",
      "address": ["10.10.10.1/24"],
      "private_key": "...",
      "listen_port": 51820
    },
    {
      "type": "wireguard",
      "tag": "wg-ep2",
      "address": ["20.20.20.1/24"],
      "private_key": "...",
      "listen_port": 51821
    }
  ]
}
```

Each endpoint will be treated as a separate inbound in Marznode. 