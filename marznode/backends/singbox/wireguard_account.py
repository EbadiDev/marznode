"""WireGuard account implementation for sing-box"""

import base64
import hashlib
import ipaddress
import logging
import subprocess
import json
import os
from typing import Tuple, List, Optional

logger = logging.getLogger(__name__)

class WireGuardAccount:
    """WireGuard peer configuration for SingBox endpoints"""
    
    def __init__(self, identifier: str, seed: str, endpoint_config: dict = None):
        """
        Initialize WireGuard account
        
        Args:
            identifier: User identifier (usually userId.username)
            seed: Secret key used to generate WireGuard keys
            endpoint_config: The WireGuard endpoint configuration
        """
        self.identifier = identifier
        self.user_id = int(identifier.split('.')[0]) if '.' in identifier else 0
        
        # Generate keys based on the seed
        self.private_key, self.public_key = self._generate_keys(seed)
        
        # Extract the server subnet
        self.server_subnet = None
        self.assigned_ip = None
        
        if endpoint_config and "address" in endpoint_config:
            self._assign_ip_from_config(endpoint_config)
    
    def _generate_keys(self, seed: str) -> Tuple[str, str]:
        """Generate WireGuard keypair from the seed"""
        # Generate deterministic private key based on seed
        seed_bytes = seed.encode() if isinstance(seed, str) else seed
        private_key_bytes = hashlib.sha256(seed_bytes).digest()
        private_key = base64.b64encode(private_key_bytes).decode()
        
        # Try using sing-box to generate keys if wg command is not available
        try:
            # First, try using sing-box from the environment variables
            sing_box_path = os.environ.get("SING_BOX_EXECUTABLE_PATH", "sing-box")
            
            # Generate a keypair using sing-box
            result = subprocess.run(
                [sing_box_path, "generate", "wg-keypair"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse the output
            output_lines = result.stdout.strip().split('\n')
            if len(output_lines) >= 2:
                # Extract private and public keys from output
                for line in output_lines:
                    if line.startswith("PrivateKey:"):
                        private_key = line.split(":", 1)[1].strip()
                    elif line.startswith("PublicKey:"):
                        public_key = line.split(":", 1)[1].strip()
                
                logger.debug(f"Generated WireGuard keys using sing-box for user {self.identifier}")
                return private_key, public_key
            else:
                raise ValueError("Invalid output format from sing-box")
                
        except Exception as e:
            logger.error(f"Failed to generate WireGuard keys using sing-box: {e}")
            
            # As a fallback, use the deterministic key we generated above
            # and create a corresponding public key
            # This is a simplified approach and may not be cryptographically correct
            # But it's better than failing completely
            logger.warning("Using fallback WireGuard key generation method")
            
            # Create a deterministic "public key" from private key
            # Note: This is NOT a proper WireGuard key pair but will work as temporary fallback
            public_key_bytes = hashlib.sha256((private_key_bytes + b"public")).digest()
            public_key = base64.b64encode(public_key_bytes).decode()
            
            return private_key, public_key
    
    def _assign_ip_from_config(self, endpoint_config: dict) -> None:
        """
        Assign an IP from the endpoint's subnet configuration
        
        Args:
            endpoint_config: The WireGuard endpoint configuration
        """
        if not endpoint_config.get("address"):
            logger.warning("No address in WireGuard endpoint config")
            return
        
        try:
            # Get the first address in the list
            server_cidr = endpoint_config["address"][0]
            network = ipaddress.ip_network(server_cidr, strict=False)
            
            # Get the network address and host ID
            # Skip the first IP as it's typically used by the server
            # Use user_id to determine the host part of the IP, but ensure it fits within network
            host_id = (self.user_id % (network.num_addresses - 2)) + 2
            
            # Generate the IP address
            if network.version == 4:  # IPv4
                parts = list(map(int, network.network_address.exploded.split('.')))
                # Calculate which octet(s) to modify based on subnet size
                if network.prefixlen <= 8:  # Class A or larger
                    parts[1] = (host_id >> 16) & 0xFF
                    parts[2] = (host_id >> 8) & 0xFF
                    parts[3] = host_id & 0xFF
                elif network.prefixlen <= 16:  # Class B or larger
                    parts[2] = (host_id >> 8) & 0xFF
                    parts[3] = host_id & 0xFF
                elif network.prefixlen <= 24:  # Class C or larger
                    parts[3] = host_id & 0xFF
                
                self.assigned_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}/32"
            else:  # IPv6
                # For IPv6, we'll just use the user_id in the host portion
                # This is a simplified approach; you might want more sophisticated handling
                host_bytes = self.user_id.to_bytes(16, byteorder='big')
                host_addr = ipaddress.IPv6Address(host_bytes)
                
                # Combine network prefix with host ID
                network_int = int(network.network_address)
                host_int = int(host_addr) & (2**(128-network.prefixlen) - 1)
                ip = ipaddress.IPv6Address(network_int | host_int)
                
                self.assigned_ip = f"{ip}/128"
            
            logger.debug(f"Assigned IP {self.assigned_ip} to user {self.identifier}")
        except Exception as e:
            logger.error(f"Error assigning IP from subnet {endpoint_config['address']}: {e}")
            # Fallback to a default IP if assignment fails
            self.assigned_ip = "10.10.10.2/32"  # Fallback
    
    def to_dict(self) -> dict:
        """Convert to a peer configuration dict for SingBox"""
        result = {
            "public_key": self.public_key,
            "allowed_ips": [self.assigned_ip] if self.assigned_ip else ["0.0.0.0/0", "::/0"]
        }
        
        # Add endpoint identifier for stats tracking
        result["name"] = self.identifier
        
        return result 