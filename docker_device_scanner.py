# docker_device_scanner.py
import docker
import json
from pathlib import Path
from typing import List, Dict
from src.network_scanner.models import DeviceFingerprint

class DockerDeviceScanner:
    """Scanner that uses Docker API to find devices in test environment"""
    
    def __init__(self, network_name="honeypot-test-environment_honeypot_network"):
        self.client = docker.from_env()
        self.network_name = network_name
        
    def scan(self) -> List[DeviceFingerprint]:
        """Get device information from Docker containers"""
        devices = []
        
        try:
            # Get network information
            network = self.client.networks.get(self.network_name)
            network_info = network.attrs
            
            # Get containers in this network
            for container_id, container_config in network_info.get('Containers', {}).items():
                container = self.client.containers.get(container_id)
                
                # Map container info to device fingerprint
                ip_address = container_config.get('IPv4Address', '').split('/')[0]
                
                # Determine device type and open ports from labels and image
                image_name = container.image.tags[0] if container.image.tags else ""
                
                # Determine OS type
                os_type = "Linux"  # Most containers are Linux-based
                
                # Determine open ports and services
                ports = {}
                exposed_ports = container.attrs.get('Config', {}).get('ExposedPorts', {})
                for port_key in exposed_ports:
                    port, proto = port_key.split('/')
                    port_num = int(port)
                    
                    # Assign a service based on common port numbers
                    service = self._get_service_for_port(port_num, image_name)
                    ports[port_num] = service
                
                # Create the device fingerprint
                device = DeviceFingerprint(
                    ip_address=ip_address,
                    os_type=os_type,
                    open_ports=list(ports.keys()),
                    services=ports
                )
                devices.append(device)
                
            return devices
            
        except Exception as e:
            print(f"Error scanning Docker containers: {e}")
            return []
    
    def _get_service_for_port(self, port: int, image_name: str) -> str:
        """Map port numbers to likely services"""
        port_map = {
            22: "ssh",
            23: "telnet",
            80: "http",
            443: "https",
            8080: "http-alt",
            8443: "https-alt",
            21: "ftp",
            25: "smtp",
            110: "pop3",
            143: "imap",
            3306: "mysql",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb"
        }
        
        # First check common ports
        if port in port_map:
            return port_map[port]
        
        # Check image name for hints
        image_lower = image_name.lower()
        if "nginx" in image_lower or "apache" in image_lower or "web" in image_lower:
            return "http"
        elif "ftp" in image_lower:
            return "ftp"
        elif "ssh" in image_lower:
            return "ssh"
        elif "db" in image_lower or "sql" in image_lower:
            return "database"
        elif "mqtt" in image_lower:
            return "mqtt"
        elif "camera" in image_lower:
            return "rtsp"
        elif "thermostat" in image_lower:
            return "modbus"
        
        # Default
        return f"unknown-{port}"
    
    def save_results(self, devices: List[DeviceFingerprint], output_dir: str = 'scan_results'):
        """Save scan results to JSON file"""
        Path(output_dir).mkdir(exist_ok=True)
        
        results = []
        for device in devices:
            results.append({
                'ip_address': device.ip_address,
                'os_type': device.os_type,
                'open_ports': device.open_ports,
                'services': device.services,
                'tcp_fingerprint': device.tcp_fingerprint,
                'uptime': device.uptime
            })
            
        output_file = Path(output_dir) / 'network_scan.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        print(f"Scan results saved to {output_file}")
        return output_file