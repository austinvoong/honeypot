# docker_device_scanner.py
import docker
import json
import re
import subprocess
import hashlib
from pathlib import Path
from typing import List, Dict, Set, Optional
from src.network_scanner.models import DeviceFingerprint
import logging
from datetime import datetime

class DockerDeviceScanner:
    """Scanner that uses Docker API to find devices in test environment"""
    
    def __init__(self, network_name="honeypot-test-environment_honeypot_network"):
        self.client = docker.from_env()
        self.network_name = network_name
        self.logger = logging.getLogger(__name__)
        
        # Enhanced service pattern mapping
        self.service_patterns = {
            'http': ['http', 'web', 'apache', 'nginx', 'iis'],
            'https': ['https', 'ssl', 'tls', 'secure'],
            'ssh': ['ssh', 'secure shell'],
            'telnet': ['telnet'],
            'ftp': ['ftp', 'file transfer'],
            'smtp': ['smtp', 'mail', 'email'],
            'dns': ['dns', 'domain', 'nameserver'],
            'snmp': ['snmp', 'network management'],
            'ntp': ['ntp', 'network time'],
            'rtsp': ['rtsp', 'streaming', 'video'],
            'mqtt': ['mqtt', 'mosquitto', 'iot protocol'],
            'modbus': ['modbus', 'industrial'],
            'bacnet': ['bacnet', 'building automation'],
            'coap': ['coap', 'constrained application']
        }
        
    def scan(self) -> List[DeviceFingerprint]:
        """Get device information from Docker containers"""
        devices = []
        
        try:
            # Get all networks if network_name is not specified
            networks = {}
            if self.network_name == "all":
                networks = self.client.networks.list()
            else:
                try:
                    networks = [self.client.networks.get(self.network_name)]
                except docker.errors.NotFound:
                    self.logger.warning(f"Network {self.network_name} not found. Scanning all networks.")
                    networks = self.client.networks.list()
            
            # Iterate through each network
            for network in networks:
                try:
                    network_info = network.attrs
                    
                    # Get containers in this network
                    for container_id, container_config in network_info.get('Containers', {}).items():
                        try:
                            container = self.client.containers.get(container_id)
                            
                            # Skip if container is not running
                            if container.status != 'running':
                                continue
                                
                            # Map container info to device fingerprint
                            ip_address = container_config.get('IPv4Address', '').split('/')[0]
                            if not ip_address:
                                continue
                            
                            # Get container information
                            device = self._process_container(container, ip_address)
                            if device:
                                devices.append(device)
                                
                        except docker.errors.NotFound:
                            continue
                        except Exception as e:
                            self.logger.error(f"Error processing container {container_id}: {e}")
                            
                except Exception as e:
                    self.logger.error(f"Error processing network {network.name}: {e}")
                    
            self.logger.info(f"Found {len(devices)} devices in Docker networks")
            return devices
            
        except Exception as e:
            self.logger.error(f"Error scanning Docker containers: {e}")
            return []
    
    def _process_container(self, container, ip_address: str) -> Optional[DeviceFingerprint]:
        """Process a container and extract device information"""
        try:
            # Get container tags and name
            image_name = container.image.tags[0] if container.image.tags else container.image.id
            container_name = container.name
            
            # Determine OS type with more detail
            os_type = self._determine_os_type(container)
            
            # Get exposed ports and services
            exposed_ports, services = self._get_ports_and_services(container, image_name)
            
            # Generate a TCP fingerprint hash (simulated)
            tcp_fingerprint = self._generate_tcp_fingerprint(container)
            
            # Estimate uptime (simulated)
            uptime = self._estimate_uptime(container)
            
            # Extract HTTP headers if web server is detected
            http_headers = None
            if any(service in ['http', 'https', 'http-alt'] for service in services.values()):
                http_headers = self._scan_http_headers(ip_address, services)
            
            # Create the device fingerprint
            device = DeviceFingerprint(
                ip_address=ip_address,
                os_type=os_type,
                open_ports=list(exposed_ports),
                services=services,
                tcp_fingerprint=tcp_fingerprint,
                uptime=uptime
            )
            
            # Add HTTP headers if available
            if http_headers:
                device.http_headers = http_headers
                
            # Add MAC address (simulated)
            mac_address = self._generate_mac_address(container_name)
            device.mac_address = mac_address
            
            # Try to determine device type
            device_type = self._determine_device_type(container, services)
            device.device_type = device_type
            
            return device
            
        except Exception as e:
            self.logger.error(f"Error processing container {container.name}: {e}")
            return None
    
    def _determine_os_type(self, container) -> str:
        """Determine OS type with better accuracy"""
        # Check for OS labels
        if 'os.type' in container.labels:
            return container.labels['os.type']
            
        # Check image name for OS hints
        image_name = container.image.tags[0] if container.image.tags else ''
        image_lower = image_name.lower()
        
        if 'windows' in image_lower:
            return 'Windows'
        elif 'alpine' in image_lower:
            return 'Alpine Linux'
        elif 'ubuntu' in image_lower:
            return 'Ubuntu'
        elif 'debian' in image_lower:
            return 'Debian'
        elif 'centos' in image_lower:
            return 'CentOS'
        elif 'fedora' in image_lower:
            return 'Fedora'
        elif 'busybox' in image_lower:
            return 'BusyBox'
        elif 'freertos' in image_lower:
            return 'FreeRTOS'
        
        # Try to determine from container inspection
        try:
            # Check for Linux-specific paths
            exec_result = container.exec_run("ls /etc/*release", privileged=True)
            if exec_result.exit_code == 0:
                # Try to get release info
                os_info = container.exec_run("cat /etc/*release", privileged=True)
                output = os_info.output.decode('utf-8', errors='ignore')
                
                if 'ID=ubuntu' in output:
                    return 'Ubuntu'
                elif 'ID=debian' in output:
                    return 'Debian'
                elif 'ID=centos' in output:
                    return 'CentOS'
                elif 'ID=alpine' in output:
                    return 'Alpine Linux'
                
                # Default to generic Linux
                return 'Linux'
        except:
            pass
        
        # Default to Linux
        return 'Linux'
    
    def _get_ports_and_services(self, container, image_name: str) -> tuple:
        """Get ports and services with enhanced detection"""
        exposed_ports = set()
        services = {}
        
        # Get exposed ports from container
        port_info = container.ports
        for container_port, host_ports in port_info.items():
            if host_ports:
                port_proto = container_port.split('/')
                port = int(port_proto[0])
                exposed_ports.add(port)
                
                # Determine service
                service = self._get_service_for_port(port, image_name, container.name)
                services[port] = service
        
        # Add exposed ports from config if not already found
        config_exposed = container.attrs.get('Config', {}).get('ExposedPorts', {})
        for port_proto in config_exposed:
            port = int(port_proto.split('/')[0])
            if port not in exposed_ports:
                exposed_ports.add(port)
                service = self._get_service_for_port(port, image_name, container.name)
                services[port] = service
        
        return exposed_ports, services
    
    def _get_service_for_port(self, port: int, image_name: str, container_name: str) -> str:
        """Enhanced port to service mapping"""
        # Common port mappings
        port_map = {
            20: "ftp-data",
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            67: "dhcp",
            68: "dhcp",
            69: "tftp",
            80: "http",
            88: "kerberos",
            110: "pop3",
            123: "ntp",
            143: "imap",
            161: "snmp",
            162: "snmp-trap",
            389: "ldap",
            443: "https",
            445: "smb",
            465: "smtps",
            500: "ipsec",
            514: "syslog",
            587: "submission",
            636: "ldaps",
            993: "imaps",
            995: "pop3s",
            1080: "socks",
            1433: "mssql",
            1521: "oracle",
            1720: "h323",
            1883: "mqtt",
            3306: "mysql",
            3389: "rdp",
            5060: "sip",
            5061: "sips",
            5432: "postgresql",
            5672: "amqp",
            5683: "coap",
            5684: "coaps",
            6379: "redis",
            8080: "http-alt",
            8443: "https-alt",
            8883: "mqtt-ssl",
            27017: "mongodb",
            5000: "upnp",
            8000: "http-alt",
            8008: "http-alt",
            8888: "http-alt",
            44818: "ethernet-ip",
            47808: "bacnet",
            502: "modbus",
            102: "s7comm",
            9100: "printer",
            554: "rtsp"
        }
        
        # First check common ports
        if port in port_map:
            return port_map[port]
        
        # Check for service hints in labels
        labels = container_name.labels if hasattr(container_name, 'labels') else {}
        port_label = f"port.{port}.service"
        if port_label in labels:
            return labels[port_label]
        
        # Check image and container name for service hints
        name_lower = (image_name + " " + container_name).lower()
        
        for service, keywords in self.service_patterns.items():
            if any(keyword in name_lower for keyword in keywords):
                return service
        
        # HTTP ports are common in various ranges
        if port in range(8000, 9000):
            return "http-alt"
        
        # Default
        return f"unknown-{port}"
    
    def _generate_tcp_fingerprint(self, container) -> str:
        """Generate a simulated TCP fingerprint"""
        # Create a hash based on container details
        hash_input = (
            container.id +
            container.image.tags[0] if container.image.tags else container.image.id +
            container.name
        )
        
        # Generate SHA-256 hash
        hash_obj = hashlib.sha256(hash_input.encode())
        return hash_obj.hexdigest()
    
    def _estimate_uptime(self, container) -> int:
        """Estimate container uptime in hours"""
        try:
            # Get container start time
            started_at = container.attrs.get('State', {}).get('StartedAt', '')
            if started_at:
                # Parse the timestamp
                start_time = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
                # Calculate uptime in hours
                uptime_hours = int((datetime.now() - start_time).total_seconds() / 3600)
                return max(uptime_hours, 1)  # At least 1 hour
        except:
            pass
        
        # Default random uptime between 1 hour and 30 days
        import random
        return random.randint(1, 720)
    
    def _scan_http_headers(self, ip_address: str, services: Dict[int, str]) -> Optional[Dict[str, str]]:
        """Scan for HTTP headers on detected web services"""
        headers = {}
        
        # Find HTTP ports
        http_ports = [
            port for port, service in services.items()
            if service in ['http', 'https', 'http-alt', 'https-alt']
        ]
        
        if not http_ports:
            return None
            
        # Try each HTTP port
        for port in http_ports:
            try:
                protocol = 'https' if services[port] in ['https', 'https-alt'] else 'http'
                url = f"{protocol}://{ip_address}:{port}/"
                
                # Use curl to get headers
                process = subprocess.run(
                    ['curl', '-I', '-s', '-m', '2', url],
                    capture_output=True,
                    text=True
                )
                
                if process.returncode != 0:
                    continue
                    
                # Parse headers
                for line in process.stdout.splitlines():
                    if ':' in line:
                        name, value = line.split(':', 1)
                        headers[name.strip()] = value.strip()
                        
                # If we got headers, return them
                if headers:
                    return headers
                    
            except Exception as e:
                self.logger.debug(f"Error scanning HTTP headers on {ip_address}:{port}: {str(e)}")
                
        return headers if headers else None
    
    def _generate_mac_address(self, container_name: str) -> str:
        """Generate a deterministic MAC address based on container name"""
        # Generate hash from container name
        hash_obj = hashlib.md5(container_name.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Format as MAC address (first 12 chars of hash)
        mac_parts = [hash_hex[i:i+2] for i in range(0, 12, 2)]
        
        # Set locally administered bit (2nd least significant bit of first byte)
        first_byte = int(mac_parts[0], 16)
        first_byte = (first_byte & 0xfd) | 0x02  # Clear bit 1, set bit 2
        mac_parts[0] = f"{first_byte:02x}"
        
        return ':'.join(mac_parts)
    
    def _determine_device_type(self, container, services: Dict[int, str]) -> str:
        """Determine device type from container and services"""
        # Check labels
        labels = container.labels
        if 'device.type' in labels:
            return labels['device.type']
            
        # Check image name and container name
        name = container.name.lower()
        image = container.image.tags[0].lower() if container.image.tags else ''
        full_name = name + " " + image
        
        device_mapping = {
            'camera': ['camera', 'cam', 'webcam', 'ipcam', 'surveillance'],
            'gateway': ['gateway', 'router', 'hub', 'edge'],
            'thermostat': ['thermostat', 'hvac', 'temperature', 'climate'],
            'doorbell': ['doorbell', 'door', 'bell', 'entry'],
            'lock': ['lock', 'smartlock', 'door'],
            'sensor': ['sensor', 'detect', 'monitor'],
            'light': ['light', 'bulb', 'lamp', 'lighting'],
            'speaker': ['speaker', 'audio', 'voice', 'sound'],
            'refrigerator': ['fridge', 'refrigerator', 'cooler'],
            'air-purifier': ['air', 'purifier', 'filter', 'purification'],
            'garage': ['garage', 'door'],
            'assistant': ['assistant', 'alexa', 'google', 'siri', 'voice']
        }
        
        for device_type, keywords in device_mapping.items():
            if any(keyword in full_name for keyword in keywords):
                return device_type
                
        # Check services
        service_values = set(services.values())
        
        if 'rtsp' in service_values or 'mjpeg' in service_values:
            return 'camera'
        elif 'mqtt' in service_values:
            return 'iot-gateway'
        elif 'modbus' in service_values or 'bacnet' in service_values:
            return 'industrial-device'
        elif 'http' in service_values and len(services) < 3:
            return 'web-interface'
        
        # Default
        return 'iot-device'
    
    def save_results(self, devices: List[DeviceFingerprint], output_dir: str = 'scan_results'):
        """Save scan results to JSON file"""
        Path(output_dir).mkdir(exist_ok=True)
        
        results = []
        for device in devices:
            device_dict = {
                'ip_address': device.ip_address,
                'os_type': device.os_type,
                'open_ports': device.open_ports,
                'services': device.services,
                'tcp_fingerprint': device.tcp_fingerprint,
                'uptime': device.uptime
            }
            
            # Add optional attributes if they exist
            if hasattr(device, 'mac_address'):
                device_dict['mac_address'] = device.mac_address
                
            if hasattr(device, 'device_type'):
                device_dict['device_type'] = device.device_type
                
            if hasattr(device, 'http_headers'):
                device_dict['http_headers'] = device.http_headers
            
            results.append(device_dict)
            
        # Add timestamp to filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = Path(output_dir) / f'network_scan_{timestamp}.json'
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        self.logger.info(f"Scan results for {len(devices)} devices saved to {output_file}")
        return output_file