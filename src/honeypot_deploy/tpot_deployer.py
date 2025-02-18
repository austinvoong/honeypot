# src/honeypot_deploy/tpot_deployer.py
import subprocess  # For running shell commands
import logging  # For logging messages
import yaml  # For handling YAML files
import json  # For handling JSON files
from pathlib import Path  # For handling file paths
from typing import List, Dict, Optional, Tuple  # For type hinting
from datetime import datetime
import docker  # For interacting with Docker

# Define the TPotDeployer class
class TPotDeployer:
    """Enhanced T-Pot Deployer with comprehensive container and configuration management"""
    
    def __init__(self, tpot_dir: Path):
        self.tpot_dir = tpot_dir
        self.logger = logging.getLogger(__name__)
        self.docker_client = docker.from_env()
        
        # T-Pot paths
        self.compose_file = tpot_dir / 'docker-compose.yml'
        self.config_dir = tpot_dir / 'etc/tpot/config'
        
        # Honeypot templates directory
        self.templates_dir = tpot_dir / 'etc/tpot/templates'
        
        # Initialize directories
        self._init_directories()
        
    def _init_directories(self):
        """Initialize required directories"""
        for directory in [self.config_dir, self.templates_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            
    def _validate_configuration(self, config: Dict) -> Tuple[bool, str]:
        """
        Validate honeypot configuration
        
        Args:
            config: Honeypot configuration dictionary
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        required_fields = ['cluster_id', 'os_type', 'ports', 'services']
        
        # Check required fields
        for field in required_fields:
            if field not in config:
                return False, f"Missing required field: {field}"
                
        # Validate ports and services
        for port, service in config['services'].items():
            try:
                port_num = int(port)
                if port_num < 1 or port_num > 65535:
                    return False, f"Invalid port number: {port}"
            except ValueError:
                return False, f"Invalid port format: {port}"
                
            if not isinstance(service, str):
                return False, f"Invalid service format for port {port}"
                
        return True, ""
        
    def _map_service_to_honeypot(self, service: str, port: int) -> Optional[str]:
        """
        Map service to appropriate T-Pot honeypot with enhanced service detection
        
        Args:
            service: Service name
            port: Port number
            
        Returns:
            Honeypot name or None if no mapping found
        """
        # Enhanced service mapping
        service_map = {
            'ftp': ['honeytrap', 'dionaea'],
            'ssh': ['cowrie'],
            'telnet': ['cowrie'],
            'http': ['heralding', 'honeypy'],
            'https': ['heralding'],
            'smtp': ['mailoney'],
            'sip': ['dionaea'],
            'mysql': ['heralding'],
            'rdp': ['rdpy'],
            'vnc': ['rdpy'],
            'industrial': ['conpot'],
            'modbus': ['conpot'],
            'snmp': ['honeypy'],
            'mqtt': ['mqttiot']
        }
        
        # Check for service match
        service_lower = service.lower()
        for svc_type, honeypots in service_map.items():
            if svc_type in service_lower:
                # Return first available honeypot
                for honeypot in honeypots:
                    if self._check_honeypot_available(honeypot):
                        return honeypot
                        
        return None
        
    def _check_honeypot_available(self, honeypot: str) -> bool:
        """
        Check if honeypot image is available
        """
        try:
            self.docker_client.images.get(f"dtagdevsec/{honeypot}:latest")
            return True
        except docker.errors.ImageNotFound:
            return False
            
    def _generate_docker_compose(self, configs: List[Dict]) -> dict:
        """
        Generate T-Pot docker-compose configuration with enhanced networking
        
        Args:
            configs: List of honeypot configurations
            
        Returns:
            Docker Compose configuration dictionary
        """
        compose_config = {
            'version': '3',
            'networks': {
                'tpot_local': {
                    'driver': 'bridge',
                    'ipam': {
                        'config': [{'subnet': '172.20.0.0/24'}]
                    }
                }
            },
            'services': {}
        }
        
        used_ports = set()
        
        for config in configs:
            is_valid, error = self._validate_configuration(config)
            if not is_valid:
                self.logger.error(f"Invalid configuration: {error}")
                continue
                
            cluster_id = config['cluster_id']
            
            # Determine required honeypots
            honeypots = set()
            for port, service in config['services'].items():
                if hp := self._map_service_to_honeypot(service, int(port)):
                    honeypots.add(hp)
                    
            # Configure each honeypot
            for honeypot in honeypots:
                service_name = f"{honeypot}_{cluster_id}"
                
                # Base configuration
                service_config = {
                    'container_name': service_name,
                    'restart': 'always',
                    'network_mode': 'host',
                    'image': f"dtagdevsec/{honeypot}:latest",
                    'volumes': [
                        f"{self.config_dir}/{honeypot}/:/etc/{honeypot}/",
                        '/data:/data'
                    ],
                    'environment': {
                        'TPOT_CONFIG': 'true',
                        'CLUSTER_ID': str(cluster_id)
                    }
                }
                
                # Add ports
                ports = []
                for port, service in config['services'].items():
                    if self._map_service_to_honeypot(service, int(port)) == honeypot:
                        if int(port) not in used_ports:
                            ports.append(f"{port}:{port}")
                            used_ports.add(int(port))
                            
                if ports:
                    service_config['ports'] = ports
                    
                compose_config['services'][service_name] = service_config
                
        return compose_config
        
    async def deploy_honeypots(self, config_file: Path) -> bool:
        """
        Deploy honeypots using T-Pot with improved error handling
        
        Args:
            config_file: Path to honeypot configuration JSON
            
        Returns:
            bool: Success status
        """
        try:
            # Load configurations
            with open(config_file) as f:
                configs = json.load(f)
                
            # Generate docker-compose config
            compose_config = self._generate_docker_compose(configs)
            
            # Save docker-compose file
            with open(self.compose_file, 'w') as f:
                yaml.dump(compose_config, f)
                
            # Stop existing containers
            self.logger.info("Stopping existing honeypots...")
            subprocess.run(
                ['docker-compose', '-f', str(self.compose_file), 'down'],
                cwd=self.tpot_dir,
                check=True,
                capture_output=True
            )
            
            # Pull latest images
            self.logger.info("Pulling latest honeypot images...")
            subprocess.run(
                ['docker-compose', '-f', str(self.compose_file), 'pull'],
                cwd=self.tpot_dir,
                check=True,
                capture_output=True
            )
            
            # Start new containers
            self.logger.info("Starting honeypots...")
            subprocess.run(
                ['docker-compose', '-f', str(self.compose_file), 'up', '-d'],
                cwd=self.tpot_dir,
                check=True,
                capture_output=True
            )
            
            # Verify deployment
            if not self._verify_deployment(compose_config):
                raise Exception("Deployment verification failed")
                
            self.logger.info("T-Pot honeypots deployed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to deploy T-Pot honeypots: {str(e)}")
            return False
            
    def _verify_deployment(self, compose_config: Dict) -> bool:
        """
        Verify honeypot deployment status
        
        Args:
            compose_config: Docker Compose configuration
            
        Returns:
            bool: Verification status
        """
        try:
            expected_containers = set(compose_config['services'].keys())
            running_containers = set()
            
            containers = self.docker_client.containers.list()
            for container in containers:
                if 'dtagdevsec' in container.image.tags[0]:
                    if container.status != 'running':
                        self.logger.error(f"Container {container.name} is not running")
                        return False
                    running_containers.add(container.name)
                    
            if not expected_containers.issubset(running_containers):
                missing = expected_containers - running_containers
                self.logger.error(f"Missing containers: {missing}")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Deployment verification failed: {str(e)}")
            return False
            
    def get_honeypot_status(self) -> Dict[str, Dict]:
        """
        Get detailed status of deployed honeypots
        
        Returns:
            Dict with container status information
        """
        status = {}
        try:
            containers = self.docker_client.containers.list(all=True)
            for container in containers:
                if 'dtagdevsec' in container.image.tags[0]:
                    # Get container stats
                    stats = container.stats(stream=False)
                    
                    status[container.name] = {
                        'status': container.status,
                        'image': container.image.tags[0],
                        'created': container.attrs['Created'],
                        'ports': container.ports,
                        'cpu_usage': stats['cpu_stats']['cpu_usage']['total_usage'],
                        'memory_usage': stats['memory_stats']['usage'],
                        'network_rx': stats['networks']['eth0']['rx_bytes'],
                        'network_tx': stats['networks']['eth0']['tx_bytes']
                    }
                    
        except Exception as e:
            self.logger.error(f"Failed to get honeypot status: {str(e)}")
            
        return status
        
    def get_honeypot_logs(self, container_name: str, tail: int = 100) -> List[str]:
        """
        Get logs from a specific honeypot container
        
        Args:
            container_name: Name of the container
            tail: Number of log lines to retrieve
            
        Returns:
            List of log lines
        """
        try:
            container = self.docker_client.containers.get(container_name)
            logs = container.logs(tail=tail, timestamps=True).decode('utf-8')
            return logs.splitlines()
            
        except docker.errors.NotFound:
            self.logger.error(f"Container {container_name} not found")
            return []
        except Exception as e:
            self.logger.error(f"Failed to get container logs: {str(e)}")
            return []