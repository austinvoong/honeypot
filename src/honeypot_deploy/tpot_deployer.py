# src/honeypot_deploy/tpot_deployer.py
import subprocess  # For running shell commands
import logging  # For logging messages
import yaml  # For handling YAML files
import json  # For handling JSON files
from pathlib import Path  # For handling file paths
from typing import List, Dict, Optional  # For type hinting
import docker  # For interacting with Docker

# Define the TPotDeployer class
class TPotDeployer:
    def __init__(self, tpot_dir: Path):
        """Initialize T-Pot deployer
        
        Args:
            tpot_dir: Path to T-Pot installation directory
        """
        self.tpot_dir = tpot_dir  # Store the T-Pot directory path
        self.logger = logging.getLogger(__name__)  # Set up a logger
        self.docker_client = docker.from_env()  # Initialize Docker client from environment
        
        # T-Pot paths
        self.compose_file = tpot_dir / 'docker-compose.yml'  # Path to docker-compose file
        self.config_dir = tpot_dir / 'etc/tpot/config'  # Path to T-Pot configuration directory
        
    def _map_service_to_honeypot(self, service: str, port: int) -> Optional[str]:
        """Map service to appropriate T-Pot honeypot"""
        # Mapping of services to T-Pot honeypots
        service_map = {
            'ftp': 'honeytrap',
            'ssh': 'cowrie',
            'telnet': 'cowrie',
            'http': 'heralding',
            'https': 'heralding',
            'smtp': 'mailoney',
            'sip': 'dionaea',
            'mysql': 'heralding',
            'rdp': 'rdpy',
            'vnc': 'rdpy',
            'industrial': 'conpot'
        }
        
        return service_map.get(service.lower())  # Return the mapped honeypot or None
        
    def _generate_docker_compose(self, configs: List[Dict]) -> dict:
        """Generate T-Pot docker-compose configuration"""
        compose_config = {
            'version': '3',  # Docker Compose version
            'networks': {
                'tpot_local': {
                    'driver': 'bridge',  # Use bridge network
                    'ipam': {
                        'config': [{'subnet': '172.20.0.0/24'}]  # Subnet configuration
                    }
                }
            },
            'services': {}  # Placeholder for services
        }
        
        used_ports = set()  # Track used ports to avoid conflicts
        
        for i, config in enumerate(configs):
            # Determine honeypots needed for this configuration
            honeypots = set()
            for port, service in config['services'].items():
                if hp := self._map_service_to_honeypot(service, int(port)):
                    honeypots.add(hp)
            
            # Configure each honeypot
            for honeypot in honeypots:
                service_name = f"{honeypot}_{i}"  # Unique service name
                
                # Base configuration from T-Pot's templates
                template_file = self.config_dir / f"{honeypot}.yml"
                if template_file.exists():
                    with open(template_file) as f:
                        honeypot_config = yaml.safe_load(f)  # Load honeypot configuration
                else:
                    self.logger.warning(f"No template found for {honeypot}")  # Log warning if template is missing
                    continue
                
                # Customize configuration
                service_config = {
                    'container_name': service_name,  # Set container name
                    'restart': 'always',  # Always restart the container
                    'network_mode': 'host',  # Use host networking for honeypot
                    'image': f"dtagdevsec/{honeypot}:latest",  # Docker image to use
                    'volumes': [
                        f"{self.config_dir}/{honeypot}/:/etc/{honeypot}/",  # Mount configuration volume
                        '/data:/data'  # Mount data volume
                    ]
                }
                
                # Add ports based on service configuration
                ports = []
                for port, service in config['services'].items():
                    if self._map_service_to_honeypot(service, int(port)) == honeypot:
                        if int(port) not in used_ports:
                            ports.append(f"{port}:{port}")  # Map port
                            used_ports.add(int(port))  # Mark port as used
                
                if ports:
                    service_config['ports'] = ports  # Add ports to service configuration
                
                compose_config['services'][service_name] = service_config  # Add service to compose configuration
        
        return compose_config  # Return the complete docker-compose configuration
        
    def deploy_honeypots(self, config_file: Path) -> bool:
        """Deploy honeypots using T-Pot
        
        Args:
            config_file: Path to honeypot configuration JSON
        """
        try:
            # Load configurations
            with open(config_file) as f:
                configs = json.load(f)  # Load JSON configuration
            
            # Generate docker-compose config
            compose_config = self._generate_docker_compose(configs)
            
            # Save docker-compose file
            with open(self.compose_file, 'w') as f:
                yaml.dump(compose_config, f)  # Write configuration to file
            
            # Stop existing containers
            self.logger.info("Stopping existing honeypots...")
            subprocess.run(['docker-compose', '-f', str(self.compose_file), 'down'],
                         cwd=self.tpot_dir, check=True)  # Stop containers
            
            # Start new containers
            self.logger.info("Starting honeypots...")
            subprocess.run(['docker-compose', '-f', str(self.compose_file), 'up', '-d'],
                         cwd=self.tpot_dir, check=True)  # Start containers
            
            self.logger.info("T-Pot honeypots deployed successfully")  # Log success
            return True  # Return success
            
        except Exception as e:
            self.logger.error(f"Failed to deploy T-Pot honeypots: {str(e)}")  # Log error
            return False  # Return failure
            
    def check_status(self) -> Dict[str, str]:
        """Check status of deployed honeypots"""
        status = {}
        try:
            containers = self.docker_client.containers.list()  # List all containers
            for container in containers:
                if 'dtagdevsec' in container.image.tags[0]:  # Check if container is a honeypot
                    status[container.name] = container.status  # Record container status
        except Exception as e:
            self.logger.error(f"Failed to check honeypot status: {str(e)}")  # Log error
        
        return status  # Return status dictionary