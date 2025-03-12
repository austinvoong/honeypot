# src/honeypot_deploy/tpot_deployer.py
import asyncio  # For async operations
import logging  # For logging messages
import yaml  # For handling YAML files
import json  # For handling JSON files
from pathlib import Path  # For handling file paths
from typing import List, Dict, Optional, Tuple  # For type hinting
from datetime import datetime
import docker  # For interacting with Docker
import aiohttp  # For async HTTP requests

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
        self.data_dir = tpot_dir / 'data'
        self.log_dir = tpot_dir / 'logs'
        
        # Honeypot templates directory
        self.templates_dir = tpot_dir / 'etc/tpot/templates'
        
        # Service-to-honeypot mapping
        self.service_map = {
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
            'mqtt': ['mqttiot'],
            'coap': ['adbhoney'],
            'upnp': ['dionaea'],
            'smb': ['dionaea'],
            'ntp': ['honeytrap'],
            'tftp': ['honeytrap'],
            'ipp': ['honeytrap']
        }
        
        # Port-to-honeypot fallback mapping
        self.port_map = {
            20: 'honeytrap',   # FTP data
            21: 'honeytrap',   # FTP control
            22: 'cowrie',      # SSH
            23: 'cowrie',      # Telnet
            25: 'mailoney',    # SMTP
            53: 'honeytrap',   # DNS
            80: 'honeypy',     # HTTP
            123: 'honeytrap',  # NTP
            161: 'honeypy',    # SNMP
            443: 'heralding',  # HTTPS
            445: 'dionaea',    # SMB
            502: 'conpot',     # Modbus
            1883: 'mqttiot',   # MQTT
            3306: 'heralding'  # MySQL
        }
        
        # Initialize directories
        self._init_directories()
        
    def _init_directories(self):
        """Initialize required directories"""
        for directory in [self.config_dir, self.templates_dir, self.data_dir, self.log_dir]:
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
        # Try service name matching first
        service_lower = service.lower()
        for svc_type, honeypots in self.service_map.items():
            if svc_type in service_lower:
                return self._get_available_honeypot(honeypots)
                
        # Fall back to port-based mapping
        if port in self.port_map:
            honeypot = self.port_map[port]
            if self._check_honeypot_available(honeypot):
                return honeypot
                
        return None
        
    def _get_available_honeypot(self, honeypots: List[str]) -> Optional[str]:
        """
        Get first available honeypot from a list
        
        Args:
            honeypots: List of potential honeypot types
            
        Returns:
            Available honeypot name or None
        """
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
                'tpot_main': {
                    'driver': 'bridge',
                    'ipam': {
                        'config': [{'subnet': '172.20.0.0/24'}]
                    }
                }
            },
            'services': {}
        }
        
        # Create isolated networks per cluster
        for config in configs:
            cluster_id = config['cluster_id']
            network_name = f"tpot_cluster_{cluster_id}"
            compose_config['networks'][network_name] = {
                'driver': 'bridge',
                'ipam': {
                    'config': [{'subnet': f'172.20.{cluster_id}.0/24'}]
                }
            }
        
        used_ports = set()
        
        # Add ELK stack for better monitoring
        self._add_elk_stack(compose_config)
        
        for config in configs:
            is_valid, error = self._validate_configuration(config)
            if not is_valid:
                self.logger.error(f"Invalid configuration: {error}")
                continue
                
            cluster_id = config['cluster_id']
            network_name = f"tpot_cluster_{cluster_id}"
            
            # Determine required honeypots
            honeypots = set()
            for port, service in config['services'].items():
                hp = self._map_service_to_honeypot(service, int(port))
                if hp:
                    honeypots.add(hp)
                    
            # Configure each honeypot
            for honeypot in honeypots:
                service_name = f"{honeypot}_{cluster_id}"
                
                # Base configuration
                service_config = {
                    'container_name': service_name,
                    'restart': 'always',
                    'networks': [network_name, 'tpot_main'],
                    'image': f"dtagdevsec/{honeypot}:latest",
                    'volumes': [
                        f"{self.config_dir}/{honeypot}/:/etc/{honeypot}/",
                        f"{self.data_dir}/{honeypot}_{cluster_id}:/data",
                        f"{self.log_dir}/{honeypot}_{cluster_id}:/var/log"
                    ],
                    'environment': {
                        'TPOT_CONFIG': 'true',
                        'CLUSTER_ID': str(cluster_id),
                        'HONEYPOT_TYPE': honeypot,
                        'OS_TYPE': config['os_type']
                    },
                    'logging': {
                        'driver': 'json-file',
                        'options': {
                            'max-size': '10m',
                            'max-file': '3'
                        }
                    },
                    'deploy': {
                        'resources': {
                            'limits': {
                                'cpus': '0.5',
                                'memory': '512M'
                            },
                            'reservations': {
                                'cpus': '0.1',
                                'memory': '128M'
                            }
                        }
                    }
                }
                
                # Add ports
                ports = []
                for port, service in config['services'].items():
                    port_num = int(port)
                    if self._map_service_to_honeypot(service, port_num) == honeypot:
                        if port_num not in used_ports:
                            ports.append(f"{port}:{port}")
                            used_ports.add(port_num)
                            
                if ports:
                    service_config['ports'] = ports
                    
                compose_config['services'][service_name] = service_config
                
        return compose_config
        
    def _add_elk_stack(self, compose_config: dict):
        """
        Add ELK stack to docker-compose configuration
        
        Args:
            compose_config: Docker Compose configuration to modify
        """
        # Elasticsearch configuration
        compose_config['services']['elasticsearch'] = {
            'container_name': 'tpot_elasticsearch',
            'image': 'docker.elastic.co/elasticsearch/elasticsearch:7.10.0',
            'restart': 'always',
            'networks': ['tpot_main'],
            'environment': {
                'ES_JAVA_OPTS': '-Xms512m -Xmx512m',
                'discovery.type': 'single-node'
            },
            'volumes': [
                f"{self.data_dir}/elasticsearch:/usr/share/elasticsearch/data"
            ],
            'deploy': {
                'resources': {
                    'limits': {
                        'cpus': '1.0',
                        'memory': '1G'
                    }
                }
            }
        }
        
        # Logstash configuration
        compose_config['services']['logstash'] = {
            'container_name': 'tpot_logstash',
            'image': 'docker.elastic.co/logstash/logstash:7.10.0',
            'restart': 'always',
            'networks': ['tpot_main'],
            'depends_on': ['elasticsearch'],
            'volumes': [
                f"{self.config_dir}/logstash/:/usr/share/logstash/pipeline/",
                f"{self.log_dir}:/var/log/honeypots:ro"
            ],
            'deploy': {
                'resources': {
                    'limits': {
                        'cpus': '0.5',
                        'memory': '512M'
                    }
                }
            }
        }
        
        # Kibana configuration
        compose_config['services']['kibana'] = {
            'container_name': 'tpot_kibana',
            'image': 'docker.elastic.co/kibana/kibana:7.10.0',
            'restart': 'always',
            'networks': ['tpot_main'],
            'depends_on': ['elasticsearch'],
            'ports': ['5601:5601'],
            'environment': {
                'ELASTICSEARCH_URL': 'http://elasticsearch:9200'
            },
            'deploy': {
                'resources': {
                    'limits': {
                        'cpus': '0.5',
                        'memory': '512M'
                    }
                }
            }
        }
        
    async def deploy_honeypots(self, config_file: Path) -> bool:
        """
        Deploy honeypots using T-Pot with improved error handling and async implementation
        
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
            process = await asyncio.create_subprocess_exec(
                'docker-compose', '-f', str(self.compose_file), 'down',
                cwd=self.tpot_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Failed to stop containers: {stderr.decode()}")
            
            # Pull latest images
            self.logger.info("Pulling latest honeypot images...")
            process = await asyncio.create_subprocess_exec(
                'docker-compose', '-f', str(self.compose_file), 'pull',
                cwd=self.tpot_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Failed to pull images: {stderr.decode()}")
            
            # Start new containers
            self.logger.info("Starting honeypots...")
            process = await asyncio.create_subprocess_exec(
                'docker-compose', '-f', str(self.compose_file), 'up', '-d',
                cwd=self.tpot_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Failed to start containers: {stderr.decode()}")
            
            # Verify deployment
            if not await self._verify_deployment_async(compose_config):
                raise Exception("Deployment verification failed")
                
            self.logger.info("T-Pot honeypots deployed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to deploy T-Pot honeypots: {str(e)}")
            return False
            
    async def _verify_deployment_async(self, compose_config: Dict) -> bool:
        """
        Async verify honeypot deployment status
        
        Args:
            compose_config: Docker Compose configuration
            
        Returns:
            bool: Verification status
        """
        try:
            expected_containers = set(compose_config['services'].keys())
            running_containers = set()
            
            # Give containers time to start up
            await asyncio.sleep(10)
            
            containers = self.docker_client.containers.list()
            for container in containers:
                if 'dtagdevsec' in container.image.tags[0] or any(
                    tag in container.image.tags[0] for tag in ['elasticsearch', 'logstash', 'kibana']
                ):
                    if container.status != 'running':
                        self.logger.error(f"Container {container.name} is not running")
                        return False
                    running_containers.add(container.name)
                    
            # Check if all expected containers are running
            if not expected_containers.issubset(running_containers):
                missing = expected_containers - running_containers
                self.logger.error(f"Missing containers: {missing}")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Async deployment verification failed: {str(e)}")
            return False
            
    async def get_honeypot_status_async(self) -> Dict[str, Dict]:
        """
        Get detailed status of deployed honeypots (async version)
        
        Returns:
            Dict with container status information
        """
        status = {}
        try:
            containers = self.docker_client.containers.list(all=True)
            for container in containers:
                if 'dtagdevsec' in container.image.tags[0] or any(
                    tag in container.image.tags[0] for tag in ['elasticsearch', 'logstash', 'kibana']
                ):
                    # Get container stats
                    stats = container.stats(stream=False)
                    
                    # Extract network stats safely
                    network_rx = 0
                    network_tx = 0
                    if 'networks' in stats and 'eth0' in stats['networks']:
                        network_rx = stats['networks']['eth0']['rx_bytes']
                        network_tx = stats['networks']['eth0']['tx_bytes']
                    
                    status[container.name] = {
                        'status': container.status,
                        'image': container.image.tags[0],
                        'created': container.attrs['Created'],
                        'ports': container.ports,
                        'cpu_usage': stats['cpu_stats']['cpu_usage']['total_usage'],
                        'memory_usage': stats['memory_stats'].get('usage', 0),
                        'network_rx': network_rx,
                        'network_tx': network_tx
                    }
                    
        except Exception as e:
            self.logger.error(f"Failed to get honeypot status: {str(e)}")
            
        return status
        
    async def get_honeypot_logs_async(self, container_name: str, tail: int = 100) -> List[str]:
        """
        Get logs from a specific honeypot container (async version)
        
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
            
    async def monitor_and_reconfigure(self, scanner, clusterer, config_gen, interval=3600):
        """
        Monitor network for changes and reconfigure honeypots as needed
        
        Args:
            scanner: Network scanner object
            clusterer: Device clusterer object
            config_gen: Honeypot configuration generator object
            interval: Monitoring interval in seconds
        """
        self.logger.info(f"Starting network monitoring (interval: {interval}s)")
        
        while True:
            try:
                # Scan network
                self.logger.info("Scanning network for changes...")
                devices = scanner.scan()
                
                # Skip if no devices found
                if not devices:
                    self.logger.warning("No devices found in network")
                    await asyncio.sleep(interval)
                    continue
                
                # Analyze and cluster devices
                clusters = clusterer.cluster_devices(devices, method='kmeans')
                
                # Generate honeypot configurations
                configs = config_gen.generate_config(clusters)
                config_file = config_gen.save_configs(configs)
                
                # Check if configuration has changed significantly
                if await self._should_reconfigure(config_file):
                    self.logger.info("Network changes detected, reconfiguring honeypots...")
                    await self.deploy_honeypots(config_file)
                else:
                    self.logger.info("No significant changes detected, continuing monitoring")
                
            except Exception as e:
                self.logger.error(f"Monitoring error: {str(e)}")
                
            # Wait for next monitoring cycle
            await asyncio.sleep(interval)
            
    async def _should_reconfigure(self, new_config_file: Path) -> bool:
        """
        Determine if honeypots should be reconfigured based on config changes
        
        Args:
            new_config_file: Path to new configuration file
            
        Returns:
            bool: True if reconfiguration is needed
        """
        try:
            # Load new configuration
            with open(new_config_file) as f:
                new_configs = json.load(f)
                
            # Get current running containers
            containers = self.docker_client.containers.list()
            running_honeypots = set()
            
            for container in containers:
                if 'dtagdevsec' in container.image.tags[0]:
                    # Extract honeypot type and cluster ID from container name
                    parts = container.name.split('_')
                    if len(parts) >= 2:
                        honeypot_type = parts[0]
                        cluster_id = parts[1]
                        running_honeypots.add((honeypot_type, cluster_id))
            
            # Check for new honeypots
            for config in new_configs:
                cluster_id = str(config['cluster_id'])
                for port, service in config['services'].items():
                    honeypot_type = self._map_service_to_honeypot(service, int(port))
                    if honeypot_type and (honeypot_type, cluster_id) not in running_honeypots:
                        self.logger.info(f"New honeypot needed: {honeypot_type} for cluster {cluster_id}")
                        return True
            
            # If we get here, no major changes detected
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking for configuration changes: {str(e)}")
            # In case of error, trigger reconfiguration to be safe
            return True
    
    def get_honeypot_status(self) -> Dict[str, Dict]:
        """
        Synchronous wrapper for get_honeypot_status_async
        """
        return asyncio.run(self.get_honeypot_status_async())
    
    def get_honeypot_logs(self, container_name: str, tail: int = 100) -> List[str]:
        """
        Synchronous wrapper for get_honeypot_logs_async
        """
        return asyncio.run(self.get_honeypot_logs_async(container_name, tail))