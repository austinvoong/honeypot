# src/honeypot_deploy/remote_tpot_deployer.py
import asyncio
import logging
import os
import yaml
import json
import re
import tempfile
from typing import Dict, Optional, List, Any
from pathlib import Path

class RemoteTPotDeployer:
    """
    Remote T-Pot honeypot deployer using SSH
    """
    
    def __init__(self, hostname: str, port: int = 64295, username: str = 'tpot',
                 password: Optional[str] = None, key_path: Optional[str] = None,
                 remote_tpot_dir: str = '/opt/tpot', local_output_dir: Path = Path('output')):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.remote_tpot_dir = remote_tpot_dir
        self.local_output_dir = local_output_dir
        self.logger = logging.getLogger(__name__)
        
        # Directory for dynamic honeypots (separate from main T-Pot config)
        self.remote_dyn_dir = f"{self.remote_tpot_dir}/docker/dyn"
        
        # Store docker-compose command once determined
        self.docker_compose_cmd = "docker compose"  # Default to modern syntax
        
    async def run_ssh_command(self, command: str, use_sudo: bool = False, use_shell: bool = False) -> tuple:
        """
        Run command via SSH on remote T-Pot instance
        
        Args:
            command: Command to run
            use_sudo: Whether to run with sudo
            use_shell: Whether to run in a shell (needed for cd, etc.)
        """
        self.logger.info(f"Running command: {command}")
        
        # Build SSH command
        ssh_cmd = ['ssh', '-p', str(self.port), '-o', 'StrictHostKeyChecking=no']
        
        # Add authentication
        if self.key_path:
            ssh_cmd.extend(['-i', self.key_path])
        elif self.password:
            # Use sshpass if password is provided
            ssh_cmd = ['sshpass', '-p', self.password] + ssh_cmd
        
        # Build the target
        target = f"{self.username}@{self.hostname}"
        
        # Process the command based on sudo and shell requirements
        if use_sudo:
            if use_shell:
                # For commands that need a shell (e.g., with cd, pipes, etc.)
                # Use sudo -S to read password from stdin if needed
                if self.password:
                    ssh_cmd.extend([target, f"echo '{self.password}' | sudo -S sh -c '{command}'"])
                else:
                    ssh_cmd.extend([target, f"sudo sh -c '{command}'"])
            else:
                # Simple sudo command
                if self.password:
                    ssh_cmd.extend([target, f"echo '{self.password}' | sudo -S {command}"])
                else:
                    ssh_cmd.extend([target, f"sudo {command}"])
        else:
            # No sudo needed
            ssh_cmd.extend([target, command])
            
        # Run the command
        try:
            process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            success = process.returncode == 0
            stdout_str = stdout.decode('utf-8')
            stderr_str = stderr.decode('utf-8')
            
            if not success:
                self.logger.error(f"SSH command failed with exit code {process.returncode}")
                self.logger.error(f"Error output: {stderr_str}")
                
            return success, stdout_str, stderr_str
            
        except Exception as e:
            self.logger.error(f"Failed to run SSH command: {str(e)}")
            return False, "", str(e)
            
    async def run_scp_command(self, local_path: str, remote_path: str) -> bool:
        """Copy file to remote T-Pot instance"""
        self.logger.info(f"Uploading {local_path} to {remote_path}")
        
        # Build SCP command
        scp_cmd = ['scp', '-P', str(self.port), '-o', 'StrictHostKeyChecking=no']
        
        # Add authentication
        if self.key_path:
            scp_cmd.extend(['-i', self.key_path])
        elif self.password:
            # Use sshpass if password is provided
            scp_cmd = ['sshpass', '-p', self.password] + scp_cmd
            
        # Add source and destination
        target = f"{self.username}@{self.hostname}:{remote_path}"
        scp_cmd.extend([local_path, target])
        
        # Run SCP command
        try:
            process = await asyncio.create_subprocess_exec(
                *scp_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            success = process.returncode == 0
            if not success:
                self.logger.error(f"SCP failed with exit code {process.returncode}")
                self.logger.error(f"Error output: {stderr.decode('utf-8')}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to run SCP command: {str(e)}")
            return False
    
    async def determine_docker_compose_cmd(self) -> str:
        """Determine which docker-compose command to use"""
        self.logger.info("Determining docker-compose command...")
        success, stdout, stderr = await self.run_ssh_command(
            "which docker-compose || echo 'docker compose'"
        )
        
        if success and stdout.strip() and "not found" not in stdout:
            self.docker_compose_cmd = stdout.strip()
        else:
            # Use the new docker compose command as fallback
            self.docker_compose_cmd = "docker compose"
            
        self.logger.info(f"Using docker-compose command: {self.docker_compose_cmd}")
        return self.docker_compose_cmd
            
    async def deploy_honeypots(self, config_file: str) -> bool:
        """Deploy honeypots to remote T-Pot instance"""
        # Test SSH connection
        self.logger.info(f"Testing SSH connection to {self.username}@{self.hostname}:{self.port}...")
        success, stdout, stderr = await self.run_ssh_command("echo 'SSH connection successful'")
        if not success:
            self.logger.error("SSH connection test failed")
            return False
            
        self.logger.info("SSH connection successful")
        
        # Test sudo access
        self.logger.info("Testing sudo access...")
        success, stdout, stderr = await self.run_ssh_command("sudo -n echo 'Sudo access confirmed'", use_sudo=True)
        if "Password" in stderr or not success:
            # Sudo requires password or failed
            self.logger.warning("Sudo might require password input. Commands will prompt for password.")
        else:
            self.logger.info("Sudo access confirmed")
            
        # Determine which docker-compose command to use
        await self.determine_docker_compose_cmd()
        
        # Load honeypot configurations
        try:
            with open(config_file, 'r') as f:
                configs = json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load honeypot configurations: {str(e)}")
            return False
            
        # Generate docker-compose.yml
        docker_compose = await self._generate_docker_compose(configs)
        
        if not docker_compose:
            self.logger.error("Failed to generate docker-compose.yml")
            return False
            
        # Save docker-compose.yml locally
        local_compose_path = os.path.join(self.local_output_dir, 'docker-compose.yml')
        try:
            os.makedirs(os.path.dirname(local_compose_path), exist_ok=True)
            with open(local_compose_path, 'w') as f:
                yaml.dump(docker_compose, f)
                
            self.logger.info(f"Generated docker-compose.yml at {local_compose_path}")
        except Exception as e:
            self.logger.error(f"Failed to save docker-compose.yml: {str(e)}")
            return False
            
        # Upload docker-compose.yml
        self.logger.info(f"Uploading docker-compose.yml to /tmp/docker-compose.yml")
        if not await self.run_scp_command(local_compose_path, "/tmp/docker-compose.yml"):
            self.logger.error("Failed to upload docker-compose.yml")
            return False
            
        # Create directory for dynamic honeypots if it doesn't exist
        self.logger.info(f"Creating directory for dynamic honeypots: {self.remote_dyn_dir}")
        await self.run_ssh_command(f"mkdir -p {self.remote_dyn_dir}", use_sudo=True)
            
        # Move docker-compose.yml to T-Pot directory
        self.logger.info(f"Moving docker-compose.yml to {self.remote_dyn_dir}/docker-compose.yml")
        success, stdout, stderr = await self.run_ssh_command(
            f"mv /tmp/docker-compose.yml {self.remote_dyn_dir}/docker-compose.yml",
            use_sudo=True
        )
        if not success:
            self.logger.error("Failed to move docker-compose.yml")
            return False
        
        # Clean up any previous containers (with --remove-orphans)
        self.logger.info("Stopping existing honeypots...")
        success, stdout, stderr = await self.run_ssh_command(
            f"cd {self.remote_dyn_dir} && {self.docker_compose_cmd} down --remove-orphans",
            use_sudo=True,
            use_shell=True  # Use shell for cd command
        )
        if not success:
            self.logger.warning(f"Failed to stop containers: {stderr}")
            
        # Pull latest honeypot images
        self.logger.info("Pulling latest honeypot images...")
        success, stdout, stderr = await self.run_ssh_command(
            f"cd {self.remote_dyn_dir} && {self.docker_compose_cmd} pull",
            use_sudo=True,
            use_shell=True  # Use shell for cd command
        )
        if not success:
            self.logger.error(f"Failed to pull images: {stderr}")
            
        # Create data directories for honeypots
        data_dirs = await self._get_data_directories(docker_compose)
        for data_dir in data_dirs:
            success, stdout, stderr = await self.run_ssh_command(
                f"mkdir -p {data_dir}",
                use_sudo=True
            )
            if not success:
                self.logger.warning(f"Failed to create data directory {data_dir}: {stderr}")
                
        # Start honeypots
        self.logger.info("Starting honeypots...")
        success, stdout, stderr = await self.run_ssh_command(
            f"cd {self.remote_dyn_dir} && {self.docker_compose_cmd} up -d",
            use_sudo=True,
            use_shell=True  # Use shell for cd command
        )
        if not success:
            self.logger.error(f"Failed to start honeypots: {stderr}")
            return False
            
        # Verify honeypots are running
        self.logger.info("Verifying honeypots are running...")
        success, stdout, stderr = await self.run_ssh_command(
            f"cd {self.remote_dyn_dir} && {self.docker_compose_cmd} ps",
            use_sudo=True,
            use_shell=True  # Use shell for cd command
        )
        if success:
            self.logger.info("Honeypots running:")
            self.logger.info(stdout)
            
        # Get honeypot status
        status = await self.get_honeypot_status()
        if status:
            self.logger.info("Honeypot status:")
            for name, info in status.items():
                self.logger.info(f"  {name}: {info['status']}")
                
        return True
        
    async def _generate_docker_compose(self, configs: List[Dict]) -> Dict:
        """Generate docker-compose configuration for dynamic honeypots"""
        from src.utils.port_utils import generate_port_mappings
        
        compose_config = {
            'version': '2.3',
            'services': {}
        }
        
        for config in configs:
            cluster_id = config['cluster_id']
            os_type = config.get('os_type', 'Linux')
            
            # Process each service in the configuration
            port_mappings = await generate_port_mappings(config['services'], self.run_ssh_command)
            
            for port_str, service_name in config['services'].items():
                # Skip if we couldn't find an available port for this service
                if port_str not in port_mappings:
                    continue
                    
                host_port, container_port = port_mappings[port_str]
                
                # Generate honeypot configuration
                honeypot_config = await self._map_service_to_honeypot(service_name, int(port_str), cluster_id)
                if not honeypot_config:
                    continue
                    
                container_name, image, volumes = honeypot_config
                
                # Create the service configuration
                service_config = {
                    'container_name': container_name,
                    'image': image,
                    'restart': 'always',
                    'networks': ['default'],
                    'ports': [f"{host_port}:{container_port}"],
                    'volumes': volumes,
                    'environment': {
                        'CLUSTER_ID': str(cluster_id),
                        'HONEYPOT_TYPE': container_name.split('_')[1],
                        'OS_TYPE': os_type
                    }
                }
                
                # Add service to compose config
                # Use a valid service name (no special chars)
                service_name_clean = f"{container_name}"
                compose_config['services'][service_name_clean] = service_config
        
        return compose_config
            
    async def _map_service_to_honeypot(self, service: str, port: int, cluster_id: int) -> Optional[tuple]:
        """
        Map service to appropriate T-Pot honeypot
        
        Args:
            service: Service name
            port: Port number
            cluster_id: Cluster ID for naming
            
        Returns:
            Tuple of (container_name, image, volumes) or None if no mapping found
        """
        import time
        import uuid
        
        # Registry information
        registry = "ghcr.io/telekom-security"
        tag = "24.04.1"
        timestamp = int(time.time())
        random_id = str(uuid.uuid4())[:8]
        
        # Service mapping to honeypot types
        service_map = {
            'ftp': ['dionaea', 'honeytrap'],
            'ssh': ['cowrie'],
            'telnet': ['cowrie'],
            'http': ['heralding', 'snare'],
            'https': ['snare'],
            'smtp': ['mailoney'],
            'sip': ['dionaea'],
            'mysql': ['heralding', 'dionaea'],
            'redis': ['redishoneypot'],
            'mqtt': ['adbhoney'],
            'rtsp': ['adbhoney'],
            'unknown': ['heralding']
        }
        
        # Default to heralding for all services (simple and versatile)
        honeypot_type = 'heralding'
        
        # Try to find a specific honeypot for this service
        service_lower = service.lower()
        for svc_type, honeypots in service_map.items():
            if svc_type in service_lower:
                honeypot_type = honeypots[0]
                break
                
        # Common port mappings
        port_map = {
            22: 'cowrie',     # SSH
            23: 'cowrie',     # Telnet
            25: 'mailoney',   # SMTP
            80: 'heralding',  # HTTP
            443: 'heralding', # HTTPS
            1883: 'adbhoney', # MQTT
            5060: 'dionaea',  # SIP
            3306: 'dionaea'   # MySQL
        }
        
        if port in port_map:
            honeypot_type = port_map[port]
            
        # Create container name with unique identifier
        container_name = f"dyn_{honeypot_type}_{cluster_id}_{timestamp}_{random_id}"
        
        # Create image name
        image = f"{registry}/{honeypot_type}:{tag}"
        
        # Create volumes
        volumes = [
            f"/data/dyn_{honeypot_type}/{container_name}/:/data",
            f"/data/dyn_{honeypot_type}/{container_name}/log:/var/log"
        ]
        
        return (container_name, image, volumes)
    
    async def _get_data_directories(self, docker_compose: Dict) -> List[str]:
        """Get all data directories from docker-compose configuration"""
        data_dirs = []
        
        for service_name, service_config in docker_compose.get('services', {}).items():
            volumes = service_config.get('volumes', [])
            for volume in volumes:
                if ':' in volume:
                    host_path, _ = volume.split(':', 1)
                    data_dirs.append(host_path)
                    
        return data_dirs
    
    async def get_honeypot_status(self) -> Dict:
        """Get status of deployed honeypots"""
        # Determine docker-compose command if not already done
        if not hasattr(self, 'docker_compose_cmd') or not self.docker_compose_cmd:
            await self.determine_docker_compose_cmd()
            
        success, stdout, stderr = await self.run_ssh_command(
            f"cd {self.remote_dyn_dir} && {self.docker_compose_cmd} ps",
            use_sudo=True,
            use_shell=True  # Use shell for cd command
        )
        
        if not success:
            self.logger.warning("Failed to get honeypot status")
            return {}
            
        try:
            # Parse basic Docker Compose PS output (not relying on JSON format)
            containers = {}
            lines = stdout.strip().split('\n')
            
            # Skip the header line
            if len(lines) > 1:
                header = lines[0]
                for line in lines[1:]:
                    if not line.strip():
                        continue
                    # Extract container name (first column)
                    parts = line.split()
                    if parts:
                        name = parts[0]
                        # Status is usually in the 4th-5th columns, but format may vary
                        status = "running" if "Up" in line else "stopped"
                        # Extract ports from the last part
                        ports = line[line.find('0.0.0.0:'):] if '0.0.0.0:' in line else ""
                        
                        containers[name] = {
                            'status': status,
                            'ports': ports
                        }
                        
            return containers
            
        except Exception as e:
            self.logger.error(f"Failed to parse honeypot status: {str(e)}")
            return {}