# src/honeypot_deploy/coexist_tpot_deployer.py
import asyncio
import logging
import os
import tempfile
import time
import yaml
import json
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple

from src.utils.port_utils import generate_port_mappings, get_all_used_ports

class CoexistRemoteTPotDeployer:
    """
    Deploy honeypots to a remote T-Pot instance while ensuring 
    they coexist with existing honeypots.
    """
    
    def __init__(self, 
                 hostname: str, 
                 port: int = 64295, 
                 username: str = None, 
                 password: str = None, 
                 key_path: str = None,
                 remote_tpot_dir: str = "/opt/tpot",
                 local_output_dir: Path = Path("./scan_results")):
        
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.remote_tpot_dir = remote_tpot_dir
        self.local_output_dir = local_output_dir
        self.logger = logging.getLogger(__name__)
        
        # Ensure output directory exists
        os.makedirs(self.local_output_dir, exist_ok=True)
        
        # Store docker-compose command once determined
        self.docker_compose_cmd = "docker compose"  # Default to modern syntax
    
    async def run_ssh_command(self, command: str, use_sudo: bool = False, use_shell: bool = False) -> Tuple[bool, str, str]:
        """
        Run a command on the remote server via SSH
        
        Args:
            command: Command to execute
            use_sudo: Whether to use sudo
            use_shell: Whether to run in a shell (needed for cd, pipes, etc.)
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        self.logger.info(f"Running command on {self.hostname}: {command}")
        
        # Build the SSH command
        ssh_cmd = ['ssh', '-p', str(self.port)]
        
        # Add key or use password
        if self.key_path:
            ssh_cmd.extend(['-i', self.key_path])
        elif self.password:
            # Use sshpass if password is provided
            ssh_cmd = ['sshpass', '-p', self.password] + ssh_cmd
        
        # Disable strict host key checking
        ssh_cmd.extend(['-o', 'StrictHostKeyChecking=no'])
        
        # Add destination
        ssh_cmd.append(f"{self.username}@{self.hostname}")
        
        # Process the command based on sudo and shell requirements
        if use_sudo:
            if use_shell:
                # For commands that need a shell (e.g., with cd, pipes, etc.)
                # Use sudo -S to read password from stdin if needed
                if self.password:
                    ssh_cmd.append(f"echo '{self.password}' | sudo -S bash -c '{command}'")
                else:
                    ssh_cmd.append(f"sudo bash -c '{command}'")
            else:
                # Simple sudo command
                if self.password:
                    ssh_cmd.append(f"echo '{self.password}' | sudo -S {command}")
                else:
                    ssh_cmd.append(f"sudo {command}")
        else:
            # No sudo needed
            if use_shell:
                ssh_cmd.append(f"bash -c '{command}'")
            else:
                ssh_cmd.append(command)
        
        # Execute the command
        try:
            process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            stdout_str = stdout.decode('utf-8')
            stderr_str = stderr.decode('utf-8')
            
            success = process.returncode == 0
            
            if not success:
                self.logger.error(f"Command failed with exit code {process.returncode}")
                self.logger.error(f"Error output: {stderr_str}")
            
            return success, stdout_str, stderr_str
            
        except Exception as e:
            self.logger.error(f"Failed to execute SSH command: {str(e)}")
            return False, "", str(e)
    
    async def run_scp_command(self, local_path: str, remote_path: str) -> bool:
        """
        Copy a file to the remote server via SCP
        
        Args:
            local_path: Path to local file
            remote_path: Path on remote server
            
        Returns:
            Success status
        """
        self.logger.info(f"Copying {local_path} to {self.hostname}:{remote_path}")
        
        # Build the SCP command
        scp_cmd = ['scp', '-P', str(self.port)]
        
        # Add key or use password
        if self.key_path:
            scp_cmd.extend(['-i', self.key_path])
        elif self.password:
            # Use sshpass if password is provided
            scp_cmd = ['sshpass', '-p', self.password] + scp_cmd
        
        # Disable strict host key checking
        scp_cmd.extend(['-o', 'StrictHostKeyChecking=no'])
        
        # Add source and destination
        scp_cmd.append(local_path)
        scp_cmd.append(f"{self.username}@{self.hostname}:{remote_path}")
        
        # Execute the command
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
            self.logger.error(f"Failed to execute SCP command: {str(e)}")
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

    async def cleanup_old_honeypots(self):
        """
        Remove old honeypot containers that might be in a bad state
        
        Returns:
            Success status
        """
        self.logger.info("Cleaning up old honeypot containers in restart loops...")
        try:
            # Find containers that are restarting
            success, stdout, stderr = await self.run_ssh_command(
                "docker ps -a --filter 'status=restarting' --filter 'name=dyn_' --format '{{.Names}}'",
                use_sudo=True
            )
            
            if success and stdout.strip():
                # Create a list of container names
                containers = stdout.strip().split('\n')
                self.logger.info(f"Found {len(containers)} containers in restart loop")
                
                # Stop and remove them
                for container in containers:
                    self.logger.info(f"Removing container: {container}")
                    await self.run_ssh_command(
                        f"docker stop {container} && docker rm {container}",
                        use_sudo=True,
                        use_shell=True
                    )
                    
            # Additionally, check for old created/exited containers
            success, stdout, stderr = await self.run_ssh_command(
                "docker ps -a --filter 'status=created' --filter 'status=exited' --filter 'name=dyn_' --format '{{.Names}}'",
                use_sudo=True
            )
            
            if success and stdout.strip():
                # Create a list of container names
                containers = stdout.strip().split('\n')
                self.logger.info(f"Found {len(containers)} stopped containers")
                
                # Remove them
                for container in containers:
                    self.logger.info(f"Removing container: {container}")
                    await self.run_ssh_command(
                        f"docker rm {container}",
                        use_sudo=True
                    )
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old honeypots: {str(e)}")
            return False
    
    async def verify_honeypot_health(self, container_names):
        """
        Verify honeypot containers are healthy
        
        Args:
            container_names: List of container names to check
            
        Returns:
            Dictionary mapping container names to health status
        """
        health_status = {}
        
        for name in container_names:
            try:
                # Check container state
                success, stdout, stderr = await self.run_ssh_command(
                    f"docker inspect --format='{{{{.State.Status}}}}' {name}",
                    use_sudo=True
                )
                
                if success:
                    status = stdout.strip()
                    health_status[name] = status
                    
                    if status != "running":
                        self.logger.warning(f"Container {name} is not running properly (status: {status})")
                        
                        # Get logs to help diagnose the issue
                        success, logs, _ = await self.run_ssh_command(
                            f"docker logs --tail 10 {name}",
                            use_sudo=True
                        )
                        
                        if success:
                            self.logger.warning(f"Container logs for {name}:\n{logs}")
                else:
                    health_status[name] = "unknown"
                    self.logger.warning(f"Could not inspect container {name}: {stderr}")
            except Exception as e:
                health_status[name] = "error"
                self.logger.error(f"Error checking health for {name}: {str(e)}")
                
        return health_status

    async def deploy_honeypots(self, config_file: Path) -> bool:
        """
        Deploy honeypots to the remote T-Pot instance that coexist with existing honeypots
        
        Args:
            config_file: Path to honeypot configuration JSON
            
        Returns:
            Success status
        """
        try:
            self.logger.info(f"Deploying honeypots to {self.hostname} using {config_file}")
            
            # Test SSH connection
            self.logger.info(f"Testing SSH connection to {self.username}@{self.hostname}:{self.port}...")
            success, stdout, stderr = await self.run_ssh_command("echo 'SSH connection successful'")
            if not success:
                self.logger.error("SSH connection test failed")
                return False
                
            self.logger.info("SSH connection successful")
            
            # Clean up old honeypots in bad states
            await self.cleanup_old_honeypots()
            
            # Determine which docker-compose command to use
            await self.determine_docker_compose_cmd()
            
            # Load configuration
            with open(config_file) as f:
                configs = json.load(f)
            
            # Prepare destination directories
            success = await self._prepare_directories()
            if not success:
                return False
            
            # Get all used ports on the remote system
            used_ports = await get_all_used_ports(self.run_ssh_command)
            
            # Generate docker-compose file
            compose_config = await self._generate_docker_compose(configs, used_ports)
            
            # Create a temporary file for the docker-compose
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as tmp:
                yaml.dump(compose_config, tmp)
                tmp_path = tmp.name
            
            # Upload the docker-compose file
            remote_compose_path = f"/tmp/dyn_honeypot_compose_{int(time.time())}.yml"
            success = await self.run_scp_command(tmp_path, remote_compose_path)
            os.unlink(tmp_path)  # Remove the temporary file
            
            if not success:
                self.logger.error(f"Failed to upload docker-compose file")
                return False
            
            # Move the docker-compose file to the correct location
            remote_docker_dir = f"{self.remote_tpot_dir}/docker/dyn"
            success, stdout, stderr = await self.run_ssh_command(
                f"mkdir -p {remote_docker_dir} && " + 
                f"cp {remote_compose_path} {remote_docker_dir}/docker-compose.yml",
                use_sudo=True,
                use_shell=True  # Use shell for commands with multiple parts
            )
            
            if not success:
                self.logger.error(f"Failed to move docker-compose file")
                return False
            
            # Deploy the honeypots
            self.logger.info("Deploying honeypots via docker-compose")
            success, stdout, stderr = await self.run_ssh_command(
                f"cd {remote_docker_dir} && {self.docker_compose_cmd} up -d",
                use_sudo=True,
                use_shell=True  # Use shell for cd command
            )
            
            if not success:
                self.logger.error(f"Failed to deploy honeypots: {stderr}")
                return False
            
            # Check the status
            success, stdout, stderr = await self.run_ssh_command(
                f"cd {remote_docker_dir} && {self.docker_compose_cmd} ps",
                use_sudo=True,
                use_shell=True  # Use shell for cd command
            )
            
            self.logger.info(f"Deployment status:\n{stdout}")
            
            # Clean up
            await self.run_ssh_command(f"rm {remote_compose_path}", use_sudo=True)
            
            # Get list of newly deployed containers
            success, stdout, stderr = await self.run_ssh_command(
                f"cd {remote_docker_dir} && {self.docker_compose_cmd} ps --format json",
                use_sudo=True,
                use_shell=True
            )
            
            deployed_containers = []
            if success:
                try:
                    # Try to parse JSON format (newer Docker Compose)
                    containers = json.loads(stdout)
                    deployed_containers = [c.get('Name') for c in containers if isinstance(c, dict)]
                except:
                    # Fall back to parsing regular output (older Docker Compose)
                    # First line of output is often headers
                    lines = stdout.strip().split('\n')
                    if len(lines) > 1:
                        # Skip the header line and extract the first column (container name)
                        for line in lines[1:]:
                            if line.strip():
                                columns = line.strip().split()
                                if columns:  # Make sure we have at least one column
                                    deployed_containers.append(columns[0])
            
            # If we couldn't parse container names from docker-compose output,
            # fall back to a more direct approach
            if not deployed_containers:
                success, stdout, stderr = await self.run_ssh_command(
                    "docker ps --filter 'name=dyn_' --format '{{.Names}}'",
                    use_sudo=True
                )
                
                if success and stdout.strip():
                    deployed_containers = stdout.strip().split('\n')
            
            # Verify health of deployed honeypots
            if deployed_containers:
                self.logger.info(f"Verifying health of {len(deployed_containers)} deployed honeypots...")
                health_status = await self.verify_honeypot_health(deployed_containers)
                
                # Log health status
                for name, status in health_status.items():
                    if status == "running":
                        self.logger.info(f"✓ Container {name} is healthy")
                    else:
                        self.logger.warning(f"✗ Container {name} has status: {status}")
            
            self.logger.info("Honeypots deployed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to deploy honeypots: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False
    
    async def _prepare_directories(self) -> bool:
        """
        Prepare directories on the remote T-Pot instance
        
        Returns:
            Success status
        """
        try:
            # Create directories for data and logs
            commands = [
                # Create base directories
                f"mkdir -p {self.remote_tpot_dir}/docker/dyn",
                f"mkdir -p {self.remote_tpot_dir}/data/dyn_adbhoney/log",
                f"mkdir -p {self.remote_tpot_dir}/data/dyn_heralding/log",
                f"mkdir -p {self.remote_tpot_dir}/data/dyn_cowrie/log",
                f"mkdir -p {self.remote_tpot_dir}/data/dyn_dionaea/log",
                
                # Set permissions
                f"chmod -R 777 {self.remote_tpot_dir}/data/dyn_*",
                
                # Ensure proper ownership
                f"chown -R 1000:1000 {self.remote_tpot_dir}/data/dyn_*"
            ]
            
            for cmd in commands:
                success, stdout, stderr = await self.run_ssh_command(cmd, use_sudo=True)
                if not success:
                    self.logger.error(f"Failed to execute: {cmd}")
                    self.logger.error(f"Error: {stderr}")
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to prepare directories: {str(e)}")
            return False
    
    async def _generate_docker_compose(self, configs: List[Dict], used_ports: Set[int]) -> Dict:
        """
        Generate docker-compose configuration from honeypot configs
        
        Args:
            configs: List of honeypot configurations
            used_ports: Set of already used ports
            
        Returns:
            Docker Compose configuration dictionary
        """
        timestamp = int(time.time())
        
        compose_config = {
            "version": "3",
            "services": {}
        }
        
        # Process each honeypot configuration
        for config in configs:
            cluster_id = config['cluster_id']
            os_type = config.get('os_type', 'unknown')
            services = config.get('services', {})
            
            # Map services to honeypot types
            honeypot_types = set()
            for port_str, service in services.items():
                honeypot_type = self._map_service_to_honeypot(service)
                if honeypot_type:
                    honeypot_types.add(honeypot_type)
                    
            if not honeypot_types:
                self.logger.warning(f"No suitable honeypots found for cluster {cluster_id}")
                continue
                
            # Generate port mappings for services
            port_mappings = await generate_port_mappings(services, self.run_ssh_command)
            
            # Create containers for each honeypot type
            for honeypot_type in honeypot_types:
                container_name = f"dyn_{honeypot_type}_{cluster_id}_{timestamp}_{self._generate_id()}"
                
                # Base configuration
                service_config = {
                    "container_name": container_name,
                    "image": f"ghcr.io/telekom-security/{honeypot_type}:24.04.1",
                    "restart": "always",
                    "volumes": [
                        f"{self.remote_tpot_dir}/data/dyn_{honeypot_type}/{container_name}/:/data",
                        f"{self.remote_tpot_dir}/data/dyn_{honeypot_type}/log/:/opt/{honeypot_type}/log",
                        f"{self.remote_tpot_dir}/data/dyn_{honeypot_type}/log/:/log"
                    ],
                    "environment": {
                        "HONEYPOT_TYPE": honeypot_type,
                        "CLUSTER_ID": str(cluster_id),
                        "OS_TYPE": os_type
                    },
                    "ports": []
                }
                
                # Add honeypot-specific configuration
                await self._add_honeypot_config(service_config, honeypot_type, port_mappings)
                
                # Add to the compose config
                compose_config["services"][container_name] = service_config
                
        return compose_config
    
    def _map_service_to_honeypot(self, service: str) -> Optional[str]:
        """
        Map a service to an appropriate honeypot type
        
        Args:
            service: Service name or type
            
        Returns:
            Honeypot type or None if no suitable honeypot found
        """
        service_lower = service.lower()
        
        # SSH and Telnet services
        if any(s in service_lower for s in ['ssh', 'telnet']):
            return 'cowrie'
            
        # Web services
        if any(s in service_lower for s in ['http', 'web']):
            return 'heralding'
            
        # Database services
        if any(s in service_lower for s in ['sql', 'mysql', 'db']):
            return 'heralding'
            
        # IoT services
        if any(s in service_lower for s in ['adb', 'android']):
            return 'adbhoney'
            
        # File shares, FTP, SMB
        if any(s in service_lower for s in ['ftp', 'smb', 'file']):
            return 'dionaea'
            
        # Default to heralding for unknown services
        return 'heralding'
    
    async def _add_honeypot_config(self, service_config: Dict, honeypot_type: str, port_mappings: Dict[str, Tuple[int, int]]):
        """
        Add honeypot-specific configuration
        
        Args:
            service_config: Service configuration to modify
            honeypot_type: Type of honeypot
            port_mappings: Port mappings dictionary
        """
        from src.utils.port_utils import generate_safe_port
        
        # Get current used ports
        used_ports = await get_all_used_ports(self.run_ssh_command)
        
        # Track allocated ports for this honeypot
        allocated_ports = set()
        
        # Add specific service ports from port_mappings
        for port_str, (host_port, container_port) in port_mappings.items():
            if int(port_str) in [22, 23] and honeypot_type == 'cowrie':
                service_config['ports'].append(f"{host_port}:{container_port}")
                allocated_ports.add(host_port)
            elif honeypot_type == 'heralding' and int(port_str) in [80, 443, 110, 143, 993, 995, 1080, 5432]:
                service_config['ports'].append(f"{host_port}:{container_port}")
                allocated_ports.add(host_port)
            elif honeypot_type == 'dionaea' and int(port_str) in [21, 445, 1433, 3306]:
                service_config['ports'].append(f"{host_port}:{container_port}")
                allocated_ports.add(host_port)
            elif honeypot_type == 'adbhoney' and int(port_str) == 5555:
                service_config['ports'].append(f"{host_port}:{container_port}")
                allocated_ports.add(host_port)
        
        # All ports currently in use plus our newly allocated ones
        all_used_ports = used_ports.union(allocated_ports)
        
        # Add honeypot-specific additional ports
        if honeypot_type == 'cowrie':
            # Only add these if not already in port_mappings
            if not any(int(p) == 22 for p in port_mappings.keys()):
                ssh_port = generate_safe_port(all_used_ports)
                service_config['ports'].append(f"{ssh_port}:22")  # SSH
                all_used_ports.add(ssh_port)
                allocated_ports.add(ssh_port)
                
            if not any(int(p) == 23 for p in port_mappings.keys()):
                telnet_port = generate_safe_port(all_used_ports)
                service_config['ports'].append(f"{telnet_port}:23")  # Telnet
                all_used_ports.add(telnet_port)
                allocated_ports.add(telnet_port)
            
        elif honeypot_type == 'heralding':
            # Define ports that should be exposed for heralding
            heralding_ports = {
                110: "POP3",
                143: "IMAP",
                993: "IMAPS",
                995: "POP3S",
                1080: "SOCKS",
                5432: "PostgreSQL"
            }
            
            # Add each port if not already mapped
            for container_port, service_name in heralding_ports.items():
                if not any(int(p) == container_port for p in port_mappings.keys()):
                    host_port = generate_safe_port(all_used_ports)
                    service_config['ports'].append(f"{host_port}:{container_port}")
                    all_used_ports.add(host_port)
                    allocated_ports.add(host_port)
            
        elif honeypot_type == 'dionaea':
            # Define ports that should be exposed for dionaea
            dionaea_ports = {
                21: "FTP",
                445: "SMB",
                1433: "MSSQL",
                3306: "MySQL"
            }
            
            # Add each port if not already mapped
            for container_port, service_name in dionaea_ports.items():
                if not any(int(p) == container_port for p in port_mappings.keys()):
                    host_port = generate_safe_port(all_used_ports)
                    service_config['ports'].append(f"{host_port}:{container_port}")
                    all_used_ports.add(host_port)
                    allocated_ports.add(host_port)
            
        elif honeypot_type == 'adbhoney':
            # Only add ADB port if not already in port_mappings
            if not any(int(p) == 5555 for p in port_mappings.keys()):
                adb_port = generate_safe_port(all_used_ports)
                service_config['ports'].append(f"{adb_port}:5555")  # ADB
                all_used_ports.add(adb_port)
                allocated_ports.add(adb_port)
    
    def _generate_id(self, length: int = 8) -> str:
        """
        Generate a random ID
        
        Args:
            length: Length of the ID
            
        Returns:
            Random hexadecimal ID
        """
        import random
        return ''.join(random.choice('0123456789abcdef') for _ in range(length))
    
    async def get_honeypot_status(self) -> Dict[str, Dict]:
        """
        Get status of deployed honeypots
        
        Returns:
            Dictionary with container status information
        """
        status = {}
        
        try:
            # Run docker ps command to get container status
            success, stdout, stderr = await self.run_ssh_command(
                "docker ps -a --format '{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}'",
                use_sudo=True
            )
            
            if not success:
                self.logger.error(f"Failed to get container status: {stderr}")
                return status
                
            # Parse the output
            for line in stdout.splitlines():
                if not line.strip():
                    continue
                    
                parts = line.split('|')
                if len(parts) != 4:
                    continue
                    
                container_id, name, status_str, image = parts
                
                # Only include dynamic honeypots
                if name.startswith('dyn_'):
                    status[name] = {
                        'id': container_id,
                        'status': status_str,
                        'image': image
                    }
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get honeypot status: {str(e)}")
            return status
    
    async def get_honeypot_logs(self, container_name: str, lines: int = 50) -> List[str]:
        """
        Get logs from a specific honeypot container
        
        Args:
            container_name: Name of the container
            lines: Number of log lines to retrieve
            
        Returns:
            List of log lines
        """
        try:
            success, stdout, stderr = await self.run_ssh_command(
                f"docker logs {container_name} --tail {lines}",
                use_sudo=True
            )
            
            if not success:
                self.logger.error(f"Failed to get logs for {container_name}: {stderr}")
                return []
                
            return stdout.splitlines()
            
        except Exception as e:
            self.logger.error(f"Failed to get honeypot logs: {str(e)}")
            return []