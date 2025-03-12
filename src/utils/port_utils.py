# src/utils/port_utils.py
from typing import Set, List, Dict, Tuple, Optional
import random
import logging

logger = logging.getLogger(__name__)

async def get_all_used_ports(ssh_command_func) -> Set[int]:
    """Get all ports in use on the system (more comprehensive approach)"""
    used_ports = set()
    
    # Method 1: Check Docker container ports
    logger.info("Checking Docker container ports...")
    success, stdout, stderr = await ssh_command_func(
        "sudo docker ps --format '{{.Ports}}'", 
        use_sudo=True
    )
    
    if success:
        import re
        port_pattern = re.compile(r'(\d+)->(\d+)')
        for line in stdout.splitlines():
            matches = port_pattern.findall(line)
            for host_port, container_port in matches:
                used_ports.add(int(host_port))
    
    # Method 2: Use netstat to get ALL ports in use (including non-Docker)
    logger.info("Checking all listening ports with netstat...")
    success, stdout, stderr = await ssh_command_func(
        "sudo netstat -tulpn | grep LISTEN | awk '{print $4}' | awk -F: '{print $NF}'",
        use_sudo=True
    )
    
    if success:
        for line in stdout.splitlines():
            try:
                if line.strip():
                    port = int(line.strip())
                    used_ports.add(port)
            except ValueError:
                pass
    
    # Method 3: Check with ss (newer alternative to netstat)
    logger.info("Checking all listening ports with ss...")
    success, stdout, stderr = await ssh_command_func(
        "sudo ss -tulpn | grep LISTEN | awk '{print $5}' | awk -F: '{print $NF}'",
        use_sudo=True
    )
    
    if success:
        for line in stdout.splitlines():
            try:
                if line.strip():
                    port = int(line.strip())
                    used_ports.add(port)
            except ValueError:
                pass
    
    # Method 4: Get all bound UDP ports as well
    logger.info("Checking UDP ports...")
    success, stdout, stderr = await ssh_command_func(
        "sudo netstat -uln | grep -v 'Active' | grep -v 'Proto' | awk '{print $4}' | awk -F: '{print $NF}'",
        use_sudo=True
    )
    
    if success:
        for line in stdout.splitlines():
            try:
                if line.strip():
                    port = int(line.strip())
                    used_ports.add(port)
            except ValueError:
                pass
    
    # Add well-known ports and system ports to the reserved list as a precaution
    for port in range(1, 1024):
        used_ports.add(port)
    
    # Add common service ports that might be in use
    common_service_ports = [
        80, 443, 22, 23, 21, 25, 8080, 8443, 3306, 5432,
        27017, 6379, 11211, 9200, 9300, 1521, 5601,
        3389, 5900, 5901, 6000, 7001, 8000, 8081, 8082, 8443,
        8888, 9000, 9090, 9091, 9092, 10000
    ]
    
    for port in common_service_ports:
        used_ports.add(port)
    
    # Add the T-Pot specific ports
    # For commonly used T-Pot ports and services
    tpot_ports = [
        64294, 64295, 64296, 64297,  # SSH and admin ports
        64298, 64299, 64300,         # Web UI ports
        2222, 2223,                  # SSH honeypot ports
        8090, 9100, 9200, 9300       # Common T-Pot UI and service ports
    ]
    
    for port in tpot_ports:
        used_ports.add(port)
    
    logger.info(f"Found {len(used_ports)} ports already in use")
    return used_ports

def generate_safe_port(used_ports: Set[int], preferred_range: Tuple[int, int] = (40000, 60000)) -> int:
    """
    Generate a random safe port in the preferred range that's not in use
    
    Args:
        used_ports: Set of ports already in use
        preferred_range: Tuple of (min_port, max_port) to use for selection
        
    Returns:
        An available port number
    """
    start, end = preferred_range
    
    # Create a shuffled list of potential ports
    candidate_ports = list(range(start, end))
    random.shuffle(candidate_ports)
    
    # Try ports one by one until we find an unused one
    for port in candidate_ports:
        if port not in used_ports:
            # Verify we're not too close to another used port
            # Some applications might use neighboring ports
            if port-1 not in used_ports and port+1 not in used_ports:
                return port
    
    # If all ports in the range are used (highly unlikely), try a different range
    fallback_range = (20000, 39999)
    start, end = fallback_range
    all_ports = list(range(start, end))
    random.shuffle(all_ports)
    
    for port in all_ports:
        if port not in used_ports:
            return port
    
    # This is almost impossible - all TCP ports are in use
    raise RuntimeError("Could not find any available port in ranges 20000-60000")

def find_available_port(used_ports: Set[int], preferred_port: int, max_offset: int = 100) -> Optional[int]:
    """
    Find an available port, prioritizing high port ranges
    
    Args:
        used_ports: Set of ports already in use
        preferred_port: The preferred port number (often ignored for safety)
        max_offset: Maximum offset to try from the preferred port
        
    Returns:
        An available port number
    """
    # For safety, let's ignore the preferred port if it's low
    if preferred_port < 1024:
        # Skip preferred port and go straight to high port range
        return generate_safe_port(used_ports)
    
    # If the preferred port is not a low port and is available, use it
    if preferred_port >= 1024 and preferred_port <= 65535 and preferred_port not in used_ports:
        # Double-check adjacent ports aren't in use (for safety)
        if preferred_port-1 not in used_ports and preferred_port+1 not in used_ports:
            return preferred_port
    
    # Try high ports in the range 40000-60000 (safer range)
    return generate_safe_port(used_ports)

async def generate_port_mappings(services: Dict[str, str], ssh_command_func) -> Dict[str, Tuple[int, int]]:
    """
    Generate port mappings for services that avoid conflicts with existing ports
    
    Args:
        services: Dictionary of service ports to service names
        ssh_command_func: Function to run SSH commands
        
    Returns:
        Dictionary of service to (host_port, container_port) tuples
    """
    # Get ALL used ports (more comprehensive approach)
    used_ports = await get_all_used_ports(ssh_command_func)
    logger.info(f"Found {len(used_ports)} ports already in use")
    
    # Result mapping
    port_mappings = {}
    
    # Track ports we allocate to avoid conflicts
    allocated_ports = set(used_ports)
    
    # Process each service, using higher port ranges and more safety checks
    for port_str, service_name in services.items():
        container_port = int(port_str)
        
        # Generate a port in the safer range
        host_port = generate_safe_port(allocated_ports)
        
        # Add to our allocated set to avoid reusing it
        allocated_ports.add(host_port)
        
        # Add to our mappings
        port_mappings[f"{port_str}"] = (host_port, container_port)
        
        logger.info(f"Mapped {service_name} port {container_port} to host port {host_port}")
    
    return port_mappings