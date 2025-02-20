# examples/scan_network.py (modified)
#!/usr/bin/env python3
import logging
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Import your Docker scanner
from docker_device_scanner import DockerDeviceScanner
from src.utils.config import Config

def main():
    # Configure logging
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format=Config.LOG_FORMAT
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Use the Docker scanner instead
        logger.info("Scanning Docker test environment...")
        scanner = DockerDeviceScanner()
        devices = scanner.scan()
        
        # Save results for other components to use
        scanner.save_results(devices)
        
        # Print results
        for device in devices:
            print(f"\nDevice at {device.ip_address}")
            if device.os_type:
                print(f"OS: {device.os_type}")
            print(f"Open ports: {device.open_ports}")
            print(f"Services: {device.services}")
            if device.tcp_fingerprint:
                print(f"TCP Fingerprint: {device.tcp_fingerprint}")
            if device.uptime:
                print(f"Uptime: {device.uptime} hours")
                
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()