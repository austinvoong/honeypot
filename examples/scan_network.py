# examples/scan_network.py
#!/usr/bin/env python3
import logging
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.network_scanner.scanner import NetworkScanner
from src.utils.config import Config

def main():
    # Configure logging
    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format=Config.LOG_FORMAT
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize scanner
        scanner = NetworkScanner(
            target_network=Config.TARGET_NETWORK,
            interface=Config.INTERFACE
        )
        
        # Run scan
        devices = scanner.scan_network()
        
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
        logger.error("If you need full scanning capabilities, try running with sudo:")
        logger.error("sudo python examples/scan_network.py")
        sys.exit(1)

if __name__ == '__main__':
    main()