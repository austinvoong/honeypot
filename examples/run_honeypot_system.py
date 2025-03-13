# examples/run_honeypot_system.py
import logging
import sys
import os
import asyncio
import json
from pathlib import Path
import argparse

# Add project root to Python path correctly
current_dir = Path(os.path.dirname(os.path.abspath(__file__)))
project_root = current_dir.parent
sys.path.insert(0, str(project_root))

# Now import project modules
try:
    from src.network_scanner.docker_device_scanner import DockerDeviceScanner
    from src.network_scanner.models import DeviceFingerprint
    from src.feature_analysis.clustering import DeviceClusterer
    from src.honeypot_config.generator import HoneypotConfigGenerator
    from src.honeypot_deploy.remote_tpot_deployer import RemoteTPotDeployer
    from src.honeypot_deploy.coexist_tpot_deployer import CoexistRemoteTPotDeployer
    from src.utils.config import Config
except ImportError as e:
    print(f"Import error: {e}")
    print(f"Current path: {os.getcwd()}")
    print(f"Python path: {sys.path}")
    sys.exit(1)

def load_devices_from_scan(scan_file_path: str) -> list:
    """Load devices from a previously saved scan file"""
    print(f"Loading devices from scan file: {scan_file_path}")
    try:
        with open(scan_file_path, 'r') as f:
            device_data = json.load(f)
        
        # Convert JSON data back to DeviceFingerprint objects
        devices = []
        for item in device_data:
            device = DeviceFingerprint(
                ip_address=item.get('ip_address', ''),
                os_type=item.get('os_type', 'Linux'),
                open_ports=item.get('open_ports', []),
                services=item.get('services', {}),
                tcp_fingerprint=item.get('tcp_fingerprint', ''),
                uptime=item.get('uptime', 0)
            )
            
            # Add optional attributes if they exist
            if 'mac_address' in item:
                device.mac_address = item['mac_address']
                
            if 'device_type' in item:
                device.device_type = item['device_type']
                
            if 'http_headers' in item:
                device.http_headers = item['http_headers']
                
            devices.append(device)
            
        print(f"Loaded {len(devices)} devices from scan file")
        return devices
    except Exception as e:
        print(f"Error loading scan file: {e}")
        return []

async def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Run the dynamic honeypot system')
    parser.add_argument('--monitor', action='store_true', help='Enable continuous monitoring')
    parser.add_argument('--interval', type=int, default=3600, help='Monitoring interval in seconds')
    parser.add_argument('--no-deploy', action='store_true', help='Skip deployment step')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--scan-file', type=str, help='Use scan file instead of live scanning')
    
    # Remote deployment options
    parser.add_argument('--remote', action='store_true', help='Deploy to remote T-Pot instance')
    parser.add_argument('--host', type=str, help='Remote T-Pot hostname or IP')
    parser.add_argument('--port', type=int, default=64295, help='Remote SSH port (default: 64295)')
    parser.add_argument('--user', type=str, help='Remote SSH username')
    parser.add_argument('--password', type=str, help='Remote SSH password')
    parser.add_argument('--key', type=str, help='Path to SSH private key file')
    parser.add_argument('--remote-dir', type=str, default='/opt/tpot', help='Remote T-Pot directory')
    
    # clustering method
    parser.add_argument('--clustering-method', type=str, default='kmeans', 
                    choices=['kmeans', 'dbscan'], 
                    help='Clustering method to use (default: kmeans)')
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    try:
        # Use either scan file or live scanning
        if args.scan_file:
            # Use provided scan file
            devices = load_devices_from_scan(args.scan_file)
        else:
            # Default scan file if none provided
            default_scan_file = "scan_results/network_scan_20250306_215405.json"
            if os.path.exists(default_scan_file):
                devices = load_devices_from_scan(default_scan_file)
            else:
                # 1. Scan using Docker scanner (now optional)
                logger.info("Scanning Docker test environment...")
                scanner = DockerDeviceScanner()
                devices = scanner.scan()
                scanner.save_results(devices)
                
        logger.info(f"Working with {len(devices)} devices")
        
        if not devices:
            logger.error("No devices found. Please check scan file or Docker environment")
            return
        
        # 2. Analyze and cluster devices
        logger.info("Clustering devices...")
        clusterer = DeviceClusterer()
        clusters = clusterer.cluster_devices(devices, method=args.clustering_method)
        logger.info(f"Created {len(clusters)} device clusters")
        
        for cluster_id, cluster_devices in clusters.items():
            logger.info(f"Cluster {cluster_id}: {len(cluster_devices)} devices")
            # Display a sample of devices from each cluster
            for device in cluster_devices[:3]:
                logger.info(f"  - {device.ip_address} ({device.os_type}): {len(device.open_ports)} ports")
            if len(cluster_devices) > 3:
                logger.info(f"  - ... and {len(cluster_devices) - 3} more devices")
        
        # 3. Generate honeypot configurations
        logger.info("Generating honeypot configurations...")
        # Create output directory if it doesn't exist
        output_dir = Path('./scan_results')
        output_dir.mkdir(exist_ok=True)
        
        config_gen = HoneypotConfigGenerator(output_dir)
        configs = config_gen.generate_config(clusters)
        config_file = config_gen.save_configs(configs)
        logger.info(f"Generated {len(configs)} honeypot configurations")
        
        # 4. Deploy honeypots to T-Pot if not skipped
        if not args.no_deploy:
            if args.remote:
                # Validate remote deployment parameters
                if not args.host:
                    logger.error("Remote host (--host) is required for remote deployment")
                    return
                
                if not args.password and not args.key:
                    logger.error("Either password (--password) or SSH key (--key) is required for remote deployment")
                    return
                    
                logger.info(f"Deploying honeypots to remote T-Pot at {args.host}:{args.port}...")
                deployer = CoexistRemoteTPotDeployer( #Switch deployer type here
                    hostname=args.host,
                    port=args.port,
                    username=args.user,
                    password=args.password,
                    key_path=args.key,
                    remote_tpot_dir=args.remote_dir,
                    local_output_dir=output_dir
                )
                
                success = await deployer.deploy_honeypots(config_file)
                
                if success:
                    logger.info("Honeypots deployed successfully!")
                    
                    # Get honeypot status
                    status = await deployer.get_honeypot_status()
                    logger.info("T-Pot honeypot status:")
                    for name, info in status.items():
                        logger.info(f"  {name}: {info['status']}")
                else:
                    logger.error("Failed to deploy honeypots")
            else:
                logger.error("Local deployment not supported. Use --remote for T-Pot in UTM")
        else:
            logger.info("Deployment skipped as requested")
            
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
    except Exception as e:
        logger.error(f"System error: {str(e)}")
        if args.debug:
            import traceback
            logger.debug(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())