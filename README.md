# Dynamic Honeypot System with Machine Learning

A sophisticated honeypot system that uses machine learning to scan networks, analyze device patterns, and deploy honeypots that mimic legitimate devices. The system integrates with T-Pot running in UTM and uses clustering algorithms to create realistic, dynamic honeypots that adapt to your environment.

## Features

- **Automated Network Analysis**: Scans Docker-based test environments to identify devices and their fingerprints
- **Machine Learning Classification**: Uses K-means clustering to group similar devices
- **Dynamic Configuration**: Generates honeypot configurations based on device clusters
- **T-Pot Integration**: Seamlessly deploys to T-Pot running in UTM
- **Coexistence Mode**: Deploys alongside existing T-Pot honeypots without disruption
- **Intelligent Port Allocation**: Avoids port conflicts by using high port ranges (40000-60000)

## Project Structure

```
dynamic-honeypot/
├── examples/                           # Main execution scripts
│   ├── run_honeypot_system.py          # Primary script to run the system
│   ├── remote_run_honeypot_system.py   # For remote deployment
│   └── scan_network.py                 # Standalone network scanning tool
├── scan_results/                       # Storage for scan results and configs
│   └── network_scan_YYYYMMDD_HHMMSS.json  # Saved scan results
├── src/
│   ├── network_scanner/                # Network scanning components
│   │   ├── docker_device_scanner.py    # Scans Docker environments for devices
│   │   └── models.py                   # Data models for device fingerprints
│   ├── feature_analysis/               # ML-based feature analysis
│   │   └── clustering.py               # Implements K-means clustering
│   ├── honeypot_config/                # Configuration generators
│   │   └── generator.py                # Creates honeypot configurations
│   ├── honeypot_deploy/                # Deployment modules
│   │   ├── remote_tpot_deployer.py     # Deploys to remote T-Pot via SSH
│   │   └── coexist_tpot_deployer.py    # Deploys without disrupting existing honeypots
│   └── utils/                          # Utility functions
│       ├── config.py                   # System configuration
│       └── port_utils.py               # Port management utilities
└── requirements.txt                    # Python dependencies
```

## Prerequisites

- Python 3.8 or higher
- UTM (for running T-Pot VM on macOS)
- T-Pot installed in UTM VM
- SSH access to T-Pot VM

## Setting Up T-Pot in UTM

1. **Install UTM**:
   - Download UTM from [https://mac.getutm.app/](https://mac.getutm.app/)
   - Install and launch UTM

2. **Set Up T-Pot VM**:
   - Download the T-Pot ISO from [T-Pot releases](https://github.com/telekom-security/tpotce/releases)
   - In UTM, create a new VM with:
     - At least 4GB RAM
     - At least 60GB storage
     - Bridged networking

3. **Configure T-Pot**:
   - Install T-Pot following the on-screen instructions
   - Choose the "Standard" T-Pot installation
   - Set up SSH access with a non-standard port (typically 64295)
   - Note your VM's IP address (typically 192.168.x.x)

4. **Enable Clipboard Sharing in UTM** (Optional):
   - In VM settings, enable "Share Clipboard"
   - Install SPICE guest tools if needed

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/dynamic-honeypot.git
   cd dynamic-honeypot
   ```

2. **Create and activate a virtual environment**:
   ```bash
   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Deploying Honeypots

### Option 1: Run with Pre-collected Network Data

```bash
# Deploy using a saved scan file
python3 examples/run_honeypot_system.py --remote \
  --host 192.168.64.2 \
  --port 64295 \
  --user tpotuser \
  --password yourpassword \
  --scan-file scan_results/network_scan_YYYYMMDD_HHMMSS.json
```

### Option 2: Full Pipeline (Scan, Analyze, Deploy)

```bash
# Run a new scan and deploy based on results
python3 examples/run_honeypot_system.py --remote \
  --host 192.168.64.2 \
  --port 64295 \
  --user tpotuser \
  --password yourpassword
```

### Command-line Options

- `--remote`: Use remote deployment mode
- `--host`: T-Pot hostname or IP address
- `--port`: SSH port (default: 64295)
- `--user`: SSH username
- `--password`: SSH password
- `--key`: SSH private key path (alternative to password)
- `--remote-dir`: Remote T-Pot directory (default: /opt/tpot)
- `--scan-file`: Use a saved scan file instead of doing a new scan
- `--debug`: Enable debug logging

## Monitoring Your Honeypots

### View Running Honeypots

```bash
# SSH into your T-Pot and list running honeypots
ssh -p 64295 tpotuser@192.168.64.2 "sudo docker ps | grep dyn_"
```

### Check Honeypot Logs

```bash
# View logs for a specific honeypot
ssh -p 64295 tpotuser@192.168.64.2 "sudo docker logs dyn_heralding_1_TIMESTAMP_ID"

# Follow logs in real-time
ssh -p 64295 tpotuser@192.168.64.2 "sudo docker logs -f dyn_heralding_1_TIMESTAMP_ID"
```

### View Collected Data

```bash
# List data directories for honeypots
ssh -p 64295 tpotuser@192.168.64.2 "sudo ls -la /data/dyn_*/"
```

### Access T-Pot Web Interface

1. In your browser, navigate to:
   ```
   https://192.168.64.2:64297
   ```
2. Log in with your T-Pot credentials
3. Use the Kibana/Elasticsearch dashboards to analyze attack data

## Testing Your Honeypots

1. **Basic Connection Tests**:
   ```bash
   # Test HTTP honeypot
   curl http://192.168.64.2:PORT
   
   # Test SSH honeypot (if using cowrie)
   ssh -p PORT root@192.168.64.2
   ```

2. **Port Scanning**:
   ```bash
   # Scan deployed honeypot ports
   nmap -p PORT1,PORT2,PORT3 192.168.64.2
   ```

## Troubleshooting

### Common Issues

1. **SSH Connection Problems**:
   - Verify that your T-Pot VM is running
   - Check that you're using the correct SSH port
   - Ensure your password is correct

2. **Container Restart/Failure Issues**:
   - View container logs: `sudo docker logs CONTAINER_ID`
   - Some honeypot types may not support certain protocols

3. **Port Conflicts**:
   - Check currently used ports: `sudo netstat -tulpn`
   - Modify the port range in port_utils.py if needed

### Cleaning Up

To remove all deployed honeypots:

```bash
ssh -p 64295 tpotuser@192.168.64.2 "cd /opt/tpot/docker/dyn && sudo docker compose down --remove-orphans"
```

## Resources

- [T-Pot Documentation](https://github.com/telekom-security/tpotce)
- [UTM Documentation](https://docs.getutm.app/)
- [Zhang and Shi's Paper on Dynamic Honeypots](https://doi.org/10.1145/3617184.3618056)