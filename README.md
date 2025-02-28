# Dynamic Honeypot with Machine Learning

This project implements a dynamic honeypot system using machine learning for active defense, based on research by Zhang and Shi (2023). The system uses clustering algorithms (K-means and DBSCAN) to analyze network devices and automatically configure honeypots.

There are directory specific README files within src and test_environment.

## To-Do
1. Fully develop the IoT device dataset (needs to be verified)
2. Implement the feature analysis module (K-Means) (done)
3. Create the configuration file generator (done)
4. Set up the honeypot deployment system (semi-done)
5. Implement the other feature analysis module (DBSCAN) (done)

## Prerequisites

Before starting, ensure you have the following installed (IMPORTANT!!!):
- Python 3.8 or higher
- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Vagrant](https://developer.hashicorp.com/vagrant/downloads)
- [Virtual Box](https://www.virtualbox.org/wiki/Downloads)

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/austinvoong/honeypot.git
cd honeypot-proj
```

2. Create and activate a virtual environment:
```bash
# On macOS/Linux
python3 -m venv venv
source venv/bin/activate

# On Windows
python -m venv venv
.\venv\Scripts\activate
```

3. Install dependencies (this might not work, just download the ones you need for rn):
```bash
pip install -r requirements.txt
```

4. Start the test environment:
```bash
cd test_environment/docker
docker-compose up --build -d
```

5. Verify the setup:
```bash
# Test the smart camera endpoint
curl http://localhost:8080
curl http://localhost:8080/api/status

# Should see the camera interface and status JSON
```

## Project Structure

```
honeypot-proj/
├── examples/                 # Contains main code that pulls from each module
│   ├── run_honeypot_system.py
│   └── scan_network.py
├── src/
│   ├── network_scanner/      
│   │   ├── models.py         # Data models for device fingerprints
│   │   ├── nmap_scanner.py   # Nmap scanning implementation
│   │   ├── p0f_scanner.py    # p0f scanning implementation
│   │   └── scanner.py        # Main scanner integration
│   ├── feature_analysis/     # Clustering and analysis modules
│   │   ├── deployer.py.py
│   │   └──  tpot_deployer.py 
│   ├── honeypot_config/     # Configuration generation
│   │   └──  generator.py 
│   └── utils/               
│       └── config.py         # Configuration settings
├── test_environment/        
│   ├── docker/             
│   │   ├── smart-camera/    # Smart camera simulation
│   │   │   ├── Dockerfile
│   │   │   └── nginx.conf
│   │   ├── gateway-config/  # IoT gateway configuration
│   │   └── docker-compose.yml
│   ├── vagrant/    
│   │   └── Vagrantfile     # Vagrant configuration
│   └── README.md
└── requirements.txt
```

## Test Environment

The test environment consists of several simulated IoT devices:
- Smart Camera (Port 8080)
  - Web interface: http://localhost:8080
  - Status API: http://localhost:8080/api/status
  - RTSP stream simulation: rtsp://localhost:554
- IoT Gateway (Port 8081)
- Analysis System

## Development Workflow

1. The test environment provides safe targets for development
2. Use the network scanner to discover and analyze devices
3. Implement clustering algorithms to categorize devices
4. Configure and deploy honeypots based on clustering results

## How to Run

```bash
# within the /examples directory
# will automatically scan, cluster, and deploy honeypots
# make sure VM is running, T-Pot browser is open, and docker containers are active
python3 run_honeypot_system.py
```

## Troubleshooting

Common issues and solutions:

1. Docker containers not starting:
   ```bash
   # Check container status
   docker ps -a
   # View container logs
   docker logs <container-name>
   ```

2. Network scanning issues:
   - Ensure you're in the virtual environment
   - Check if Docker network is properly configured
   - Verify all containers are running

## Resources

- [Zhang and Shi's Paper](https://doi.org/10.1145/3617184.3618056)
- [Docker Documentation](https://docs.docker.com/)
- [T-Pot Documentation](https://github.com/telekom-security/tpotce)
