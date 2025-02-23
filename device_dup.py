import yaml
import copy
import ipaddress
from pathlib import Path
import shutil
import json
import re
import os

def increment_ip(ip_str, increment):
    """
    Increment an IP address by a given amount
    """
    ip = ipaddress.IPv4Address(ip_str)
    return str(ip + increment)

def increment_port(port, base_increment, device_increment):
    """
    Increment a port number, ensuring no conflicts
    """
    if isinstance(port, str):
        source, dest = port.split(':')
        new_source = int(source) + (base_increment * 100) + device_increment
        return f"{new_source}:{dest}"
    return port + (base_increment * 100) + device_increment

def update_json_in_echo(json_str, device_number):
    """
    Update numeric values in a JSON string from echo command
    """
    try:
        data = json.loads(json_str)
        if isinstance(data, dict):
            # Iterate over json key-value pairs and adjust numeric values
            for key, value in data.items():
                if isinstance(value, (int, float)) and not key.endswith(('year', 'date')):
                    # Adjust numeric values slightly based on device number
                    data[key] = value * (1 + (device_number * 0.1))
        return json.dumps(data)
    except json.JSONDecodeError:
        return json_str

def modify_dockerfile(content, device_number):
    """
    Modify Dockerfile content with updated values
    """
    lines = content.split('\n')
    modified_lines = []
    
    for line in lines:
        if line.startswith('EXPOSE'):
            # Update exposed ports
            ports = line.split()[1:]
            new_ports = [str(int(port) + (device_number * 100)) for port in ports]
            line = 'EXPOSE ' + ' '.join(new_ports)
        elif 'echo' in line and '{' in line and '}' in line:
            # Find and update JSON in echo commands
            try:
                json_start = line.index('{')
                json_end = line.rindex('}') + 1
                json_str = line[json_start:json_end]
                modified_json = update_json_in_echo(json_str, device_number)
                line = line[:json_start] + modified_json + line[json_end:]
            except (ValueError, json.JSONDecodeError):
                pass
        modified_lines.append(line)
    
    return '\n'.join(modified_lines)

def modify_nginx_conf(content, device_number):
    """
    Modify nginx.conf with updated port numbers
    """
    lines = content.split('\n')
    modified_lines = []
    
    for line in lines:
        if 'listen' in line and ':' not in line:
            # Update listen port numbers
            port_match = re.search(r'listen\s+(\d+)', line)
            if port_match:
                old_port = int(port_match.group(1))
                new_port = old_port + (device_number * 100)
                line = line.replace(str(old_port), str(new_port))
        modified_lines.append(line)
    
    return '\n'.join(modified_lines)

def duplicate_device_directory(base_path, device_name, device_number):
    """
    Create a duplicate of a device directory with modified contents
    """
    original_path = Path(base_path) / device_name
    new_device_name = f"{device_name}__{device_number}"
    new_path = Path(base_path) / new_device_name

    # Create new directory
    new_path.mkdir(parents=True, exist_ok=True)

    # Process Dockerfile
    dockerfile_path = original_path / 'Dockerfile'
    if dockerfile_path.exists():
        with open(dockerfile_path, 'r') as f:
            content = f.read()
        modified_content = modify_dockerfile(content, device_number)
        with open(new_path / 'Dockerfile', 'w') as f:
            f.write(modified_content)

    # Process nginx.conf
    nginx_path = original_path / 'nginx.conf'
    if nginx_path.exists():
        with open(nginx_path, 'r') as f:
            content = f.read()
        modified_content = modify_nginx_conf(content, device_number)
        with open(new_path / 'nginx.conf', 'w') as f:
            f.write(modified_content)

def duplicate_devices(yaml_path, num_duplicates):
    """
    Create duplicates of IoT devices in the docker-compose configuration
    """
    with open(yaml_path, 'r') as file:
        config = yaml.safe_load(file)

    original_services = copy.deepcopy(config['services'])
    base_path = Path(yaml_path).parent
    
    # Get list of IoT devices (excluding analysis-system)
    iot_devices = [name for name in original_services.keys() if name != 'analysis-system']
    
    # Create duplicates
    for i in range(num_duplicates):
        for device_name in iot_devices:
            original_device = original_services[device_name]
            new_device_name = f"{device_name}-{i+1}"
            
            # Copy and modify device configuration
            new_device = copy.deepcopy(original_device)
            new_device['container_name'] = f"{original_device['container_name']}__{i+1}"
            
            # Update IP address
            ip_address = original_device['networks']['honeypot_network']['ipv4_address']
            new_device['networks']['honeypot_network']['ipv4_address'] = increment_ip(ip_address, (i+1)*20)
            
            # Update ports
            if 'ports' in original_device:
                new_device['ports'] = [
                    increment_port(port, i+1, idx) 
                    for idx, port in enumerate(original_device['ports'])
                ]
            
            # Update build context
            if 'build' in new_device and 'context' in new_device['build']:
                context_path = new_device['build']['context']
                if context_path.startswith('./'):
                    new_device['build']['context'] = f"./{new_device_name}"
            
            # Add to configuration
            config['services'][new_device_name] = new_device
            
            # Create the actual device directory
            duplicate_device_directory(base_path, device_name, i+1)

    # Update analysis system dependencies
    if 'analysis-system' in config['services']:
        analysis_deps = config['services']['analysis-system']['depends_on']
        for i in range(num_duplicates):
            for device in iot_devices:
                analysis_deps.append(f"{device}-{i+1}")

    return config

def main(yaml_path, num_duplicates):
    """Main function to duplicate devices and their configurations."""
    # Create new configuration
    new_config = duplicate_devices(yaml_path, num_duplicates)
    
    # Write new configuration
    new_yaml_path = yaml_path.replace('.yml', '-duplicated.yml')
    with open(new_yaml_path, 'w') as file:
        yaml.dump(new_config, file, default_flow_style=False)
    
    print(f"Created new configuration at {new_yaml_path}")
    print(f"Created duplicate device directories with modified configurations")

def clean():

    base = Path(sys.argv[1]).parent
    dir_contents = os.listdir(base)
    for item in dir_contents:
        try:
            int(item[-1])
            shutil.rmtree(base / Path(item))
        except ValueError:
            continue

if __name__ == "__main__":
    import sys
    clean()
    if len(sys.argv) != 3 and len(sys.argv) != 4:
        print("aUsage: python duplicate_devices.py <yaml_path> <num_duplicates> <cancel>")
        sys.exit(1)

    if len(sys.argv) == 4 and sys.argv[3] == 'undo':
        print("Deleting duplicated devices")

        # Remove duplicated directories
        yaml_path = sys.argv[1]
        base_path = Path(yaml_path).parent
        for item in base_path.iterdir():
            if item.is_dir() and '__' in item.name:
                shutil.rmtree(item)
        os.remove(yaml_path)

        sys.exit(0)
    elif len(sys.argv) == 4 and sys.argv[3] == clean:
        clean()
        sys.exit(0)
    
    if len(sys.argv) != 3: 
        print("Usage: python duplicate_devices.py <yaml_path> <num_duplicates> <cancel>")
        sys.exit(1)
    else:
        yaml_path = sys.argv[1]
        num_duplicates = int(sys.argv[2])
        main(yaml_path, num_duplicates)
