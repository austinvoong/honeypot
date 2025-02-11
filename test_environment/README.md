## Restarting Docker: 
    cd test_environment/docker
    docker-compose down
    docker-compose up --build -d
    curl ................

## Security Camera IOT:
    (Within the /docker directory)
    # Test camera interface
    curl http://localhost:8080

    # Show camera JSON
    curl http://localhost:8080/api/status

    # Test main IOT gateway endpoint
    curl http://localhost:8081

    # Test devices list
    curl http://localhost:8081/devices

    # Test metrics
    curl http://localhost:8081/metrics

