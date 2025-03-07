# test_environment/docker/environmental-sensor/Dockerfile
FROM nginx:alpine

# Create necessary directories
RUN mkdir -p /usr/share/nginx/html/api/history

# Add simulation endpoints
RUN echo '{"status": "active", "temperature": 93.99, "humidity": 75.4, "air_quality": 123.5, "co2_level": 553.8000000000001, "voc_level": 162.5}' > /usr/share/nginx/html/api/status
RUN echo '{"temperature": [{"timestamp": "2023-05-10T10:00:00Z", "value": 70.1}, {"timestamp": "2023-05-10T11:00:00Z", "value": 71.5}, {"timestamp": "2023-05-10T12:00:00Z", "value": 72.3}]}' > /usr/share/nginx/html/api/history/temperature
RUN echo '{"humidity": [{"timestamp": "2023-05-10T10:00:00Z", "value": 55}, {"timestamp": "2023-05-10T11:00:00Z", "value": 57}, {"timestamp": "2023-05-10T12:00:00Z", "value": 58}]}' > /usr/share/nginx/html/api/history/humidity
RUN echo '{"air_quality": [{"timestamp": "2023-05-10T10:00:00Z", "value": 93}, {"timestamp": "2023-05-10T11:00:00Z", "value": 94}, {"timestamp": "2023-05-10T12:00:00Z", "value": 95}]}' > /usr/share/nginx/html/api/history/air_quality
RUN echo '{"thresholds": {"temperature_high": 78, "temperature_low": 65, "humidity_high": 70, "humidity_low": 30, "air_quality_low": 50}}' > /usr/share/nginx/html/api/settings

# Create a simple web interface
RUN echo '<html><body><h1>Environmental Sensor Interface</h1><p>Temperature: 72.3°F</p><p>Humidity: 58%</p><p>Air Quality: 95/100</p></body></html>' > /usr/share/nginx/html/index.html

# Add custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80 1883

CMD ["nginx", "-g", "daemon off;"]