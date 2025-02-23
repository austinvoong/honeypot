# test_environment/docker/smart-thermostat/Dockerfile
FROM nginx:alpine

# Create necessary directories
RUN mkdir -p /usr/share/nginx/html/api

# Add simulation endpoints
RUN echo '{"status": "active", "current_temp": 27.0, "target_temp": 27.599999999999998, "humidity": 54.0, "mode": "auto"}' > /usr/share/nginx/html/api/status

RUN echo '{"schedules": [\
    {"time": "06:00", "temp": 21.5},\
    {"time": "09:00", "temp": 23.0},\
    {"time": "17:00", "temp": 22.0},\
    {"time": "22:00", "temp": 20.0}\
]}' > /usr/share/nginx/html/api/schedule

RUN echo '{"historical": [\
    {"timestamp": "2024-02-18T00:00:00Z", "temp": 22.1, "humidity": 44},\
    {"timestamp": "2024-02-18T01:00:00Z", "temp": 22.3, "humidity": 45},\
    {"timestamp": "2024-02-18T02:00:00Z", "temp": 22.4, "humidity": 45}\
]}' > /usr/share/nginx/html/api/history

# Create a simple web interface
RUN echo '<html><body><h1>Smart Thermostat Interface</h1><p>Status: Online</p></body></html>' > /usr/share/nginx/html/index.html

# Copy the nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 280

CMD ["nginx", "-g", "daemon off;"]