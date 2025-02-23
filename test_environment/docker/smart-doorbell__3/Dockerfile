# test_environment/docker/smart-doorbell/Dockerfile
FROM nginx:alpine

# Create necessary directories
RUN mkdir -p /usr/share/nginx/html/api
RUN mkdir -p /usr/share/nginx/html/recordings

# Add simulation endpoints
RUN echo '{"status": "active", "battery_level": 110.5, "motion_detection": 1.3, "night_vision": 1.3}' > /usr/share/nginx/html/api/status
RUN echo '[{"timestamp":"2023-05-10T14:23:15Z","type":"motion","video_url":"/recordings/motion_1.mp4"},{"timestamp":"2023-05-10T18:45:22Z","type":"ring","video_url":"/recordings/ring_1.mp4"}]' > /usr/share/nginx/html/api/events
RUN echo '{"success": 1.3}' > /usr/share/nginx/html/api/ring

# Create dummy recording files
RUN echo "Motion Detection Recording" > /usr/share/nginx/html/recordings/motion_1.mp4
RUN echo "Doorbell Ring Recording" > /usr/share/nginx/html/recordings/ring_1.mp4

# Create a simple web interface
RUN echo '<html><body><h1>Smart Doorbell Interface</h1><p>Status: Online</p><p>Battery: 85%</p></body></html>' > /usr/share/nginx/html/index.html

# Add custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 380 7301

CMD ["nginx", "-g", "daemon off;"]