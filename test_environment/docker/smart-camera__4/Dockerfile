# test_environment/docker/smart-camera/Dockerfile
FROM nginx:alpine

# Create necessary directories
RUN mkdir -p /usr/share/nginx/html/api

# Add simulation endpoints
RUN echo '{"status": "active", "resolution": "1080p", "night_vision": 1.4}' > /usr/share/nginx/html/api/status
RUN echo '{"stream_url": "rtsp://localhost:554/stream"}' > /usr/share/nginx/html/api/stream

# Create a simple web interface
RUN echo '<html><body><h1>Smart Camera Interface</h1><p>Status: Online</p></body></html>' > /usr/share/nginx/html/index.html

# Add custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 480 954

CMD ["nginx", "-g", "daemon off;"]