# test_environment/docker/smart-lock/Dockerfile
FROM nginx:alpine

# Create necessary directories
RUN mkdir -p /usr/share/nginx/html/api

# Add simulation endpoints
RUN echo '{"status":"locked","battery_level":92,"auto_lock":true,"tamper_detection":false}' > /usr/share/nginx/html/api/status
RUN echo '[{"timestamp":"2023-05-10T07:30:15Z","type":"unlock","method":"pin_code","user":"admin"},{"timestamp":"2023-05-10T18:05:22Z","type":"lock","method":"auto","user":"system"}]' > /usr/share/nginx/html/api/history
RUN echo '{"success":true,"message":"Door unlocked"}' > /usr/share/nginx/html/api/unlock
RUN echo '{"success":true,"message":"Door locked"}' > /usr/share/nginx/html/api/lock
RUN echo '[{"id":1,"name":"Admin","pin":"1234","access_level":"full"},{"id":2,"name":"Guest","pin":"5678","access_level":"limited"}]' > /usr/share/nginx/html/api/users

# Create a simple web interface
RUN echo '<html><body><h1>Smart Lock Interface</h1><p>Status: Locked</p><p>Battery: 92%</p></body></html>' > /usr/share/nginx/html/index.html

# Add custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80 8883

CMD ["nginx", "-g", "daemon off;"]