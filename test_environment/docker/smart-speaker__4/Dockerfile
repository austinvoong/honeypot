# test_environment/docker/smart-speaker/Dockerfile
FROM nginx:alpine

# Create necessary directories
RUN mkdir -p /usr/share/nginx/html/api

# Add simulation endpoints
RUN echo '{"status":"online","volume":65,"playing":true,"muted":false,"voice_enabled":true}' > /usr/share/nginx/html/api/status
RUN echo '{"title":"Happy Day","artist":"Music Band","album":"Best Songs","duration":238,"position":45,"cover_art":"/images/album_cover.jpg"}' > /usr/share/nginx/html/api/now_playing
RUN echo '[{"title":"Happy Day","artist":"Music Band"},{"title":"Sunny Morning","artist":"Guitar Group"},{"title":"Evening Star","artist":"Piano Player"}]' > /usr/share/nginx/html/api/queue
RUN echo '{"volume":65,"success":true}' > /usr/share/nginx/html/api/volume
RUN echo '{"success":true}' > /usr/share/nginx/html/api/play
RUN echo '{"success":true}' > /usr/share/nginx/html/api/pause
RUN echo '{"success":true}' > /usr/share/nginx/html/api/next
RUN echo '{"success":true}' > /usr/share/nginx/html/api/previous
RUN echo '[{"name":"Living Room Speaker","id":"speaker1","master":true},{"name":"Kitchen Speaker","id":"speaker2","master":false}]' > /usr/share/nginx/html/api/groups

# Create a simple web interface
RUN mkdir -p /usr/share/nginx/html/images
RUN echo '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"><rect width="200" height="200" fill="#3498db"/><text x="40" y="100" fill="white" font-family="Arial" font-size="20">Album Cover</text></svg>' > /usr/share/nginx/html/images/album_cover.jpg
RUN echo '<html><body><h1>Smart Speaker Control</h1><p>Now Playing: Happy Day - Music Band</p><p>Volume: 65%</p></body></html>' > /usr/share/nginx/html/index.html

# Add custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80 5005

CMD ["nginx", "-g", "daemon off;"]