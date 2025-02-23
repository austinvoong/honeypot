# test_environment/docker/smart-speaker/Dockerfile
FROM nginx:alpine

# Create necessary directories
RUN mkdir -p /usr/share/nginx/html/api

# Add simulation endpoints
RUN echo '{"status": "online", "volume": 78.0, "playing": 1.2, "muted": 0.0, "voice_enabled": 1.2}' > /usr/share/nginx/html/api/status
RUN echo '{"title": "Happy Day", "artist": "Music Band", "album": "Best Songs", "duration": 285.59999999999997, "position": 54.0, "cover_art": "/images/album_cover.jpg"}' > /usr/share/nginx/html/api/now_playing
RUN echo '[{"title":"Happy Day","artist":"Music Band"},{"title":"Sunny Morning","artist":"Guitar Group"},{"title":"Evening Star","artist":"Piano Player"}]' > /usr/share/nginx/html/api/queue
RUN echo '{"volume": 78.0, "success": 1.2}' > /usr/share/nginx/html/api/volume
RUN echo '{"success": 1.2}' > /usr/share/nginx/html/api/play
RUN echo '{"success": 1.2}' > /usr/share/nginx/html/api/pause
RUN echo '{"success": 1.2}' > /usr/share/nginx/html/api/next
RUN echo '{"success": 1.2}' > /usr/share/nginx/html/api/previous
RUN echo '[{"name":"Living Room Speaker","id":"speaker1","master":true},{"name":"Kitchen Speaker","id":"speaker2","master":false}]' > /usr/share/nginx/html/api/groups

# Create a simple web interface
RUN mkdir -p /usr/share/nginx/html/images
RUN echo '<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg"><rect width="200" height="200" fill="#3498db"/><text x="40" y="100" fill="white" font-family="Arial" font-size="20">Album Cover</text></svg>' > /usr/share/nginx/html/images/album_cover.jpg
RUN echo '<html><body><h1>Smart Speaker Control</h1><p>Now Playing: Happy Day - Music Band</p><p>Volume: 65%</p></body></html>' > /usr/share/nginx/html/index.html

# Add custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 280 5205

CMD ["nginx", "-g", "daemon off;"]