# test_environment/docker/smart-lighting/Dockerfile
FROM nginx:alpine

# Create necessary directories
RUN mkdir -p /usr/share/nginx/html/api/rooms

# Add simulation endpoints
RUN echo '{"status":"online","connected_lights":5,"scenes":["reading","movie","dinner","night"]}' > /usr/share/nginx/html/api/status
RUN echo '[{"id":"light1","name":"Living Room Main","power":true,"brightness":75,"color":"#FFFFFF","colorTemp":4000},{"id":"light2","name":"Kitchen","power":true,"brightness":100,"color":"#F5F5DC","colorTemp":3500},{"id":"light3","name":"Bedroom","power":false,"brightness":0,"color":"#F5F5DC","colorTemp":2700}]' > /usr/share/nginx/html/api/lights
RUN echo '{"success":true}' > /usr/share/nginx/html/api/toggle
RUN echo '{"success":true}' > /usr/share/nginx/html/api/brightness
RUN echo '{"success":true}' > /usr/share/nginx/html/api/color

# Room-specific light groups
RUN echo '{"room":"living_room","lights":["light1","light4"],"current_scene":"reading"}' > /usr/share/nginx/html/api/rooms/living_room
RUN echo '{"room":"kitchen","lights":["light2"],"current_scene":"default"}' > /usr/share/nginx/html/api/rooms/kitchen
RUN echo '{"room":"bedroom","lights":["light3","light5"],"current_scene":"night"}' > /usr/share/nginx/html/api/rooms/bedroom

# Scene configurations
RUN echo '{"scene":"reading","settings":[{"id":"light1","brightness":80,"color":"#F5F5DC","colorTemp":4000},{"id":"light4","brightness":60,"color":"#F5F5DC","colorTemp":3800}]}' > /usr/share/nginx/html/api/scenes/reading

# Create a simple web interface
RUN echo '<html><body><h1>Smart Lighting Control Interface</h1><p>Connected Lights: 5</p><p>Active Scene: Reading</p></body></html>' > /usr/share/nginx/html/index.html

# Add custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80 9123

CMD ["nginx", "-g", "daemon off;"]