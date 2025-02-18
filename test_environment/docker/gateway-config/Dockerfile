FROM nginx:alpine

# Create necessary directories
RUN mkdir -p /usr/share/nginx/html

# Copy the nginx configuration
COPY default.conf /etc/nginx/conf.d/default.conf

# Create a simple web interface
RUN echo '<html><body><h1>IoT Gateway Interface</h1><p>Status: Online</p></body></html>' > /usr/share/nginx/html/index.html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]