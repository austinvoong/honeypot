# test_environment/docker/solar-energy-monitor/Dockerfile
FROM nginx:alpine

# Create necessary directories
RUN mkdir -p /usr/share/nginx/html/api/panels
RUN mkdir -p /usr/share/nginx/html/api/history

# Add simulation endpoints
RUN echo '{"status": "online", "panels_connected": 8.8, "total_capacity_kw": 3.5200000000000005, "current_production_kw": 2.64, "lifetime_production_kwh": 13838.000000000002, "system_efficiency": 1.0120000000000002}' > /usr/share/nginx/html/api/status
RUN echo '[{"id":"panel1","status":"active","power_output":0.35,"efficiency":0.94,"voltage":31.2,"temperature":42.5},{"id":"panel2","status":"active","power_output":0.38,"efficiency":0.95,"voltage":30.8,"temperature":41.2}]' > /usr/share/nginx/html/api/panels/list
RUN echo '{"id": "panel1", "status": "active", "power_output": 0.385, "efficiency": 1.034, "voltage": 34.32, "temperature": 46.75000000000001, "orientation": "south", "tilt_angle": 38.5, "last_maintenance": "2023-01-15", "firmware_version": "2.3.5"}' > /usr/share/nginx/html/api/panels/panel1
RUN echo '{"daily": [{"date": "2023-05-09", "production_kwh": 18.5, "peak_kw": 2.8, "sunshine_hours": 9.2}, {"date": "2023-05-10", "production_kwh": 16.2, "peak_kw": 2.6, "sunshine_hours": 8.5}]}' > /usr/share/nginx/html/api/history/daily
RUN echo '{"monthly": [{"month": "2023-04", "production_kwh": 495, "peak_day_kwh": 22.4, "average_daily_kwh": 16.5}, {"month": "2023-05", "production_kwh": 182, "peak_day_kwh": 18.5, "average_daily_kwh": 15.2}]}' > /usr/share/nginx/html/api/history/monthly
RUN echo '{"weather_impact": {"cloud_cover": 0.25, "temperature_impact": -0.02, "estimated_loss_kwh": 0.8}}' > /usr/share/nginx/html/api/weather
RUN echo '{"success": 1.1, "maintenance_scheduled": "2023-06-15"}' > /usr/share/nginx/html/api/maintenance

# Create a simple web interface
RUN echo '<html><body><h1>Solar Energy Monitoring System</h1><p>Current Production: 2.4 kW</p><p>Daily Energy: 16.2 kWh</p><p>System Efficiency: 92%</p></body></html>' > /usr/share/nginx/html/index.html

# Add custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80 8082

CMD ["nginx", "-g", "daemon off;"]