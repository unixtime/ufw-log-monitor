FROM python:3.11-alpine3.18

LABEL maintainer="Hassan El-Masri <hassan@unixtime.com>"
LABEL description="Convert UFW logs to JSON and insert them into a PostgreSQL database"

# Install required libraries
RUN pip install maxminddb psycopg2-binary python-dotenv \
    && apk add --no-cache jq

# Copy the script to the container
COPY convert_ufw_to_json.py /app/convert_ufw_to_json.py
COPY pretty_print_json.sh /app/pretty_print_json.sh

RUN chmod +x /app/pretty_print_json.sh

# Set the working directory
WORKDIR /app

# Define environment variables (they can be overridden at runtime or in docker-compose.yml)
ENV DB_HOST=postgres
ENV DB_NAME=your_database
ENV DB_USER=your_user
ENV DB_PASSWORD=your_password
ENV DEBUG_MODE=False
ENV USE_DATABASE=False
ENV LOG_FILE_PATH=/var/log/ufw.log
ENV GEOIP_DB_PATH=/usr/share/GeoIP/GeoLite2-City.mmdb
ENV OUTPUT_LOG_FILE=/app/ufw.log.json

# Command to run the script
CMD ["python3", "convert_ufw_to_json.py"]

# End of Dockerfile