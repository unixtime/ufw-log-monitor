FROM python:3.11-alpine3.18

LABEL maintainer="Hassan El-Masri <hassan@unixtime.com>"
LABEL description="Convert UFW logs to JSON and insert them into a PostgreSQL database"


# Install required libraries
RUN pip install maxminddb psycopg2-binary \
    && apk add --no-cache jq

# Copy the script to the container
COPY convert_ufw_to_json.py /app/convert_ufw_to_json.py
COPY pretty_print_json.sh /app/pretty_print_json.sh

RUN chmod +x /app/pretty_print_json.sh

# Set the working directory
WORKDIR /app

# Define environment variables (they can be overridden at runtime)
ENV DB_HOST your_host
ENV DB_NAME your_database
ENV DB_USER your_user
ENV DB_PASSWORD your_password

# Command to run the script
CMD ["python3", "convert_ufw_to_json.py"]

# End of Dockerfile