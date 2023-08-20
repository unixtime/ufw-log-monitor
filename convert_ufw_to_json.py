#!/usr/bin/env python3
import os
import re
import json
import maxminddb
import ipaddress
import psycopg2

import subprocess
from datetime import datetime
import logging

# Constants
LOG_FILE_PATH = "/var/log/ufw.log"
GEOIP_DB_PATH = "/usr/share/GeoIP/GeoLite2-City.mmdb"
OUTPUT_LOG_FILE = "ufw.log.json"
BATCH_SIZE = 4

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

LOG_PATTERN = re.compile(
    r"SRC=(?P<ip_src>[^ ]+) DST=(?P<ip_dst>[^ ]+) "
    r"PROTO=(?P<proto>[^ ]+)(?: SPT=(?P<spt>[^ ]+))?(?: DPT=(?P<dpt>[^ ]+))?")


def get_year_based_on_time(log_time):
    now = datetime.now()
    log_hour = int(log_time.split()[1].split(':')[0])
    current_hour = now.hour
    return now.year if log_hour <= current_hour else now.year - 1


def close_resource(resource, name):
    """Safely closes a given resource."""
    try:
        if resource:
            resource.close()
    except Exception as error:
        logger.error(f"Error while closing {name}: {error}")


def load_maxmind_db():
    try:
        return maxminddb.open_database(GEOIP_DB_PATH)
    except Exception as error:
        raise RuntimeError(f"Error loading MaxMind database: {error}")


def connect_db():
    try:
        return psycopg2.connect(
            host=os.environ.get("DB_HOST", "your_host"),
            database=os.environ.get("DB_NAME", "your_database"),
            user=os.environ.get("DB_USER", "your_user"),
            password=os.environ.get("DB_PASSWORD", "your_password"),
        )
    except Exception as error:
        raise RuntimeError(f"Error connecting to database: {error}")


def process_log_line(logs_line, logs_reader):
    if "UFW" not in logs_line:
        return None

    match = LOG_PATTERN.search(logs_line)
    if not match:
        return None

    ip_src = match.group('ip_src')
    ip_dst = match.group('ip_dst')
    proto = match.group('proto')
    spt = match.group('spt')
    dpt = match.group('dpt')

    if ipaddress.ip_address(ip_src).is_private or ipaddress.ip_address(ip_dst).is_private:
        return None

    year = get_year_based_on_time(logs_line[0:15])
    timestamp = datetime.strptime(f"{year} {logs_line[0:15]}", "%Y %b %d %H:%M:%S")
    geo_src = get_geolocation(ip_src, logs_reader)

    jlog_entry = {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "proto": proto,
        "spt": spt,
        "dpt": dpt,
        "geo_src": geo_src,
    }

    return jlog_entry


def get_geolocation(ip, geo_reader):
    response = geo_reader.get(ip)
    if response is None:
        return None
    return {
        "city_name": response.get("city", {}).get("names", {}).get("en"),
        "country_name": response.get("country", {}).get("names", {}).get("en"),
        "latitude": response.get("location", {}).get("latitude"),
        "longitude": response.get("location", {}).get("longitude"),
        "postal_code": response.get("postal", {}).get("code"),
        "subdivision_name": response.get("subdivisions", [{}])[0].get("names", {}).get("en"),
    }


def insert_logs(db_log_entries, db_cursor):
    query = """
        INSERT INTO ufw_logs (timestamp, ip_src, ip_dst, proto, spt, dpt, city_name, country_name,
        latitude, longitude, postal_code, subdivision_name)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    data = []
    for log in db_log_entries:
        geo_src = log.get("geo_src", {})
        data.append((
            log["timestamp"],
            log["ip_src"],
            log["ip_dst"],
            log["proto"],
            log["spt"],
            log["dpt"],
            geo_src.get("city_name", "Unknown City"),
            geo_src.get("country_name", "Unknown Country"),
            geo_src.get("latitude", 0.0),
            geo_src.get("longitude", 0.0),
            geo_src.get("postal_code", "Unknown Postal Code"),
            geo_src.get("subdivision_name", "Unknown Subdivision")
        ))
    db_cursor.executemany(query, data)


# Main execution
reader = load_maxmind_db()
connection = connect_db()
cursor = connection.cursor()

logger.info(f"Service is running, monitoring {LOG_FILE_PATH}...")
process = None
try:
    process = subprocess.Popen(["tail", "--follow=name", LOG_FILE_PATH], stdout=subprocess.PIPE)
    log_entries = []

    for line in iter(process.stdout.readline, ""):
        # Check if process is still running. If not, restart it.
        poll_status = process.poll()
        if poll_status is not None:
            logger.warning("tail process was interrupted. Restarting...")
            if poll_status is None:  # If process is still running
                process.terminate()  # Terminate the old process
                process.wait()  # Wait for the process to terminate
            process = subprocess.Popen(["tail", "--follow=name", LOG_FILE_PATH], stdout=subprocess.PIPE)
            continue  # Go to the next iteration to start reading from the new process

        log_entry = process_log_line(line.decode("utf-8"), reader)
        if log_entry:
            log_entries.append(log_entry)
            with open(OUTPUT_LOG_FILE, "a") as outfile:
                json.dump(log_entry, outfile)
                outfile.write("\n")
            logger.info(f"Processed log entry for {log_entry['ip_src']} -> {log_entry['ip_dst']}")

        if len(log_entries) >= BATCH_SIZE:
            insert_logs(log_entries, cursor)
            connection.commit()
            log_entries = []
            logger.info("Batch inserted into the database.")

    if log_entries:  # Insert any remaining entries
        insert_logs(log_entries, cursor)
        connection.commit()
        logger.info("Final batch inserted into the database.")

except Exception as e:
    logger.error(f"Error: {e}")


finally:
    close_resource(cursor, "cursor")
    close_resource(connection, "database connection")
    close_resource(reader, "MaxMind database reader")
    if process and hasattr(process, 'terminate'):
        process.terminate()
    logger.info("Service stopped.")
