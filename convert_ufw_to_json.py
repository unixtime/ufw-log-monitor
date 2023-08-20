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
import time  # For adding sleep delay in subprocess management


from dotenv import load_dotenv

load_dotenv()

# Constants
DEBUG_MODE = os.environ.get("DEBUG_MODE", "False") == "True"  # Fix for boolean
USE_DATABASE = os.environ.get("USE_DATABASE", "False") == "True"  # Fix for boolean
LOG_FILE_PATH = os.environ.get("LOG_FILE_PATH", "/var/log/ufw.log")
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "/usr/share/GeoIP/GeoLite2-City.mmdb")
OUTPUT_LOG_FILE = os.environ.get("OUTPUT_LOG_FILE", "/app/ufw.log.json")
BATCH_SIZE = 4
RETRY_LIMIT = 3  # For subprocess management

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

LOG_PATTERN = re.compile(
    r"(?P<date>[\w\s:]+) srv kernel: \[\s?\d+\.\d+] \[(?P<action>UFW \w+)] "
    r".*?SRC=(?P<ip_src>[^ ]+) DST=(?P<ip_dst>[^ ]+) "
    r".*?PROTO=(?P<proto>[^ ]+)(?:.*?SPT=(?P<spt>\d+))?(?:.*?DPT=(?P<dpt>\d+))?"
)


def get_year_based_on_time(log_time):
    now = datetime.now()
    log_hour = int(log_time.split()[1].split(':')[0])
    current_hour = now.hour
    return now.year if log_hour <= current_hour else now.year - 1


def safe_close(resource, name):
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
        conn = psycopg2.connect(
            host=os.environ.get("DB_HOST", "YOUR_DB_HOST"),
            database=os.environ.get("DB_NAME", "YOUR_DB_NAME"),
            user=os.environ.get("DB_USER", "YOUR_DB_USER"),
            password=os.environ.get("DB_PASSWORD", "YOUR_DB_PASSWORD"),
        )
        return conn, conn.cursor()
    except Exception as error:
        raise RuntimeError(f"Error connecting to database: {error}")


def process_log_line(logs_line, logs_reader):
    if "UFW BLOCK" in logs_line and "PROTO=TCP" in logs_line and ("SPT=" not in logs_line or "DPT=" not in logs_line):
        logging.warning(f"Suspicious Log Line: {logs_line}")
    if DEBUG_MODE:
        logging.info(f"Processing: {logs_line}")
    if "UFW" not in logs_line:
        if DEBUG_MODE:
            logging.info(f"Skipped Line: {logs_line}")
        return None

    match = LOG_PATTERN.search(logs_line)
    if not match:
        if DEBUG_MODE:
            logging.info(f"Unmatched Log Line: {logs_line}")
        return None

    ufw_action = match.group('action')  # UFW BLOCK, UFW AUDIT, UFW ALLOW
    ip_src = match.group('ip_src')
    ip_dst = match.group('ip_dst')
    proto = match.group('proto')
    spt = match.group('spt')
    dpt = match.group('dpt')

    if not spt or not dpt and proto in ["TCP", "UDP"]:
        if DEBUG_MODE:
            logging.warning(f"Missing SPT or DPT in Log Line: {logs_line}")
        return None

    # Debugging statement based on DEBUG_MODE
    if DEBUG_MODE:
        logging.info(f"Parsed Log: Action: {ufw_action}, SRC: {ip_src}, DST: {ip_dst}")

    if ipaddress.ip_address(ip_src).is_private or ipaddress.ip_address(ip_dst).is_private:
        return None

    year = get_year_based_on_time(logs_line[0:15])
    timestamp = datetime.strptime(f"{year} {logs_line[0:15]}", "%Y %b %d %H:%M:%S")
    geo_src = get_geolocation(ip_src, logs_reader)

    if geo_src is None:
        geo_src = {}

    jlog_entry = {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "action": ufw_action,
        "ip_src": ip_src,
        "ip_dst": ip_dst,
        "proto": proto,
        "spt": spt,
        "dpt": dpt,
        "geo_src": geo_src,
    }

    # Debugging statement based on DEBUG_MODE
    if DEBUG_MODE:
        logging.info(f"Returning processed log entry: {jlog_entry}")

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
        INSERT INTO ufw_logs (timestamp, action, ip_src, ip_dst, proto, spt, dpt, city_name, country_name,
        latitude, longitude, postal_code, subdivision_name)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    data = []
    for log in db_log_entries:
        geo_src = log.get("geo_src", {})
        data.append((
            log["timestamp"],
            log["action"],
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

if USE_DATABASE:
    connection, cursor = connect_db()
else:
    connection, cursor = None, None

logger.info(f"Service is running, monitoring {LOG_FILE_PATH}...")
process = None
retry_count = 0

try:
    with subprocess.Popen(["tail", "--follow=name", LOG_FILE_PATH],
                          stdout=subprocess.PIPE, universal_newlines=True) as process:

        while process.poll() is None:  # Continue processing while the tail process is running
            logs = []

            for _ in range(BATCH_SIZE):
                logs.append(process.stdout.readline().strip())

            # Processing logs
            jlog_entries = [process_log_line(log, reader) for log in logs if log]
            jlog_entries = [entry for entry in jlog_entries if entry]

            # Write to JSON File
            with open(OUTPUT_LOG_FILE, "a") as f:
                for entry in jlog_entries:
                    json.dump(entry, f, indent=2)

            # If database is enabled, insert logs into the database
            if USE_DATABASE and jlog_entries:
                try:
                    insert_logs(jlog_entries, cursor)
                    connection.commit()
                except Exception as e:
                    logger.error(f"Error inserting logs into the database: {e}")
                    connection.rollback()

            time.sleep(0.5)  # Avoids excessive CPU usage, can be adjusted as necessary

except KeyboardInterrupt:
    logger.info("Gracefully stopping the service...")

except Exception as ex:
    retry_count += 1
    logger.error(f"An error occurred: {ex}")

    if retry_count <= RETRY_LIMIT:
        logger.info(f"Retrying ({retry_count}/{RETRY_LIMIT})...")
    else:
        logger.error(f"Exceeded retry limit. Exiting.")

finally:
    if process:
        process.terminate()  # Ensuring the process is terminated properly.

    safe_close(reader, "GeoIP Reader")

    if cursor:
        cursor.close()
    if connection:
        connection.close()

logger.info("Service has stopped.")
