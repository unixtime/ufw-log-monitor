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


def load_maxmind_db():
    try:
        return maxminddb.open_database(GEOIP_DB_PATH)
    except Exception as error:
        logger.error(f"Error loading MaxMind database: {error}")
        exit(1)


def connect_db():
    try:
        return psycopg2.connect(
            host=os.environ.get("DB_HOST", "your_host"),
            database=os.environ.get("DB_NAME", "your_database"),
            user=os.environ.get("DB_USER", "your_user"),
            password=os.environ.get("DB_PASSWORD", "your_password"),
        )
    except Exception as error:
        logger.error(f"Error connecting to database: {error}")
        exit(1)


def process_log_line(logs_line, logs_reader):
    if "UFW" not in logs_line:
        return None

    ip_src = re.search(r"SRC=([^ ]+)", logs_line).group(1)
    ip_dst = re.search(r"DST=([^ ]+)", logs_line).group(1)

    if (
            ipaddress.ip_address(ip_src).is_private
            or ipaddress.ip_address(ip_dst).is_private
    ):
        return None

    current_year = datetime.now().year
    timestamp_str = logs_line[0:15]
    timestamp = datetime.strptime(
        f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S"
    )
    proto = re.search(r"PROTO=([^ ]+)", logs_line).group(1)
    spt = re.search(r"SPT=([^ ]+)", logs_line)
    dpt = re.search(r"DPT=([^ ]+)", logs_line)
    spt = spt.group(1) if spt else None
    dpt = dpt.group(1) if dpt else None
    geo_src = get_geolocation(ip_src, logs_reader)

    jlog_entry = {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),  # Updated line
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
    data = [
        (
            log["timestamp"],
            log["ip_src"],
            log["ip_dst"],
            log["proto"],
            log["spt"],
            log["dpt"],
            log["geo_src"].get("city_name"),
            log["geo_src"].get("country_name"),
            log["geo_src"].get("latitude"),
            log["geo_src"].get("longitude"),
            log["geo_src"].get("postal_code"),
            log["geo_src"].get("subdivision_name"),
        )
        for log in db_log_entries
    ]
    db_cursor.executemany(query, data)


# Main execution
reader = load_maxmind_db()
connection = connect_db()
cursor = connection.cursor()

logger.info(f"Service is running, monitoring {LOG_FILE_PATH}...")

try:
    process = subprocess.Popen(["tail", "-F", LOG_FILE_PATH], stdout=subprocess.PIPE)
    log_entries = []
    for line in iter(process.stdout.readline, ""):
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
    logger.error(f"Error reading {LOG_FILE_PATH}: {e}")

finally:
    cursor.close()
    connection.close()
    reader.close()
