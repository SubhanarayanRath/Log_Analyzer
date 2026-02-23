import re
from datetime import datetime


def parse_log_line(line):
    """
    Parses a single Apache log line.
    Returns a dictionary with:
    ip, timestamp, method, url, status
    """

    pattern = r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<method>\S+) (?P<url>\S+) .*?" (?P<status>\d{3}) \d+'

    match = re.match(pattern, line)

    if not match:
        return None

    ip = match.group("ip")
    time_str = match.group("time")
    method = match.group("method")
    url = match.group("url")
    status = int(match.group("status"))

    # Convert timestamp string to datetime object
    timestamp = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")

    return {
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "url": url,
        "status": status
    }
