from collections import defaultdict


class LogProcessor:
    def __init__(self):
        # Store all parsed logs
        self.logs = []

        # Count requests per IP
        self.ip_count = defaultdict(int)

        # Count status codes
        self.status_count = defaultdict(int)

        # Determines IP
        self.ip_status_count = defaultdict(lambda: defaultdict(int))



    def add_log(self, parsed_log):
        if not parsed_log:
            return

        self.logs.append(parsed_log)

        ip = parsed_log["ip"]
        status = parsed_log["status"]

        self.ip_count[ip] += 1
        self.status_count[status] += 1
        self.ip_status_count[ip][status] += 1

    def summary(self):
        return {
    "total_requests": len(self.logs),
    "ip_count": dict(self.ip_count),
    "status_count": dict(self.status_count),
    "ip_status_count": {
        ip: dict(status_map)
        for ip, status_map in self.ip_status_count.items()
    }
}

        

        
