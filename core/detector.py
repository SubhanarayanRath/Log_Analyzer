from datetime import timedelta


class LogDetector:
    def __init__(self, processor):
        self.processor = processor
        
# detects possible DDoS, Excessive scraping, Bot behaviour..

    def detect_high_traffic(self, threshold=10):
        suspicious_ips = []

        for ip, count in self.processor.ip_count.items():
            if count > threshold:
                suspicious_ips.append((ip, count))

        return suspicious_ips
    
#Detects classic brute-force attack, How many failed login attempts from same IP.

    def detect_bruteforce_per_ip(self, threshold=5):
        suspicious_ips = []

        for ip, status_map in self.processor.ip_status_count.items():
            failed_attempts = status_map.get(401, 0)

            if failed_attempts >= threshold:
                suspicious_ips.append((ip, failed_attempts))

        return suspicious_ips
#Detect: -System under attack, Widespread login failure attempts

    def detect_many_401(self, threshold=5):
        count_401 = self.processor.status_count.get(401, 0)
        return count_401 >= threshold

# Useful for Access control scanning, Directory brute forcing

    def detect_many_403(self, threshold=5):
        count_403 = self.processor.status_count.get(403, 0)
        return count_403 >= threshold

    def detect_time_based_bruteforce(self, threshold=5, window_seconds=60):
        suspicious_ips = []

        # Step 1: Collect all failed login timestamps per IP
        ip_failed_timestamps = {}

        for log in self.processor.logs:
            if log["status"] == 401:
                ip = log["ip"]
                timestamp = log["timestamp"]

                if ip not in ip_failed_timestamps:
                    ip_failed_timestamps[ip] = []

                ip_failed_timestamps[ip].append(timestamp)

        # Step 2: Sliding window check
        for ip, timestamps in ip_failed_timestamps.items():
            timestamps.sort()

            for i in range(len(timestamps)): # Picks a starting timestamp.
                window_start = timestamps[i]
                count = 1

                for j in range(i + 1, len(timestamps)): # checks next timestamps.
                    if timestamps[j] - window_start <= timedelta(seconds=window_seconds):
                        count += 1
                    else:
                        break

                if count >= threshold:
                    suspicious_ips.append((ip, count))
                    break

        return suspicious_ips
