import argparse # Handles command line arguments..
from core.parser import parse_log_line
from core.processor import LogProcessor
from core.detector import LogDetector

def main():
    # CLI Arguments
    parser = argparse.ArgumentParser(description="Web Log Analyzer CLI Tool")

    parser.add_argument("--file", required=True, help="Path to log file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Threshold for brute force detection (default: 5)")
    parser.add_argument("--window", type=int, default=60,
                        help="Time window in seconds (default: 60)")

    args = parser.parse_args()

    # Processing
    processor = LogProcessor()

    with open(args.file, "r") as f:
        for line in f:
            parsed = parse_log_line(line)
            processor.add_log(parsed)

    summary = processor.summary()

    # ===== SUMMARY OUTPUT =====
    print("\n====================")
    print("LOG SUMMARY")
    print("====================")

    print(f"\nTotal Requests: {summary['total_requests']}")

    print("\nRequests Per IP:")
    for ip, count in summary["ip_count"].items():
        print(f"  {ip:<15} → {count}")

    print("\nStatus Code Distribution:")
    for status, count in summary["status_count"].items():
        print(f"  {status} → {count}")

    # ===== DETECTION =====
    detector = LogDetector(processor)

    high_traffic = detector.detect_high_traffic(args.threshold)
    brute_force = detector.detect_bruteforce_per_ip(args.threshold)
    time_based = detector.detect_time_based_bruteforce(
        args.threshold,
        args.window
    )

    print("\n====================")
    print("DETECTION RESULTS")
    print("====================")

    if high_traffic:
        print("\nHigh Traffic IPs:")
        for ip, count in high_traffic:
            print(f"  {ip:<15} → {count} requests")

    if brute_force:
        print("\nBrute Force Suspects:")
        for ip, count in brute_force:
            print(f"  {ip:<15} → {count} failed attempts")

    if time_based:
        print("\nTime-Window Brute Force Detected:")
        for ip, count in time_based:
            print(f"  {ip:<15} → {count} attempts within {args.window} seconds")

    if not (high_traffic or brute_force or time_based):
        print("\nNo suspicious activity detected.")

    print("\nAnalysis Complete.")

if __name__ == "__main__":
    main()



