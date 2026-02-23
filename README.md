# Web Log Analyzer & Intrusion Detection CLI Tool

A modular Python-based command-line tool for analyzing Apache server logs and detecting activity patterns such as brute force attempts and abnormal traffic spikes.

## Problem Statement

Web Servers generate large volumes of access logs cointaining information about timestamps and IP addresses. Manually analyzing these logs to identify suspicious behaviour such as brute force attacks or abnormal traffic spikes is inefficient and error-prone. There is a need for an automated solution that can process logs, extract meaningful statistics, and detect potential security threats.

## Objective 

The Objective of this project is to develop a command-line log analysis tool that :
 * Parses Apache anf server log files .
 * Extracts structured information from raw log lines.
 * Aggregates request statistics such as IP frequency and status code distribution.
 * Detects suspicious activity using rule-based detection logic.
 * Allows configurable thresholds for security analysis.

## Features

* Apache log line parsing,
* Request aggregation per IP address,
* HTTP status code distribution analysis,
* High traffic IP detection,
* Brute force detection based on repeated 401 requests,
* Time-Window based brute force detection,
* CLI configurable detections thresholds.

## Project Architecture

The project follows a modular structure to separate responsibilities such as parsing, processing, and detection. This improves maintainability and scalability.

 Different Modules are :-

1. main.py
Acts as the entry point of the application. It handles command-line arguments, reads the log file, and coordinates parsing, processing, and detection.

2. core/parser.py
Responsible for parsing raw Apache log lines and converting them into structured dictionary objects.

3. core/processor.py
Stores parsed logs and maintains aggregated statistics such as total requests, requests per IP, and status code distribution.

4. core/detector.py
Contains rule-based detection algorithms to identify suspicious activity like high traffic, brute force attempts, and time-based attacks.

## Execution Flow 

1. The user provides the log file path and optional detection parameters through CLI arguments.

2. main.py reads the log file line by line.

3. Each log line is passed to parser.py, which converts it into structured data.

4. The structured data is stored and aggregated by processor.py.

5. detector.py analyzes the processed data using rule-based detection algorithms.

* The results are printed in the terminal as summary statistics and detection findings.

## Detection Logic

1. High Traffic Detection

Identifies IP addresses, whose total request count exceeds a user-defined threshold. This helps detect abnormal traffic spikes or potential suspicious behavior.

2. Brute Force Detection (Per IP)

Flags IP addresses, that generate repeated HTTP 401 (Unauthorized) responses beyond the defined threshold. This may indicate password guessing attempts.

3. Time-Window Based Brute Force Detection

Analyzes failed login attempts within a configurable time window. If multiple 401 responses occur within a short duration from the same IP, it is flagged as suspicious. This uses a sliding time window approach.

* Both threshold and time window values can be configured through CLI arguments.

## Usage 

To run the Log Analyzer:
   * python main.py --file sample_logs.txt

With custom threshold and time Window:
   * python main.py --file sample_logs.txt --threshold 5 --window 60
   
* Parameters explaination:- 

1. --file = Path to the log file(required)
2. --threshold = Threshold for detection(default:5)
3. --window = Time window in seconds for time-based detection(default:60)

## Future Improvements

* Support streaming log analysis instead of processing only static files. This would allow monitoring live server activity.

* Improve detection logic by reducing nested loops in the time-window algorithm to optimize performance for large log files.

* Add export functionality to save summary results in CSV format for further analysis.

* Add support for additional HTTP status-based detections such as repeated 403 responses.

* Extend compatibility to support different log formats beyond Apache default format.

## Sample Output
``` 
====================
LOG SUMMARY
====================

Total Requests: 13

Requests Per IP:
  192.168.1.10    → 11
  192.168.1.15    → 1
  10.0.0.5        → 1

Status Code Distribution:
  200 → 1
  302 → 1
  403 → 1
  401 → 10

====================
DETECTION RESULTS
====================

High Traffic IPs:
  192.168.1.10    → 11 requests

Brute Force Suspects:
  192.168.1.10    → 10 failed attempts

Time-Window Brute Force Detected:
  192.168.1.10    → 10 attempts within 60 seconds

Analysis Complete.
```