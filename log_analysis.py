import re
import csv
from collections import Counter

print("Hello VRV Security!")

# Function to read the log fileclear
def read_log_file(file_path):
    try:
        with open(file_path, 'r') as file:
            logs = file.readlines()
        return logs
    except FileNotFoundError:
        print(f"Error: The file at '{file_path}' was not found.")
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

# Provide the path to the log file
log_file_path = r"C:\Users\ADMIN\VRC_Assignment\sample.log"

# Call the function and read the file
logs = read_log_file(log_file_path)

# Print the first 5 lines to check if it's read correctly
if logs:
    print("First 5 lines of the log file:")
    print("".join(logs[:5]))  # Concatenate and print lines for better formatting
else:
    print("No logs to display.")

def extract_ips(logs):
    ip_pattern = r'^\d+\.\d+\.\d+\.\d+'
    ips = [re.match(ip_pattern, line).group() for line in logs if re.match(ip_pattern, line)]
    return ips

ips = extract_ips(logs)
ip_counts = Counter(ips)
print("IP Address Counts:", ip_counts)

def extract_endpoints(logs):
    endpoint_pattern = r'\"[A-Z]+ (.+?) HTTP'
    endpoints = [re.search(endpoint_pattern, line).group(1) for line in logs if re.search(endpoint_pattern, line)]
    return endpoints

endpoints = extract_endpoints(logs)
endpoint_counts = Counter(endpoints)
most_accessed = endpoint_counts.most_common(1)[0] if endpoint_counts else ("None", 0)
print(f"Most Frequently Accessed Endpoint: {most_accessed[0]} (Accessed {most_accessed[1]} times)")

def detect_suspicious_activity(logs, threshold=10):
    failed_attempts = {}
    for line in logs:
        if "401" in line or "Invalid credentials" in line:
            ip_match = re.match(r'^\d+\.\d+\.\d+\.\d+', line)
            if ip_match:
                ip = ip_match.group()
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    flagged_ips = {ip: count for ip, count in failed_attempts.items() if count >= threshold}
    return flagged_ips

suspicious_ips = detect_suspicious_activity(logs)
print("Suspicious Activity Detected:", suspicious_ips)

def save_to_csv(ip_counts, endpoint_counts, suspicious_ips):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in endpoint_counts.items():
            writer.writerow([endpoint, count])

        writer.writerow([])
        writer.writerow(["Suspicious IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

save_to_csv(ip_counts, endpoint_counts, suspicious_ips)
print("Results saved to log_analysis_results.csv")