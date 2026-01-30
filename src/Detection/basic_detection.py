import sys
from collections import Counter
from pathlib import Path
import json



def load_logs(file_path: str) -> list[str]:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with path.open("r", encoding="utf-8") as f:
        return f.readlines()
    
def load_keywords(config_path: str) -> tuple[list[str], str]:
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    keywords = data.get("keywords", [])
    alert_message = data.get(
        "alert_message",
        "Suspicious keyword detected in logs"
    )

    return keywords, alert_message

def detect_frequency_anomalies(logs: list[str], threshold: int = 3) -> list[str]:
    ip_counter = Counter()

    for line in logs:
        if "ip=" in line:
            ip = line.split("ip=")[-1].strip()
            ip_counter[ip] += 1

    findings = [
        f"High activity detected from IP {ip} ({count} events)"
        for ip, count in ip_counter.items()
        if count >= threshold
    ]

    return findings

def detect_suspicious_keywords(logs: list[str],keywords: list[str],alert_message: str) -> list[str]:
    findings = []
    for line in logs:
        for keyword in keywords:
            if keyword.lower() in line.lower():
                findings.append(
                    f"{alert_message}: '{keyword}' -> {line.strip()}"
                )
                break
    return findings

def summarize_findings(findings: list[str]) -> None:
    if not findings:
        print("No suspicious activity detected.")
        return

    print("\n=== Detection Findings ===")
    for finding in findings:
        print(f"- {finding}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python basic_detection.py <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]

    logs = load_logs(log_file)
    keywords, alert_message = load_keywords("config/keywords.json")

    findings = []
    findings.extend(detect_frequency_anomalies(logs))
    findings.extend(detect_suspicious_keywords(logs, keywords, alert_message))

    summarize_findings(findings)

if __name__ == "__main__":
    main()
