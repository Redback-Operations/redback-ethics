import re
import json
import os
from typing import List


# Finding class: represents one match of a pattern in a file

class Finding:
    def __init__(self, file: str, line: int, pattern_id: str, snippet: str):
        self.file = file            # File where the match occurred
        self.line = line            # Line number of the match
        self.pattern_id = pattern_id  # Identifier for the matched regex
        self.snippet = snippet      # The actual matched text snippet

    def __repr__(self):
        return f"Finding(file={self.file}, line={self.line}, pattern_id={self.pattern_id}, snippet={self.snippet})"


# RegexScanner class: loads regex patterns and scans files/directories for matches

class RegexScanner:
    def __init__(self, pattern_file: str = "patterns.json"):
        self.patterns = self.load_patterns(pattern_file)

    
    # Loads regex patterns from a JSON file and compiles them
    # Each pattern should be a dict with "id" and "regex"
    
    def load_patterns(self, pattern_file: str) -> List[dict]:
        if not os.path.exists(pattern_file):
            raise FileNotFoundError(f"Pattern file not found: {pattern_file}")

        with open(pattern_file, "r") as f:
            try:
                patterns = json.load(f)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON in pattern file.")

        compiled = []
        for pattern in patterns:
            try:
                compiled.append({
                    "id": pattern["id"],
                    "regex": re.compile(pattern["regex"])
                })
            except re.error as e:
                print(f"Skipping invalid regex (ID: {pattern['id']}): {e}")
        return compiled

    
    # Scans a single text file line by line for pattern matches
    # Returns a list of Finding objects
    
    def scan_file(self, filepath: str) -> List[Finding]:
        findings = []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                for pattern in self.patterns:
                    for match in pattern["regex"].finditer(line):
                        snippet = match.group(0)
                        findings.append(Finding(filepath, lineno, pattern["id"], snippet))
        return findings

    
    # Recursively scans all files in a directory with the given extensions
    # Aggregates results from all files
    
    def scan_directory(self, directory: str, extensions: List[str] = [".txt", ".csv", ".json"]) -> List[Finding]:
        all_findings = []
        for root, _, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    path = os.path.join(root, file)
                    findings = self.scan_file(path)
                    all_findings.extend(findings)
        return all_findings


# Script entry point (runs if file is executed directly)

if __name__ == "__main__":
    # Initialize scanner with patterns from patterns.json
    scanner = RegexScanner("patterns.json")

    # Prompt user to input a directory to scan
    directory_to_scan = input("Enter the directory path to scan: ").strip()

    # Validate the directory exists
    if not os.path.isdir(directory_to_scan):
        print("❌ Invalid directory.")
        exit(1)

    # Run the scan across the directory
    results = scanner.scan_directory(directory_to_scan)

    # Output summary and individual findings
    print(f"✅ Scan complete. {len(results)} findings.")
    for finding in results:
        print(finding)
