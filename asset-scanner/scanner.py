#!/usr/bin/env python3
"""
scanner.py — Redback Ethics PII & Secrets Scanner (Presidio-powered)

Features:
  • Hybrid detection: Microsoft Presidio (NLP) + custom regex fallback
  • High-accuracy detection of names, emails, phones, credit cards, addresses
  • Keeps full compatibility with:
      - patterns.json → only secrets not covered by Presidio needed
      - reporter.py → identical findings schema and exit code behavior

Findings schema (unchanged):
  {
    "pattern": <id from patterns.json or Presidio entity>,
    "file": <path>,
    "line": <int>,
    "match": <raw string>,
    "description": <str>
  }

Exit code:
  • 1 → if any High-risk finding (via reporter.write_report + risk_rules.json)
  • 0 → otherwise

Now requires: pip install presidio-analyzer
"""

from __future__ import annotations
import argparse
import json
import re
import sys
from bisect import bisect
from typing import Dict, Any, Iterable, List
import os

# Presidio 
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer import PatternRecognizer, Pattern
except ImportError:
    print("[!] ERROR: presidio-analyzer not installed")
    print("    Run: pip install presidio-analyzer")
    sys.exit(1)

from file_handler import find_files, read_file
from reporter import write_report, generate_console_report

# Defaults
DEFAULT_PATTERNS_FILE = "patterns.json"
DEFAULT_TARGET_EXTS = [".py", ".txt", ".md", ".cfg", ".json", ".docx", ".csv", ".pdf", ".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".webp"]
DEFAULT_OUT = "scan_report.local.json"

# Presidio Engine (auto-download once)
def get_analyzer() -> AnalyzerEngine:
    print("[i] Initializing Presidio analyzer (first run downloads ~120 MB model)...")
    return AnalyzerEngine()

# Load patterns.json 
def load_patterns(path: str) -> Dict[str, Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"[i] Loaded {len(data)} patterns from {path}")
    return data

#  Core scanning 
def scan_text(text: str, file_path: str, analyzer: AnalyzerEngine, patterns_meta: Dict) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not text.strip():
        return findings

    newlines = [i for i, c in enumerate(text) if c == "\n"]

    # Presidio scan
    try:
        results = analyzer.analyze(text=text, language="en", score_threshold=0.01)
        print(f"[i] Presidio found {len(results)} potential entities in {os.path.basename(file_path)}")

        for r in results:
            if r.score < 0.3:
                continue

            # Map Presidio entity to pattern ID
            entity = r.entity_type.upper()
            pattern_id = None

            # Direct match via "presidio_entity" field in patterns.json
            for pid, rule in patterns_meta.items():
                if rule.get("presidio_entity", "").upper() == entity:
                    pattern_id = pid
                    break
            # Fallback: common built-in names
            if not pattern_id:
                fallback_map = {
                    "EMAIL_ADDRESS": "email",
                    "PHONE_NUMBER": "phone",
                    "CREDIT_CARD": "credit_card",
                    "US_SSN": "ssn",
                    "PERSON": "full_name",
                    "LOCATION": "location",
                    "IP_ADDRESS": "ip_address"
                }
                pattern_id = fallback_map.get(entity, entity.lower())

            line = bisect(newlines, r.start) + 1
            match_text = text[r.start:r.end]

            findings.append({
                "pattern": pattern_id,
                "file": file_path,
                "line": line,
                "match": match_text,
                "description": patterns_meta.get(pattern_id, {}).get("description", f"Detected {entity}")
            })
            print(f"    → Found: {pattern_id} | {match_text} | Line {line}")

    except Exception as e:
        print(f"[!] Presidio crashed: {e}")

    # regex fallback
    for pid, rule in patterns_meta.items():
        pat = rule.get("pattern")
        if not pat or pat == "NOT_NEEDED":
            continue
        try:
            for m in re.finditer(pat, text, re.DOTALL):
                line = bisect(newlines, m.start()) + 1
                findings.append({
                    "pattern": pid,
                    "file": file_path,
                    "line": line,
                    "match": m.group(0),
                    "description": rule.get("description", pid)
                })
                print(f"    → Regex hit: {pid} | {m.group(0)} | Line {line}")
        except re.error:
            pass

    return findings

def scan_folder_or_file(file=None, root=None, extensions=None):
    """Scan either a single file or all relevant files in the folder."""
    if file:
        # Single file scan
        return [file]  # Return as a single-element list for compatibility
    else:
        # Scan entire folder
        return find_files(root, exts=extensions)

# file scanner
def scan_paths(paths, analyzer, patterns_meta):
    """Process and scan all provided files."""
    all_findings = []

    for path in paths:  # Loop through `paths`, one file at a time
        print(f"[i] Scanning file: {path}")  # Log the file being scanned
        try:
            content = read_file(path)  # Pass a single file to `read_file()`
            if not content.strip():  # Skip empty or unsupported files
                print(f"[i] Skipping unsupported or empty file: {path}")
                continue

            # Scan file content
            findings = scan_text(content, path, analyzer, patterns_meta)
            all_findings.extend(findings)  # Collect results
        except Exception as e:
            print(f"[!] Error processing file {path}: {e}")
            continue  # Skip to the next file on error

    return all_findings

# CLI & main
def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Sensitive data scanner")
    ap.add_argument(
        "--file", nargs="*", help="One or more specific files to scan (space-separated list)"
    )  # `nargs="*"` allows multiple files
    ap.add_argument(
        "--root", nargs="*", help="One or more directories for recursive scanning"
    )
    ap.add_argument(
        "--patterns", default="patterns.json", help="Path to patterns.json"
    )
    ap.add_argument(
        "--ext", nargs="*", default=[".txt", ".json"], help="File extensions to include (e.g., .txt .pdf)"
    )
    ap.add_argument(
        "--out", default="scan_report.local.json", help="Output file for results"
    )
    return ap.parse_args(argv or sys.argv[1:])

def get_valid_path():
    while True:
        path = input("Enter directory (or Enter for current): ").strip().strip('"\'')
        if not path:
            return os.getcwd()
        if os.path.isdir(path):
            return path
        print("Invalid path, try again.")

def main():
    # Parse arguments from the CLI
    ns = parse_args()  # Contains file, root, patterns, ext, and out args

    # Load patterns and initialize the analyzer
    patterns_meta = load_patterns(ns.patterns)
    analyzer = get_analyzer()

    # Determine files to scan (using --file and --root)
    paths = []  # Initialize an empty list to store all files
    if ns.file:  # Add files passed using the --file argument
        paths.extend(ns.file)  # ns.file is already a list of files

    if ns.root:  # Add files from folders passed using --root
        for folder in ns.root:
            folder_files = find_files(folder, extensions=ns.ext)  # Recursively find files
            paths.extend(folder_files)

    # Validate if any files were found
    if not paths:
        print("[!] No files found to scan. Please check your input.")
        return 0

    print(f"[i] Found {len(paths)} files to scan.")

    # Scan the files
    findings = scan_paths(paths, analyzer, patterns_meta)

    # Write the scan results to an output report file
    enriched = write_report(findings, out_path=ns.out)
    print(f"\n[i] Full report (with paths & raw PII) saved locally → {ns.out}")
    print("    This file is git-ignored and must NEVER be committed.")

    # Handle scan results and risk evaluation
    if any(f.get("risk") == "High" for f in enriched):
        print("\n[!] HIGH-RISK PII DETECTED → SCAN FAILED")
        return 1
    elif findings:
        print(f"\n[i] {len(findings)} findings → check {ns.out}")
    else:
        print("\n[Success] NO PII FOUND!")
    return

if __name__ == "__main__":
    raise SystemExit(main())