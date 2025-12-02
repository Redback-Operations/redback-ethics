#!/usr/bin/env python3
import os
print("Redback Ethics scanner – environment is ready!")
print("Installed packages test:")

try:
    import spacy
    print(f"spaCy {spacy.__version__} OK")
except Exception as e:
    print(f"spaCy failed: {e}")

try:
    from presidio_analyzer import AnalyzerEngine
    print("Presidio Analyzer OK")
except Exception as e:
    print(f"Presidio failed: {e}")

try:
    import cv2
    print(f"OpenCV {cv2.__version__} OK")
except Exception as e:
    print(f"OpenCV failed: {e}")

print("\nNext step: actual scanner code needs to be added in scanner-bot/ or asset-scanner/")