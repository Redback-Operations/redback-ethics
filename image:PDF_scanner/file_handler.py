from __future__ import annotations
import os
from pathlib import Path
from typing import Iterable, List

TEXT_EXTS = {".txt", ".md"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".webp"}
PDF_EXTS = {".pdf"}

def find_files(root: str | os.PathLike, patterns: Iterable[str] | None = None) -> List[Path]:
    root = Path(root)
    results: List[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if patterns:
            for pat in patterns:
                if p.match(pat):
                    results.append(p)
                    break
        else:
            ext = p.suffix.lower()
            if ext in TEXT_EXTS | IMAGE_EXTS | PDF_EXTS:
                results.append(p)
    return results

def read_file(path: str | os.PathLike, binary: bool = False) -> bytes | str:
    mode = "rb" if binary else "r"
    try:
        with open(path, mode, encoding=None if binary else "utf-8", errors=None if binary else "replace") as f:
            return f.read()
    except Exception as e:
        raise IOError(f"Failed to read {path}: {e}")

# Function to get a valid directory path from the user
def get_valid_path():
    while True:
        path = input("Enter the directory path to scan and save the files (press Enter to save in the project folder): ").strip()
        path = path.strip('"').strip("'")  # Remove surrounding quotes if present
        if not path:  # If no input is provided, use the current directory
            print("No path provided. Files will be saved in the project folder.")
            print("-" * 63)
            return os.getcwd()
        elif os.path.isdir(path):  # Validate the provided path
            print("-" * 63)
            return path
        
        else:
            print("We cannot find that path. Please enter a valid directory or press Enter to use the project folder.")