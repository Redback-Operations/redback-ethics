import os

def find_files(directory, exts=None):
    exts = exts or []
    matches = []
    for dirpath, _, filenames in os.walk(directory):
        for fn in filenames:
            if not exts or any(fn.lower().endswith(e) for e in exts):
                matches.append(os.path.join(dirpath, fn))
    return matches

def read_file(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        return f.read()
