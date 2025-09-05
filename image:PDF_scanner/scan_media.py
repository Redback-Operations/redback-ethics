from __future__ import annotations
import argparse
from pathlib import Path
import json

from file_handler import *
from ocr_engine import ocr_image, ocr_pdf, OCRConfig
from PIL import Image

def main():

    cfg = OCRConfig()
    dir_path = Path(get_valid_path())
    dir_path.mkdir(parents=True, exist_ok=True)

    records = []
    for path in find_files(dir_path):
        p = Path(path)
        try:
            if p.suffix.lower() == ".pdf":
                text, _ = ocr_pdf(p, cfg)
            elif p.suffix.lower() in {".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp", ".webp"}:
                text = ocr_image(Image.open(p), cfg)
            else:
                continue
        except Exception as e:
            print(f"[WARN] OCR failed for {p}: {e}")
            continue

        out_txt = dir_path / (p.stem + ".txt")
        out_txt.write_text(text, encoding="utf-8")
        records.append({"source": str(p), "text_path": str(out_txt), "chars": len(text)})

    print(f"Done. Wrote {len(records)} files to {dir_path}.")

if __name__ == "__main__":
    main()
