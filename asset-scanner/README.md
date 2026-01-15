# Redback Ethics Asset Scanner

The **Asset Scanner** is a Python-based tool for detecting sensitive information (PII, secrets, credentials, etc.) in documents, code, and media. Designed for educational use in cybersecurity and ethics modules, the scanner helps students and professionals identify and mitigate risks associated with the exposure of sensitive data.

---

## 🛠️ Key Features

- **Hybrid Detection**: Combines **Microsoft Presidio**'s NLP-based entity recognition with **custom regex patterns** from `patterns.json`.
- **OCR Capabilities**: Scans text within images and PDFs using Optical Character Recognition (OCR) via `ocr_engine.py`.
- **Risk Assessment**: Categorizes findings into _Low_, _Medium_, or _High_ risk levels with references to compliance frameworks (e.g., GDPR, Privacy Act).
- **Flexible Input Handling**: Supports directories, individual files, and various formats, including `.txt`, `.docx`, `.pdf`, `.png`, `.jpg`, and more.
- **Actionable Reports**: Provides detailed mitigation tips and compliance recommendations for each detected risk.
- **Command-Line Interface**: Easy-to-use CLI with options to customize pattern files, output format, and verbosity.

---

## 📂 Project Structure

| File/Directory        | Description                                                                                                |
|-----------------------|------------------------------------------------------------------------------------------------------------|
| `scanner.py`          | Main entry point for scanning files and generating reports.                                                |
| `scan_media.py`       | Handles scanning of media files (images, PDFs) using OCR (`ocr_engine.py`).                                |
| `file_handler.py`     | Manages file discovery and preprocessing (parsing `.docx`, `.txt`, etc.).                                  |
| `ocr_engine.py`       | OCR engine wrapper for extracting text from images and PDFs.                                               |
| `reporter.py`         | Builds structured scan results and outputs reports.                                                        |
| `patterns.json`       | Regex patterns for detecting sensitive items (AWS keys, emails, etc.).                                     |
| `risk_rules.json`     | Maps detected patterns to risk levels, compliance references, and remediation tips.                        |
| `requirements.txt`    | Lists the Python dependencies required to run the scanner.                                                 |

---

## ⚙️ Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/<your-repo>/redback-ethics.git
   cd redback-ethics/asset-scanner
   ```

2. **Create and Activate a Virtual Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install OCR Dependencies (Optional)**:
   - For PDF/image support:
     ```bash
     sudo apt install poppler-utils
     pip install pdf2image pytesseract
     ```

---

## 🚀 Usage

### Scan a Single File:
```bash
python scanner.py --file "/path/to/document.docx"
```

### Scan an Image or PDF (OCR):
```bash
python scan_media.py --file "/path/to/image_or_pdf"
```

### Scan a Directory Recursively:
```bash
python scanner.py --root "/path/to/folder"
```

### Interactive Mode:
Running `scanner.py` without arguments prompts you to specify a directory or file at runtime:
```bash
python scanner.py
```

Output Includes:
- Detected matches with line numbers
- Risk levels (_Low_, _Medium_, _High_)
- Mitigation tips and compliance references

---

## ⚡ Command-Line Interface (CLI)

| Argument      | Type      | Description                                                   | Example                                   |
|---------------|-----------|---------------------------------------------------------------|-------------------------------------------|
| `--file`      | Path      | Scan a single file or multiple                                | `python scanner.py --file "/path/to/doc"` |
| `--root`      | Path      | Recursively scan all files in a directory.                    | `python scanner.py --root "/path/to/"`    |
| `--patterns`  | Path      | Custom path to `patterns.json`.                               | `--patterns ./configs/patterns.json`      |
| `--out`       | Path      | Path to save structured scan results (e.g., `.json`, `.txt`). | `--out results.json`                      |
| `--ext`       | List      | Filter by file extensions (_default: .txt, .docx, .pdf_).     | `--ext .txt .md`                          |
| `--no-console`| Flag      | Suppress console output. Only write to the output file.       | `--no-console`                            |

### Example Usage:
- **Scanning a File**: `python scanner.py --file /example/path/file.docx`
- **Full Folder Scan**: `python scanner.py --root "./sensitive_files"`

---

## 📋 Customization

### `patterns.json`
Defines custom regex patterns for sensitive data detection. Each entry includes:
- `pattern`: The regex string to match.
- `risk`: The associated risk level (_Low_, _Medium_, or _High_).
- `description`: A brief explanation of what the pattern detects.

Example:
```json
{
  "aws_access_key": {
    "pattern": "\\bAKIA[0-9A-Z]{16}\\b",
    "risk": "High",
    "description": "AWS Access Key ID"
  }
}
```

### `risk_rules.json`
Maps patterns to risk levels, mitigation tips, and compliance frameworks:
- `level`: _Low_, _Medium_, or _High_
- `tip`: A recommended action for addressing the risk.
- `compliance`: Legal/regulatory references (e.g., GDPR).

Example:
```json
{
  "aws_access_key": {
    "level": "High",
    "tip": "Rotate immediately; revoke if exposed.",
    "compliance": ["GDPR Art. 33 — Data Breach Notification"]
  }
}
```

---

## 🥼 Example

### Input File:
```
Email: john.doe@example.com
Password: "SuperSecret123"
AWS Key: AKIAIOSFODNN7EXAMPLE
```

### Output:
In **Console**:
```
[Email] -> Medium Risk
Tip: Mask or obfuscate emails in logs/code unless strictly required.
Compliance: Privacy Act 1988 (Cth) — APP 11

[Password] -> High Risk
Tip: Remove hard-coded passwords; rotate immediately.
Compliance: GDPR Art. 32 — Security of processing

[AWS Key] -> High Risk
Tip: Rotate immediately; revoke if exposed.
Compliance: GDPR Art. 33 — Data Breach Notification
```

In **JSON Report**:
```json
[
  {
    "pattern": "email",
    "file": "example.docx",
    "line": 1,
    "match": "john.doe@example.com",
    "risk": "Medium",
    "tip": "Mask or obfuscate emails in logs/code..."
  },
  {
    "pattern": "aws_access_key",
    "file": "example.docx",
    "line": 3,
    "match": "AKIAIOSFODNN7EXAMPLE",
    "risk": "High",
    "tip": "Rotate immediately; revoke if exposed..."
  }
]
```

---

## 🔒 Notes and Limitations

1. **False Positives**: The scanner uses regex and NLP. Carefully tune `patterns.json` to reduce mismatches.
2. **Performance**: Large files or directories with OCR can be resource-intensive. Use efficient hardware.
3. **File Type Support**: By default, only common formats are supported. Extend `file_handler.py` for additional types.

For serious cases (e.g., accidental secret leaks), follow the [Security Policy](SECURITY.md).

---

## 🌟 Contributing

We welcome contributions! Fork the repository, create a feature branch, and submit a pull request.  
Please adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).  
See the `LICENSE` file for full details.
