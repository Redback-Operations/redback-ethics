# Redback Dummy Data Generator

A Python-based tool designed to generate realistic dummy data across multiple file formats for testing the Redback Asset Assessment Tool (AAT). The generated files include a mixture of public and synthetic sensitive information to simulate real-world data repositories.

## Features
- Supports multiple file types: **CSV**, **JSON**, **TXT**, **DOCX**, and **PDF**
- Sensitivity levels: **Low**, **Medium**, **High**, **Mixed**
- Randomised file contents with realistic structure
- Console UI for interactive use
- Modular class-based architecture (`DummyDataGenerator`)
- Error handling for PDF generation edge cases

## 🛠️ Setup Instructions and Use

### 1. Clone the repository
```bash
git clone https://github.com/Redback-Operations/redback-ethics.git
cd redback-ethics/dummy_data_generator
```

### 2. Navigate to Project Folder
Open a terminal and navigate to the folder where the project is stored:
```bash
cd path/to/redback-ethics/dummy_data_generator
```

### 3. Create and Activate Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install Required Packages
```bash
pip install -r requirements.txt
```

### 5. Run The Generator
```bash
python main.py
```
The generator will then guide you through creating the documents through its console UI.