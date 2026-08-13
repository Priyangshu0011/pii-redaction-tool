# PII Redaction & Anonymization Engine

> **Enterprise Data Assignment Submission**: Production-grade PII Detection, Pseudonymization, and Anonymization System for Word (`.docx`) Documents with 100% Recall, XML Run-Aware Styling Preservation, and Cloud Web Application.

---

## 🌟 Key Features

1. **Multi-Layer Hybrid Detection Engine**:
   - **Regex Engine**: Deterministic patterns for Email, Phone (+91 / 020 landline), CIN, PAN, SSN, Credit Cards, IP Addresses, Dates of Birth.
   - **spaCy NLP NER (`en_core_web_sm`)**: Named entity recognition for Person Names (`PERSON`), Organizations (`ORG`), and Locations/Addresses (`GPE`/`LOC`/`FAC`).
   - **Domain Context Rules**: Indian financial & legal prospectus heuristics (Promoters, Registered Office, Compliance Officers).
2. **XML Run-Stitching & Format Preservation**:
   - Preserves all font styles, bold/italic formatting, alignment, cell shading, tables, headers, footers, and XML node integrity.
   - Handles multi-run split entities (e.g. emails split across multiple XML `<w:r>` tags).
3. **Consistent Pseudonymization**:
   - Replaces PII with realistic synthetic alternatives using `Faker` and deterministic hash mapping.
   - Guaranteed entity consistency across paragraphs, tables, and headers (`Rashi Patil` $\rightarrow$ `John Doe`).
4. **Quantitative Evaluation Suite**:
   - Built-in precision, recall, F1, and accuracy benchmarking suite (`src/evaluator.py`).
   - Reached **100% Recall** across all minimum required PII types.
5. **Interactive Web Dashboard**:
   - Built with FastAPI & Modern Glassmorphism UI (Drag & Drop upload, real-time pie charts, direct download).

---

## 📊 Evaluation Summary

| Metric | Score | Notes |
| :--- | :--- | :--- |
| **Overall Recall** | **100.0%** | Zero PII leakage across ground truth test set |
| **Overall Precision** | **78.3%** | High precision preserving non-sensitive text |
| **Overall F1-Score** | **0.878** | Balanced harmonic mean |
| **Processed Entities** | **2,591** | Total PII items redacted in *Red Herring Prospectus.docx* |

---

## 🚀 Quickstart

### 1. Installation

```bash
# Clone repository
git clone https://github.com/priyangshusett/pii-redaction-tool.git
cd pii-redaction-tool

# Install dependencies
pip install -r requirements.txt
```

### 2. Run CLI Redaction

```bash
python run_redaction.py
```
This processes `Red Herring Prospectus.docx` and generates `Red_Herring_Prospectus_REDACTED.docx`.

### 3. Launch Web Application

```bash
uvicorn app:app --reload
```
Open `http://127.0.0.1:8000` in your browser.

---

## ☁️ Cloud Deployment Guide (Render / Railway / Docker)

### Option A: Render One-Click Deployment
1. Connect this GitHub repository to [Render](https://render.com).
2. Select **Web Service**. Render automatically detects `render.yaml` or `Procfile`.
3. Click **Deploy**.

### Option B: Docker Container
```bash
docker build -t pii-redactor .
docker run -p 8000:8000 pii-redactor
```

---

## 📁 Repository Structure

```
├── app.py                            # FastAPI Web Backend
├── run_redaction.py                  # CLI Redaction Script
├── Enterprise Data - Assignment.docx # Assignment Specification
├── Red Herring Prospectus.docx       # Input Document
├── Red_Herring_Prospectus_REDACTED.docx # Redacted Output Document
├── EVALUATION_STRATEGY_AND_METRICS.md# Detailed Evaluation Report
├── requirements.txt                  # Python Dependencies
├── Procfile / render.yaml / Dockerfile# Deployment Configs
├── src/
│   ├── pii_detector.py               # Regex + spaCy NER Engine
│   ├── anonymizer.py                 # Pseudonymization & Hash Mapping
│   ├── docx_processor.py             # XML Run-Aware Docx Processor
│   └── evaluator.py                  # Benchmark & Metrics Suite
├── static/                           # CSS & Dashboard Assets
└── templates/                        # HTML UI Templates
```
