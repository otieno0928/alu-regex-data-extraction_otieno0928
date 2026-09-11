# ALU Data Extraction & Secure Validation flow

## Overview
This program extracts structured data from raw, unstructured text files, enforces domain-specific validation rules for African Leadership University (ALU) email addresses, masks sensitive financial records, and screens for potential security injection threats.


## File Structure
alu-regex-data-extraction_otieno0928/
│
├── input/
│   └── raw-text.txt
├── src/
│   └── main.py
├── output/
│   └── sample-output.json
└── README.md

## Implemented Data Types & Patterns

1. Email Addresses & ALU Specific Rules:
   - Regex: \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b
   - Validations: Categorizes matches into ALU Official (@alueducation.com), ALU Alumni (@alumni.alueducation.com), and ALU SI (@si.alueducation.com). Filters out malformed domains containing double periods (..).

2. Credit Card Numbers:
   - Regex: \b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{4}[-\s]?\d{6}[-\s]?\d{5}\b
   - Security Handling: Implements automatic masking, obscuring all but the final 4 digits (e.g., ************1029).

3. URLs:
   - Regex: https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?
   - Extraction: Captures HTTP/HTTPS web endpoints while discarding invalid domain configurations.

4. Phone Numbers:
   - Regex: (?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b
   - Extraction: Supports local and international phone number formats (e.g., +254..., +250..., (555)...).

## Security Considerations

- Input Sanitization & Injection Prevention: Scans inputs for Cross-Site Scripting (<script>) and SQL Injection queries (SELECT, DROP TABLE). Malicious tokens are isolated and recorded under security_flags.
- Sensitive Data Exposure: PCI-DSS compliant masking applied to all credit card records prior to stdout/JSON output.


## How to Run it 

1. Ensure Python 3.x is installed:
   python3 --version

2. Execute the extraction pipeline:
   python3 src/main.py

3. Review extracted results in output/sample-output.json.
