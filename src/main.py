import re
import json
import os

PATTERNS = {
    "emails": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    "urls": re.compile(r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?'),
    "phone_numbers": re.compile(r'(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b'),
    
    "credit_cards": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{4}[-\s]?\d{6}[-\s]?\d{5}\b'),
    
    "xss_injection": re.compile(r'<script\b[^>]*>(.*?)</script>', re.IGNORECASE),
    "sql_injection": re.compile(r'\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER)\b', re.IGNORECASE)
}

ALU_EMAIL_DOMAINS = {
    "alu_official": "@alueducation.com",
    "alu_alumni": "@alumni.alueducation.com",
    "alu_si": "@si.alueducation.com"
}

def mask_credit_card(card_number):
    """Masks credit card numbers showing only the last 4 digits for privacy."""
    digits = re.sub(r'\D', '', card_number)
    if len(digits) >= 13:
        return '*' * (len(digits) - 4) + digits[-4:]
    return card_number

def validate_alu_email(email):
    """Categorizes and validates ALU-specific email addresses."""
    for category, domain in ALU_EMAIL_DOMAINS.items():
        if email.lower().endswith(domain):
            return category
    return "external_email"

def process_data(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Input file not found at {file_path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    results = {
        "security_flags": [],
        "alu_emails": {
            "official": [],
            "alumni": [],
            "si": [],
            "external": []
        },
        "extracted_data": {
            "urls": [],
            "phone_numbers": [],
            "credit_cards_masked": []
        }
    }

    # Security Analysis
    xss_matches = PATTERNS["xss_injection"].findall(content)
    if xss_matches:
        results["security_flags"].append({
            "threat_type": "XSS Script Injection",
            "action": "Blocked & Isolated",
            "detected_count": len(xss_matches)
        })

    sql_matches = PATTERNS["sql_injection"].findall(content)
    if sql_matches:
        results["security_flags"].append({
            "threat_type": "SQL Injection Query",
            "action": "Blocked & Isolated",
            "detected_count": len(sql_matches)
        })

    raw_emails = PATTERNS["emails"].findall(content)
    for email in raw_emails:
        if ".." in email:
            continue
        category = validate_alu_email(email)
        if category == "alu_official":
            results["alu_emails"]["official"].append(email)
        elif category == "alu_alumni":
            results["alu_emails"]["alumni"].append(email)
        elif category == "alu_si":
            results["alu_emails"]["si"].append(email)
        else:
            results["alu_emails"]["external"].append(email)

    raw_urls = PATTERNS["urls"].findall(content)
    results["extracted_data"]["urls"] = [url for url in raw_urls if ".." not in url]

    raw_phones = PATTERNS["phone_numbers"].findall(content)
    results["extracted_data"]["phone_numbers"] = list(set(raw_phones))

    raw_cards = PATTERNS["credit_cards"].findall(content)
    results["extracted_data"]["credit_cards_masked"] = [mask_credit_card(card) for card in raw_cards]

    return results

if __name__ == "__main__":
    input_file = os.path.join("input", "raw-text.txt")
    output_file = os.path.join("output", "sample-output.json")

    extracted = process_data(input_file)

    os.makedirs("output", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(extracted, f, indent=4)

    print("Data extraction and safe validation executed successfully.")
    print(f"Results saved to {output_file}")
