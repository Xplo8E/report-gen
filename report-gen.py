#!/usr/bin/env python3
import argparse
import requests
import time
import re
from pathlib import Path
from openai import OpenAI
 # To integrate OpenAI's API

# API URLs and configurations
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OPENAI_API_KEY = "openai"
DEFAULT_MODEL = "qwen2.5:3b"
USE_OPENAI = False


REPORT_TEMPLATE = """# {title}

**Severity**: {severity}

## Description
{description}

## Remediation
{remediation}

_Report generated at {timestamp} using {model}_"""

SYSTEM_PROMPT = """You are a senior cybersecurity analyst. Generate vulnerability reports with this structure:

[Title]
- Precise vulnerability identification (5-10 words)
- Explicit affected component (e.g., "Payment Gateway API")

[Description]
Single paragraph containing:
1. Vulnerability type/location
2. Essential exploitation path (if critical)
3. Demonstrable technical/business impact

[Remediation]
2-3 technical fixes:
- Specific implementation actions
- Exact security mechanisms
- No explanations or validation steps

### Example:
[Title]
SQL Injection in User Search Endpoint

[Description]
The /api/v1/users endpoint lacks input sanitization, allowing attackers to inject malicious SQL payloads through search parameters. This could enable unauthorized database access, potentially exposing 2.3M customer records including payment information.

[Remediation]
1. Implement parameterized queries using Python's SQLAlchemy ORM
2. Deploy regex validation allowing only alphanumeric characters in search inputs
3. Add WAF rules blocking SQL pattern matches (OWASP CRS ID 942100-942199)

### Mandatory Requirements:
1. Description must be 3-4 lines maximum - no technical jargon or secondary explanations
2. Omit exploitation mechanics unless essential to demonstrate attacker value
3. Remediation must be 2-3 bullet points
4. Each point ≤ 12 words - pure technical action
5. No explanations/rationale - only fix implementation
6. Prioritize code/config changes over policies
7. Use specific libraries/tools (e.g., "Use bcrypt hashing" not "improve password security")"""

# Function to interact with Ollama API
def generate_report_ollama(vulnerability_name: str, model: str) -> dict:
    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={
                "model": model,
                "prompt": f"Vulnerability: {vulnerability_name}",
                "system": SYSTEM_PROMPT,
                "options": {"temperature": 0.7},
                "stream": False,
                "keep_alive": 0
            },
            timeout=60
        )
        response.raise_for_status()
        data = response.json()
        if "response" not in data:
            raise ValueError("Unexpected API response: 'response' key missing")
        return parse_response(data["response"])
    except (requests.RequestException, ValueError, KeyError) as e:
        return {"error": f"Generation failed: {str(e)}"}

# Function to interact with OpenAI API
def generate_report_openai(vulnerability_name: str, model: str) -> dict:
    try:
        client = OpenAI(api_key=OPENAI_API_KEY, base_url="https://api.deepseek.com")
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Vulnerability: {vulnerability_name}"}
        ]
        
        # f"Vulnerability: {vulnerability_name}\n{SYSTEM_PROMPT}"

        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.4,
            max_tokens=150,
            timeout=30
        )

        return parse_response(response['choices'][0]['text'])
    except (requests.RequestException, ValueError, KeyError) as e:
        return {"error": f"Generation failed: {str(e)}"}

# Function to parse the generated report
def parse_response(raw_text: str) -> dict:
    report = {
        "title": "Security Vulnerability Report",
        "description": "",
        "remediation": ""
    }

    # print(raw_text)
    # Extract title
    title_match = re.search(r'### Title\s*(.*?)(?=\n###|\n$)', raw_text, re.IGNORECASE | re.DOTALL)
    if title_match:
        report["title"] = title_match.group(1).strip()

    # Extract description
    desc_match = re.search(r'(?:###\s?Description|\[Description\])\s*\n([^\[]+)', raw_text, re.IGNORECASE | re.DOTALL)
    if desc_match:
        report["description"] = desc_match.group(1).strip()

    # Extract remediation, regex matches all the bullet points in the remediation section

    rem_match = re.search(r'(?:###\s?Remediation|\[Remediation\])\s*\n([^\[]+)', raw_text, re.IGNORECASE | re.DOTALL)
    if rem_match:
        report["remediation"] = rem_match.group(1).strip()
        # Clean up and extract the remediation steps
        # remediation_lines = [line.strip() for line in remediation_content.splitlines() if line.strip()]
        # if remediation_lines:
        #     report["remediation"] = "\n".join(remediation_lines)
        # else:
        #     report["remediation"] = "No specific remediation steps found."
    else:
        report["remediation"] = "Failed to parse remediation section. Raw response:\n"

    # Fallback validation for missing sections
    if not report["description"]:
        report["description"] = "Failed to parse description. Raw response:\n"

    if not report["remediation"] or report["description"]:
        print(raw_text)

    return report

# Main function to handle arguments and call the relevant API
def main():
    parser = argparse.ArgumentParser(description="AI Security Report Generator")
    parser.add_argument("vulnerability", help="Vulnerability details (e.g., 'Session fixation in authentication system')")
    parser.add_argument("-m", "--model", default=DEFAULT_MODEL, help="AI model to use ('openai' or 'ollama')")
    
    args = parser.parse_args()

    # Select the correct API based on the model argument
    if USE_OPENAI:
        report_data = generate_report_openai(args.vulnerability, args.model)
    else:
        report_data = generate_report_ollama(args.vulnerability, args.model)
    
    if "error" in report_data:
        print(f"Error: {report_data['error']}")
        return

    # Build final report
    report_content = REPORT_TEMPLATE.format(
        title=report_data["title"],
        severity="High",  # Default severity; can be adjusted dynamically
        description=report_data["description"],
        remediation=report_data["remediation"],
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        model=args.model
    )

    # Print report to console
    print("\nGenerated Report:\n")
    print(report_content)

if __name__ == "__main__":
    main()
