#!/usr/bin/env python3
import argparse
import requests
import time
import re
from pathlib import Path
from openai import OpenAI
 # To integrate OpenAI's API

# API URLs and configurations
OLLAMA_API_URL = "http://192.168.1.8:11434/api/generate"
OPENAI_API_KEY = "openai"
DEFAULT_MODEL = "llama3.2:3b"
USE_OPENAI = False


REPORT_TEMPLATE = """# {title}

**Severity**: {severity}

## Description
{description}

## Remediation
{remediation}

_Report generated at {timestamp} using {model}_"""

SYSTEM_PROMPT = """You are a highly skilled security researcher specializing in identifying vulnerabilities across web, API, Android, and iOS platforms. Your task is to report vulnerabilities in the following structured format:

[Title]
{Platform}: {Vulnerability Name} - {Specific Location/Component}

[Description]
Concise explanation of the vulnerability, including:
- Affected component/endpoint
- Technical cause (e.g., lack of input validation)
- Demonstrable impact (e.g., "could expose 15,000 user credentials")
- Attack vector (if non-obvious)

[Remediation]
Numbered list of specific, actionable fixes:
1. Technical solutions (e.g., "Implement parameterized queries")
2. Configuration changes (e.g., "Set HttpOnly flag on cookies")
3. Monitoring/validation (e.g., "Add WAF rules to block SQLi patterns")

Guidelines:
1. Title must specify platform (web/api/android/ios) and location
2. Description should reference application-specific implementation flaws
3. Remediations must be executable by developers
4. Use real-world metrics where applicable ("exposes payment records", "grants admin privileges")
5. Format remediation steps as a numbered list
6. Omit CVSS, PoC, and reproduction steps unless explicitly requested

Example Format:
[Title]
API: Unrestricted File Upload in document-conversion API

[Description]
The document conversion endpoint accepts executable .jar files through its multipart form handler. This flaw stems from missing file-type validation in the Node.js middleware, allowing attackers to upload malicious binaries to AWS S3 storage (15MB file limit). Successful exploitation could enable remote code execution on processing servers.

[Remediation]
1. Implement allow-list validation for file extensions (PDF/DOCX/PNG only)
2. Add magic byte verification using the 'file-type' library
3. Configure S3 bucket policies to reject unauthorized MIME types
4. Isolate document processing in a serverless environment with 5-minute execution limits"""

# Function to interact with Ollama API
def generate_report_ollama(vulnerability_name: str, model: str) -> dict:
    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={
                "model": model,
                "prompt": f"Vulnerability: {vulnerability_name}",
                "system": SYSTEM_PROMPT,
                "options": {"temperature": 0, "top_k":0},
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
        "title": "",
        "description": "",
        "remediation": ""
    }

    # print(raw_text)
    # Extract title with [Title] format
    title_match = re.search(r'\[Title\]\s*\n(.+?)(?=\n\[|\n$)', raw_text, re.IGNORECASE | re.DOTALL)
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

    if not report["remediation"] or not report["description"]:
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
