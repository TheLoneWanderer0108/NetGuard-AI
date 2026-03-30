import os
import json
from openai import AzureOpenAI
from dotenv import load_dotenv

load_dotenv()

client = AzureOpenAI(
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version=os.getenv("AZURE_OPENAI_API_VERSION"),
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
)

deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst with expertise in threat detection, 
incident response, and log analysis across multiple platforms including Windows Event Logs, 
Linux syslog, firewall logs, web server logs, and cloud provider logs (Azure, AWS).

Your job is to analyze security logs and respond ONLY with a valid JSON object in this exact format:
{
    "is_suspicious": true or false,
    "severity": "none" or "low" or "medium" or "high" or "critical",
    "reason": "Clear explanation of why this log is or is not suspicious",
    "attack_type": "Name of the attack or threat category, or null if not suspicious",
    "mitre_attack": {
        "tactic": "MITRE ATT&CK tactic name or null",
        "technique_id": "MITRE technique ID (e.g. T1078) or null",
        "technique_name": "MITRE technique name or null"
    },
    "recommended_action": "Specific actionable steps the SOC analyst should take",
    "confidence_score": a number between 0 and 100 representing your confidence in this assessment
}

Rules:
- Never include markdown, code fences, or any text outside the JSON object
- Be specific and technical in your reasoning
- Map to MITRE ATT&CK whenever possible
- confidence_score should reflect how clearly the log indicates malicious activity
- If the log is not suspicious, set attack_type and mitre_attack fields to null
"""

def explain_log(log: str, log_type: str = "generic") -> str:
    user_message = f"""Log Type: {log_type}

Analyze the following log entry:
{log}"""

    response = client.chat.completions.create(
        model=deployment,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message}
        ],
        temperature=0.2,
        response_format={"type": "json_object"}
    )

    return response.choices[0].message.content


def clean_ai_response(response_text: str) -> dict:
    # Strip markdown fences just in case (fallback)
    cleaned = response_text.replace("```json", "").replace("```", "").strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "is_suspicious": None,
            "severity": "unknown",
            "reason": cleaned,
            "attack_type": None,
            "mitre_attack": {
                "tactic": None,
                "technique_id": None,
                "technique_name": None
            },
            "recommended_action": "Could not parse structured response — review manually",
            "confidence_score": 0
        }