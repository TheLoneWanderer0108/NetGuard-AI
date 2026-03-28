import os
from openai import AzureOpenAI
from dotenv import load_dotenv
import json

load_dotenv()

client = AzureOpenAI(
    api_key = os.getenv("AZURE_OPENAI_API_KEY"),
    api_version = os.getenv("AZURE_OPENAI_API_VERSION"),
    azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")

)

deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

def explain_log(log: str):
    prompt = f"""
    You are a senior SOC analyst.

    Respond in this JSON format:
    {{
    "is_suspicious": true/false,
    "reason": "...",
    "recommended_action": "..."
    }}

    Log:
    {log}
    """

    response = client.chat.completions.create(
        model=deployment,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3
    )

    return response.choices[0].message.content

def clean_ai_response(response_text):
    # Remove markdown ```json ``` wrappers
    cleaned = response_text.replace("```json", "").replace("```", "").strip()
    
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "is_suspicious": None,
            "reason": cleaned,
            "recommended_action": "Could not parse structured response"
        }