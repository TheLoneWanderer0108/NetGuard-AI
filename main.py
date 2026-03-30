from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator
from typing import Optional
from pathlib import Path
from backend.analyzer import analyze_log
from backend.ai_client import explain_log, clean_ai_response

app = FastAPI(
    title="NetGuard AI",
    description="AI-powered SOC assistant for log analysis and threat detection",
    version="1.0.0"
)

SUPPORTED_LOG_TYPES = [
    "generic",
    "windows_event",
    "linux_syslog",
    "firewall",
    "nginx",
    "apache",
    "azure",
    "aws"
]

class LogRequest(BaseModel):
    log: str
    log_type: Optional[str] = "generic"

    @field_validator("log")
    @classmethod
    def log_must_not_be_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("Log entry cannot be empty")
        if len(v) > 10000:
            raise ValueError("Log entry too large — max 10,000 characters")
        return v.strip()

    @field_validator("log_type")
    @classmethod
    def validate_log_type(cls, v):
        if v not in SUPPORTED_LOG_TYPES:
            return "generic"
        return v


@app.get("/")
def home():
    return FileResponse(Path(__file__).with_name("index.html"))


@app.get("/health")
def health():
    return {
        "message": "NetGuard AI is up and running ;)",
        "version": "1.0.0",
        "supported_log_types": SUPPORTED_LOG_TYPES
    }


@app.post("/analyze")
def analyze(request: LogRequest):
    try:
        rule_analysis = analyze_log(request.log)
        ai_analysis = clean_ai_response(
            explain_log(request.log, request.log_type)
        )

        return {
            "log": request.log,
            "log_type": request.log_type,
            "analysis": rule_analysis,
            "ai_explanation": ai_analysis,
            # Backward-compatible aliases
            "rule_based_analysis": rule_analysis,
            "ai_analysis": ai_analysis,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/log-types")
def get_log_types():
    return {"supported_log_types": SUPPORTED_LOG_TYPES}