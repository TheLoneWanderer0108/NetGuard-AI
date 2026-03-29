from fastapi import FastAPI
from pydantic import BaseModel
from backend.analyzer import analyze_log
from backend.ai_client import explain_log, clean_ai_response

app = FastAPI()

class LogRequest(BaseModel):
    log: str

@app.get("/")
def home():
    return {"message": "NetGuard AI is up and running ;)"}

@app.post("/analyze")
def analyze(request: LogRequest):
    log = request.log
    rule_analysis = analyze_log(log)
    ai_analysis = clean_ai_response(explain_log(log))

    return {
        "log": log,
        "analysis": rule_analysis,
        "ai_explanation": ai_analysis,
    }
