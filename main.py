from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path
from backend.analyzer import analyze_log
from backend.ai_client import explain_log, clean_ai_response

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LogRequest(BaseModel):
    log: str

@app.get("/")
def home():
    return FileResponse(Path(__file__).with_name("index.html"))

@app.get("/health")
def health():
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
