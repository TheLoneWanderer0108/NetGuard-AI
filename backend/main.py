from analyzer import analyze_log
from ai_client import explain_log

def process_log(log: str):
  rule_result = analyze_log(log)
  ai_result = explain_log(log)


  return{
   "log": log,
   "analysis": rule_result,
   "ai_explanation": ai_result
}
