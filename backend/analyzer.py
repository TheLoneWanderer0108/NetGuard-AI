def analyze_log(log: str):
 log = log.lower()
 
 if "failed login" in log:
  return{
     "threat": "Brute Force Attempt",
     "severity": "High"
}
 elif "port scan" in log:
  return{
    "threat": "Reconnaissance Activity",
    "Severity": "Medium"
}

 else:
  return{
    "Threat": "Normal Activity",
    "Severity": "LOW"
}
