def analyze_log(log: str):
 log = log.lower()
 
 if "failed login" in log:
  return{
     "threat": "Brute Force Attempt",
     "severity": "HIGH"
}
 elif "port scan" in log:
  return{
    "threat": "Reconnaissance Activity",
    "severity": "MEDIUM"
}

 else:
  return{
    "threat": "Normal Activity",
    "severity": "LOW"
}
