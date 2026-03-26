import sys
sys.path.append("../backend")

from main import process_log

logs = [
  "User admin failed login from 192.168.1.10",
  "Port scan detected from 172.16.0.3",
  "User logged in successfully"
]
for log in logs:
   result = process_log(log)
   print("\n---")
   print(result)
