# =======================================================
# Project: Server Log Analyser
# Description: Scans server log files to find errors, 
#              patterns, and suspicious activity.
# =======================================================

mockLogs = [
  "2026-09-16 14:30:01 [INFO] User login successful from 192.168.1.10",
  "2026-09-16 14:30:15 [ERROR] Database connection timeout",
  "2026-09-16 14:31:00 [WARN] High memory usage detected",
  "2026-09-16 14:32:10 [ERROR] Failed to load resource",
  "2026-09-16 14:33:05 [INFO] User logout from 192.168.1.10",
  "2026-09-16 14:33:40 [ERROR] Database connection timeout",
  "2026-09-16 14:41:00 [ERROR] Failed login attempt from 192.168.1.45",
  "2026-09-16 14:41:20 [INFO] User login successful from 192.168.1.33",
  "2026-09-16 14:41:45 [ERROR] Failed login attempt from 192.168.1.45",
  "2026-09-16 14:42:00 [WARN] Multiple failed attempts from 192.168.1.45",
  "2026-09-16 14:34:20 [ERROR] Authentication failed for user admin",
  "2026-09-16 14:34:55 [INFO] Backup process started",
  "2026-09-16 14:35:10 [ERROR] Disk read error on /dev/sda1",
  "2026-09-16 14:42:30 [ERROR] Failed login attempt from 192.168.1.45",
  "2026-09-16 14:43:00 [INFO] User login successful from 192.168.1.10",
  "2026-09-16 14:43:20 [ERROR] Failed login attempt from 192.168.1.99",
  "2026-09-16 14:43:45 [ERROR] Failed login attempt from 192.168.1.99",
  "2026-09-16 14:35:30 [WARN] CPU usage above 85%",
  "2026-09-16 14:36:00 [ERROR] Failed login attempt from 192.168.1.45",
  "2026-09-16 14:36:15 [INFO] Cache cleared successfully",
  "2026-09-16 14:36:50 [ERROR] Service timeout: payment gateway",
  "2026-09-16 14:37:10 [WARN] Low disk space on /dev/sdb",
  "2026-09-16 14:44:00 [INFO] User login successful from 192.168.1.33",
  "2026-09-16 14:44:30 [ERROR] Failed login attempt from 192.168.1.99",
  "2026-09-16 14:45:00 [WARN] Unusual traffic from 192.168.1.45",
  "2026-09-16 14:45:30 [ERROR] Failed login attempt from 192.168.1.45",
  "2026-09-16 14:37:45 [ERROR] Null pointer exception in module auth.py",
  "2026-09-16 14:38:00 [INFO] Scheduled task completed",
  "2026-09-16 14:38:30 [ERROR] Connection refused by host 10.0.0.5",
  "2026-09-16 14:39:00 [WARN] Retry attempt 3 of 5 for job queue",
  "2026-09-16 14:39:45 [ERROR] Memory allocation failed",
  "2026-09-16 14:40:10 [INFO] User login successful from 192.168.1.22",
]

with open('logs.txt', 'w') as file:
  for log in mockLogs:
    file.write(log + '\n')

def logAnalysingAgent(file_path):
  logCounts = {
    "ERROR": 0,
    "WARN": 0,
    "INFO": 0
  }
  countIP = {}
  ipCounts = {}
  bucketCounts = {}
  newList = []
  ipList = []
  left = 0
  leftIP = 0
  errorCounts = 0
  k = 3
  k1 = 5

  print(f"---Reading logs from {file_path} ---")
  with open(file_path, 'r') as file:
    for line in file:
      newList.append(line)
      ipList.append(line)
      ip = line.split()[-1]
      minute = line.split()[1]
      bucket = int(minute.split(":")[1]) // 5
      hour = minute.split(":")[0]

      if "ERROR" in line:
        logCounts["ERROR"] = logCounts["ERROR"] + 1
      elif "WARN" in line:
        logCounts["WARN"] = logCounts["WARN"] + 1
      elif "INFO" in line:
        logCounts["INFO"] = logCounts["INFO"] + 1

      if "from" in line:
        if ip in countIP:
          countIP[ip] = countIP[ip] + 1
        else:
          countIP[ip] = 1
      else:
        continue

      if "ERROR" in line:
        if bucket in bucketCounts:
          bucketCounts[bucket] = bucketCounts[bucket] + 1
        else:
          bucketCounts[bucket] = 1
      else:
        continue

      busiestBucket = max(bucketCounts, key=bucketCounts.get)
      lowerInterval = busiestBucket * 5
      upperInterval = (busiestBucket * 5) + 4

    print(f"The following window experienced the most frequent errors ({hour}:{lowerInterval} - {hour}:{upperInterval})")

    print(countIP)

    for right in range(len(newList)):
      char = newList[right]
      if "ERROR" in char:
        errorCounts = errorCounts + 1

      windowSize = right - left + 1
      if errorCounts >= k:
        print("Alert!")

      while windowSize > k and left < len(newList):
        if "ERROR" in newList[left]:
          errorCounts = errorCounts - 1
        left = left + 1
        windowSize = right - left + 1
      
      print(char.strip())

    for rightIP in range(len(ipList)):
      charIP = ipList[rightIP]
      ip1 = charIP.split()[-1]
      if "from" in charIP:
        if ip1 in ipCounts:
          ipCounts[ip1] = ipCounts[ip1] + 1
        else:
          ipCounts[ip1] = 1
      else:
        continue

      windowSize = rightIP - leftIP + 1
      if ipCounts[ip1] >= 3:
        print("Alert: IP ADDRESS THRESHOLD REACHED!")

      while windowSize > k1:
        charIP_left = ipList[leftIP]
        ip2 = charIP_left.split()[-1]
        if "from" in charIP_left:
          ipCounts[ip2] = ipCounts[ip2] - 1
        leftIP = leftIP + 1

        windowSize = rightIP - leftIP + 1

  timeInterval = str(hour) + ":" + str(lowerInterval) + " - " + str(hour) + ":" + str(upperInterval)
  return logCounts, countIP, timeInterval

if __name__ == "__main__":

  finalCounts, finalIPCount, finalBucket = logAnalysingAgent('logs.txt')
  print("==== Today's Sever Log Summary Report ====")
  print(" Below you find the final log counts: ")
  print(finalCounts)
  print(" Below is the frequency of each IP address that visited our servers: ")
  print(finalIPCount)
  print(" The following time interval experienced the most frequent errors: ")
  print(finalBucket)