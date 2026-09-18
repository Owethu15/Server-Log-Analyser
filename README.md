PROJECT OVERVIEW:
  Imagine you are a security guard in a complex, and your job is to patrol the complex while also taking note of everything that happens at the main entrance of the complex. This includes when a resident enters or leaves the building, a delivery is made or collected from the main entrance, etc. These activities are to be recorded at the instant they occur. Since you are just one person and you cannot be at more than one place at once, fulfilling these duties would be difficult, unless you can ask/hire someone else to work with you, but what if you used a computer to record the activities at the gate for you and you can focus on patrolling the complex? What I have created is your digital companion who thoroughly records, analyses, interprets and relays every activity that occurs at the main entrance to your complex and returns to you a well written summary after each new entry, and continuously updates as each new entry is made.

FEATURES:
  This companion...
    1. Looks at all the log entries and counts line by line how many times a log entry received an "ERROR", a "WARN", or an "INFO" tag and returns to you the final count for each of the tags, at the time of checking.
    2. Reads through the entire log file line by line and tracks the number of times each IP address appears. Each IP address is then collected and counted and the final counts for how often each IP address appeared is returned to you.
    3. Divides the logs into 5 minute intervals and checks which interval received the most "ERROR" messages and returns to you the interval in hh:mm - hh:mm format. This is useful if you want to identify when your system experienced the most "ERROR" messages.
    4. Fires an alert signal when 3 consecutive log entries receive an "ERROR" tag, which may indicate something is seriously wrong.
    5. Fires an alert signal when an IP address appears 3 or more times in a window of 5 IP address appearances, which may indicate something is worth looking into.

TECHNOLOGIES USED:
  The following technologies were used to build and run this service:
    1. Python
    2. Flask

CREDITS:
  Built with pride in RSA by Njabulo Owethu Mabena.
  API layer powered by the Flask web framework.