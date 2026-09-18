from flask import Flask, jsonify
from server_log_analyser import logAnalysingAgent

app = Flask(__name__)

@app.route("/")
def home():
  return "Server Log API is running!"

@app.route("/analyse")
def analyse():
  finalCounts, finalIPCount, finalBucket = logAnalysingAgent('logs.txt')
  return jsonify ({
    "logCounts": finalCounts,
    "ipCounts": finalIPCount,
    "busiestTimeInterval": finalBucket
  })

if __name__ == "__main__":
  app.run(debug=True)