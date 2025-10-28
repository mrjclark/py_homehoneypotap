from flask import Flask, Response, abort
import os
from dotenv import load_dotenv
import datetime

# Variables
SIEM_USR="siem"
SIEM_FOLDER=os.path.join("/home",SIEM_USR,"/var/logs")

# Load environment variables from .env
load_dotenv("/home/siem/.env")

# Access the token
API_TOKEN = os.getenv("API_TOKEN")
if not API_TOKEN:
    raise RuntimeError("Missing API token from environment")

def log_request():
    timestamp = datetime.datetime.now().isoformat()
    method = request.method
    path = request.path
    ip = request.remote_addr
    


@app.before_request
def check_token():
    token = request.headers.get("X-API-Token")
    if token != API_TOKEN:
        abort(403)
def log_method():
    print(f"{request.method} request to {request.path}")

@app.route("/logs/<log_name>", methods=["GET"])
def get_log(log_name):
    if log_name not in ["hostapd","dnsmasq"]:
        abort(404)
    path = os.path.join(LOG_DIR, f"{log_name}.log")
    if not os.path.exists(path):
        abort(404)
    with open(path) as f:
        return Response(f.read(), mimetype="text/plain")

if __name__ = "main":
    app.run(
            host="0.0.0.0" # Accessible only from other devices
            ,port=5000     # Default
            ,debug=True    # Auto reload and detailed error pages
            )
    
