"""EvidenceShield AI - Launch Full-Stack System.

Runs FastAPI backend on port 8000 serving both API endpoints and the
integrated frontend dashboard.
"""

import os
import sys
import uvicorn

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "crypto"))

if __name__ == "__main__":
    os.chdir(BASE_DIR)
    print("=====================================================================")
    print(" EvidenceShield AI — Full-Stack Zero-Trust Judicial Portal")
    print("=====================================================================")
    print(" Serving Web UI at:   http://127.0.0.1:8000/")
    print(" API Documentation:  http://127.0.0.1:8000/docs")
    print(" Health Endpoint:    http://127.0.0.1:8000/health")
    print("=====================================================================")
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=False)
