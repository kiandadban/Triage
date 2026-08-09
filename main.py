import sqlite3
from fastapi import FastAPI
from pydantic import BaseModel
import requests
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

if VT_API_KEY == None:
    raise ValueError("API KEY is not valid")

app = FastAPI()

DB_NAME = "iocs.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            type TEXT NOT NULL,
            verdict TEXT,
            malicious_count INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()

#describes the shape of an incoming IOC
class IOC(BaseModel):
    indicator: str
    type: str

def check_virustotal(indicator: str, ioc_type: str):
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    else:
        return {"verdict": "unsupported", "malicious_count": None}

    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats["malicious"]

    verdict = "malicious" if malicious > 0 else "clean"
    return {"verdict": verdict, "malicious_count": malicious}

@app.get("/")
def read_root():
    return {"message": "IOC enricher is running"}

@app.post("/iocs")
def add_ioc(ioc: IOC):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO iocs (indicator, type) VALUES (?, ?)",
        (ioc.indicator, ioc.type)
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return {"id": new_id, "indicator": ioc.indicator, "type": ioc.type}

@app.get("/iocs")
def get_iocs():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, indicator, type FROM iocs")
    rows = cursor.fetchall()
    conn.close()
    #Return a list of dicts, each dict being an IOC
    return [
        {"id": r[0], "indicator": r[1], "type": r[2]}
        for r in rows
    ]

""" @app.post("/iocs/{ioc_id}/enrich")
def enrich_ioc(ioc_id: int):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE id = ? LIMIT 1)", (ioc_id,))
    result = cursor.fetchone()[0] 
    conn.commit()
    conn.close()

    # 1. look up the IOC in the database by id
    # 2. (cache check) if it already has a verdict, return it — no VT call
    # 3. otherwise call VirusTotal for that indicator
    # 4. parse the verdict
    # 5. save the verdict to the database
    # 6. return it

if __name__ == "__main__":
    print(check_virustotal("8.8.8.8", "ip")) """