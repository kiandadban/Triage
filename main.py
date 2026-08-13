import sqlite3
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
import requests
import os
from dotenv import load_dotenv
import re

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
            indicator TEXT NOT NULL UNIQUE,
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

#This is for inputs into a text box
class TextInput(BaseModel):
    text: str

@app.get("/", response_class=HTMLResponse)
def serve_page():
    return FileResponse("index.html")

@app.get("/iocs")
def get_iocs() -> list[dict]:
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, indicator, type, verdict, malicious_count FROM iocs")
    rows = cursor.fetchall()
    conn.close()
    #Return a list of dicts, each dict being an IOC
    return [
        {"indicator": r[1], "type": r[2], "verdict": r[3],
        "malicious_count": r[4]}
        for r in rows
    ]

@app.post("/check-file")
async def check_file(file: UploadFile):
    contents = await file.read()
    text = contents.decode("utf-8")

    # extract indicators from the raw text
    found = extract_indicators(text)

    # enrich each IOC
    results = []
    for item in found:
        ioc = IOC(indicator=item["indicator"], type=item["type"])
        results.append(process_ioc(ioc))

    return results

@app.post("/check-text")
def check_text(payload: TextInput):
    found = extract_indicators(payload.text)
    results = []
    for item in found:
        ioc = IOC(indicator=item["indicator"], type=item["type"])
        results.append(process_ioc(ioc))
    return results

#Helper to decide if an IOC is malicious
def derive_verdict(stats) -> str:
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]
    if malicious >= 3:
        return "malicious"
    elif malicious >= 1 or suspicious >= 2:
        return "suspicious"
    elif harmless == 0:
        return "undetected"
    else:
        return "clean"
    
#Helper function that returns virustotal's verdict
def check_virustotal(indicator: str, ioc_type: str) -> dict:
    ioc_type = ioc_type.lower()
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    else:
        return {"verdict": "unsupported", "malicious_count": None}

    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    data = response.json()

    attributes = data["data"]["attributes"]
    stats = attributes["last_analysis_stats"]
    malicious = stats["malicious"]

    verdict = derive_verdict(stats)
    return {"verdict": verdict, "malicious_count": malicious}

#Helper function to process and IOC and give a verdict
def process_ioc(ioc: IOC) -> dict:
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    #Fetch IOC by indicator
    cursor.execute(
                "SELECT indicator, type, verdict, malicious_count FROM iocs WHERE indicator = ?", 
                (ioc.indicator,))
    row = cursor.fetchone()

    # already in DB AND already enriched then just return
    if row is not None and row[2] is not None:
        conn.close()
        return {
            "indicator": row[0], "type": row[1],
            "verdict": row[2], "malicious_count": row[3]
        }

    # otherwise we need to enrich
    result = check_virustotal(ioc.indicator, ioc.type)

    if row is None:
        # brand new IOC
        cursor.execute(
            "INSERT INTO iocs (indicator, type, verdict, malicious_count) VALUES (?, ?, ?, ?)",
            (ioc.indicator, ioc.type, result["verdict"], result["malicious_count"])
        )
    else:
        # existed but wasn't enriched
        cursor.execute(
            "UPDATE iocs SET verdict = ?, malicious_count = ? WHERE indicator = ?",
            (result["verdict"], result["malicious_count"], ioc.indicator)
        )

    conn.commit()
    conn.close()

    return {
        "indicator": ioc.indicator, "type": ioc.type,
        "verdict": result["verdict"], "malicious_count": result["malicious_count"],
    }

#Helper to parse uploaded files and get ips or domains
def extract_indicators(text: str) -> list[dict]:
    #A list of dict containing the indicator and type
    seen = set()
    indicators = []

    #IP addresses: four groups of 1-3 digits separated by dots
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    for ip in re.findall(ip_pattern, text):
        if ip not in seen:
            seen.add(ip)
            indicators.append({"indicator": ip, "type": "ip"})

    #domains: name.tld
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    for domain in re.findall(domain_pattern, text):
        #Add this as a domain only if we haven't seen it and it isn't actually an IP
        if domain not in seen and not re.fullmatch(ip_pattern, domain):
            seen.add(domain)
            indicators.append({"indicator": domain, "type": "domain"})

    return indicators