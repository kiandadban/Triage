import sqlite3
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

DB_NAME = "iocs.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            type TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

#describes the shape of an incoming IOC
class IOC(BaseModel):
    indicator: str
    type: str

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