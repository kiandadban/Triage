from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

#describes the shape of an incoming IOC
class IOC(BaseModel):
    indicator: str
    type: str

@app.get("/")
def read_root():
    return {"message": "IOC enricher is running"}

@app.post("/iocs")
def add_ioc(ioc: IOC):
    return {"received": ioc}