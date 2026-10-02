from fastapi import FastAPI
from app.firewall import PromptInjectionFirewall
from app.models import ScanRequest, ScanResponse

app = FastAPI(
    title="AIShield Prompt Injection Firewall",
    version="1.0.0",
    description="Agentic cybersecurity prototype for detecting and neutralizing prompt injection."
)

firewall = PromptInjectionFirewall()

@app.get("/health")
def health():
    return {"status": "ok", "service": "AIShield"}

@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    return firewall.scan(request)
