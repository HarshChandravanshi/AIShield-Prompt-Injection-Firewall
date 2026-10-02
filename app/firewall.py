import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.config import AUDIT_LOG_FILE
from app.detectors import DETECTORS, indirect_injection
from app.models import Decision, Finding, ScanRequest, ScanResponse
from app.normalizer import normalize_text
from app.policy import calculate_risk, decide, sanitize


class PromptInjectionFirewall:
    def scan(self, request: ScanRequest) -> ScanResponse:
        request_id = str(uuid.uuid4())
        normalized = normalize_text(request.content, request.source_type)

        findings: list[Finding] = []
        for detector in DETECTORS:
            findings.extend(detector(normalized))

        findings.extend(indirect_injection(normalized, request.external_content))

        risk = calculate_risk(findings)
        decision = decide(risk, findings)

        sanitized = None
        if decision in {Decision.SANITIZE, Decision.BLOCK}:
            sanitized = sanitize(normalized, findings)

        if not findings:
            summary = "No known prompt-injection indicators were detected."
        else:
            attacks = ", ".join(sorted({f.attack_type for f in findings}))
            summary = f"Detected: {attacks}."

        response = ScanResponse(
            request_id=request_id,
            decision=decision,
            risk_score=risk,
            findings=findings,
            sanitized_content=sanitized,
            normalized_content=normalized,
            source_type=request.source_type,
            summary=summary,
        )
        self._audit(request, response)
        return response

    def _audit(self, request: ScanRequest, response: ScanResponse):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": response.request_id,
            "source_type": request.source_type,
            "external_content": request.external_content,
            "decision": response.decision.value,
            "risk_score": response.risk_score,
            "attack_types": sorted({f.attack_type for f in response.findings}),
        }
        path = Path(AUDIT_LOG_FILE)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
