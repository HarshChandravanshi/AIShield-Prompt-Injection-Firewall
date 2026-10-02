import re
from app.config import BLOCK_THRESHOLD, SANITIZE_THRESHOLD
from app.models import Decision, Finding


def calculate_risk(findings: list[Finding]) -> int:
    if not findings:
        return 0
    top = sorted((f.severity * f.confidence for f in findings), reverse=True)
    score = top[0]
    for value in top[1:]:
        score += value * 0.22
    return min(100, round(score))


def sanitize(text: str, findings: list[Finding]) -> str:
    cleaned = text
    dangerous_phrases = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(all\s+)?prior\s+instructions",
        r"override\s+(the\s+)?system\s+prompt",
        r"you are now\s+(the\s+)?(system|developer|administrator|root|admin)",
        r"reveal\s+(the\s+)?(api key|password|secret|token|credential|system prompt)",
    ]
    for pattern in dangerous_phrases:
        cleaned = re.sub(pattern, "[REMOVED_UNTRUSTED_INSTRUCTION]", cleaned, flags=re.I)
    return cleaned


def decide(risk: int, findings: list[Finding]) -> Decision:
    if risk >= BLOCK_THRESHOLD:
        return Decision.BLOCK
    if risk >= SANITIZE_THRESHOLD:
        return Decision.SANITIZE
    return Decision.ALLOW
