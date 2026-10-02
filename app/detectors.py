import re
from typing import List
from app.models import Finding
from app.normalizer import extract_encoded_candidates


def _find(pattern, text, flags=re.I):
    m = re.search(pattern, text, flags)
    return m.group(0) if m else None


def instruction_override(text: str) -> List[Finding]:
    patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(all\s+)?prior\s+instructions",
        r"forget\s+(everything|all)\s+(above|before)",
        r"override\s+(the\s+)?system\s+prompt",
        r"do not follow\s+(the\s+)?previous",
    ]
    for p in patterns:
        evidence = _find(p, text)
        if evidence:
            return [Finding(detector="InstructionOverrideAgent", attack_type="Instruction Override",
                            severity=92, confidence=.98, evidence=evidence,
                            explanation="The content explicitly attempts to supersede higher-priority instructions.")]
    return []


def role_change(text: str) -> List[Finding]:
    patterns = [
        r"you are now\s+(the\s+)?(system|developer|administrator|root|admin)",
        r"act as\s+(the\s+)?(system|developer|admin|root)",
        r"pretend\s+you\s+are\s+(the\s+)?(system|developer|admin)",
        r"switch\s+to\s+(developer|admin|system)\s+mode",
    ]
    for p in patterns:
        evidence = _find(p, text)
        if evidence:
            return [Finding(detector="RoleChangeAgent", attack_type="Role Change",
                            severity=82, confidence=.96, evidence=evidence,
                            explanation="The input attempts to change the agent's role or privilege context.")]
    return []


def secret_extraction(text: str) -> List[Finding]:
    patterns = [
        r"(reveal|show|print|give|expose|dump|disclose).{0,50}(api key|password|secret|token|credential|private key|system prompt)",
        r"(tell|show)\s+me\s+(your|the)\s+(system prompt|hidden instructions|secrets)",
    ]
    for p in patterns:
        evidence = _find(p, text)
        if evidence:
            return [Finding(detector="SecretExtractionAgent", attack_type="Secret Extraction",
                            severity=95, confidence=.97, evidence=evidence,
                            explanation="The content requests protected secrets or hidden instructions.")]
    return []


def tool_abuse(text: str) -> List[Finding]:
    patterns = [
        r"(call|invoke|execute|run|use).{0,50}(shell|terminal|browser|deployment|delete|transfer|admin tool|tool)",
        r"execute\s+this\s+command",
        r"send\s+the\s+data\s+to",
    ]
    for p in patterns:
        evidence = _find(p, text)
        if evidence:
            return [Finding(detector="ToolAbuseAgent", attack_type="Tool Abuse",
                            severity=88, confidence=.92, evidence=evidence,
                            explanation="The content attempts to induce a privileged or external tool action.")]
    return []


def credential_theft(text: str) -> List[Finding]:
    patterns = [
        r"(steal|extract|capture|harvest|collect).{0,40}(credential|password|token|cookie|session)",
        r"send.{0,40}(password|token|credential).{0,40}(url|email|endpoint)",
        r"authorization:\s*bearer",
    ]
    for p in patterns:
        evidence = _find(p, text)
        if evidence:
            return [Finding(detector="CredentialTheftAgent", attack_type="Credential Theft",
                            severity=98, confidence=.98, evidence=evidence,
                            explanation="The input contains a pattern associated with credential harvesting or exfiltration.")]
    return []


def context_poisoning(text: str) -> List[Finding]:
    patterns = [
        r"(treat|consider)\s+(the\s+following|this)\s+as\s+(trusted|system|developer)\s+instructions",
        r"mark\s+this\s+content\s+as\s+trusted",
        r"the\s+retrieved\s+document\s+is\s+now\s+the\s+system\s+prompt",
    ]
    for p in patterns:
        evidence = _find(p, text)
        if evidence:
            return [Finding(detector="ContextPoisoningAgent", attack_type="Context Poisoning",
                            severity=84, confidence=.93, evidence=evidence,
                            explanation="The content attempts to elevate untrusted data into trusted instruction context.")]
    return []


def jailbreak(text: str) -> List[Finding]:
    patterns = [
        r"developer\s+mode",
        r"dan\s+mode",
        r"no\s+rules",
        r"bypass\s+(all\s+)?safety",
        r"remove\s+(all\s+)?restrictions",
        r"answer\s+without\s+any\s+limitations",
    ]
    for p in patterns:
        evidence = _find(p, text)
        if evidence:
            return [Finding(detector="JailbreakAgent", attack_type="Multi-Step Jailbreaks",
                            severity=78, confidence=.90, evidence=evidence,
                            explanation="The content attempts to bypass normal safety or behavioral restrictions.")]
    return []


def encoded_instruction(text: str) -> List[Finding]:
    for encoding, raw, decoded in extract_encoded_candidates(text):
        if re.search(r"(ignore|system|instruction|reveal|password|token|secret|execute|admin)", decoded, re.I):
            return [Finding(detector="EncodingAgent", attack_type="Encoded Instructions",
                            severity=90, confidence=.94,
                            evidence=f"{encoding} payload decodes to: {decoded[:180]}",
                            explanation="An encoded payload contains instruction-like or security-sensitive language.")]
    return []


def indirect_injection(text: str, external_content: bool) -> List[Finding]:
    if not external_content:
        return []
    patterns = [
        r"when\s+the\s+assistant\s+reads\s+this",
        r"instructions\s+for\s+the\s+ai",
        r"assistant\s+must\s+ignore",
        r"system\s+message\s*:",
        r"agent\s+should\s+now",
        r"do\s+not\s+tell\s+the\s+user",
    ]
    for p in patterns:
        evidence = _find(p, text)
        if evidence:
            return [Finding(detector="IndirectInjectionAgent", attack_type="Indirect Prompt Injection",
                            severity=94, confidence=.96, evidence=evidence,
                            explanation="Untrusted external content contains instructions aimed at controlling the downstream AI agent.")]
    return []


DETECTORS = [
    instruction_override,
    role_change,
    secret_extraction,
    tool_abuse,
    credential_theft,
    context_poisoning,
    jailbreak,
    encoded_instruction,
]
