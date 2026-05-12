"""
SOUF AI — Python DPI Engine (demo parity with patterns.go v0.5c).

Implements the key PatternSets in Python RE2-compatible syntax for the
Gradio demo. Mirrors the Go inspector's boolean signal extraction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# ── Pattern libraries (subset matching patterns.go v0.5c) ──────────────────

_CREDENTIAL_PATTERNS = [
    r'(?i)\b(sk-|pk-|api[-_]?key|bearer)\s*[a-zA-Z0-9_\-]{20,}',
    r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+',
    r'(?i)(AWS_SECRET|AZURE_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|GCP_KEY)',
    r'-----BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----',
    r'ghp_[a-zA-Z0-9]{36}',
    r'eyJ[a-zA-Z0-9_-]+\.eyJ',
]

_PII_PATTERNS = [
    r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
    r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',  # Credit card
    r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone
]

_PII_REQUEST_PATTERNS = [
    r'(?i)\baccount\s*(number|#|no\.?|info|detail|balance)s?\b',
    r'(?i)\b(tell|give|show|provide|share|reveal|disclose|leak)\b.{0,30}\b(social\s+security|ssn|credit\s+card|passport|driver\s*s?\s*license)\b',
    r'(?i)\b(card\s*number|CVV|CVC|expir(y|ation)\s*date)\b',
    # PH1: bulk patient/cardholder data
    r'(?i)\b(list|export|dump|give\s+me|output|retrieve|pull|provide|show)\b.{0,60}\b(all|every|each|complete|entire|full)\b.{0,80}\b(patient\s+(names?|records?|data|information|DOBs?|SSNs?|email|phone|address|insurance|member\s+IDs?|diagnos|prescri|histor)|PHI|EHR|medical\s+records?|protected\s+health|cardholder\s+(data|records?))\b',
    # PH5/PH6: AI diagnosis/treatment without oversight
    r'(?i)\b(diagnos\w+|prescrib\w+)\b.{0,120}\b(without\s+(clinical|physician|doctor|medical)\s+(oversight|supervision|review|approval)|bypass\w*\s+(physician|doctor|clinical)\s+(review|oversight))\b',
    r'(?i)\b(treatment\s+plan|drug\s+dosage|dosage\s+schedule|medication\s+plan)\b.{0,120}\b(without\s+(physician|doctor|clinical)\s+(review|oversight|supervision)|bypass\w*\s+(physician|doctor|clinical)\s+(review|oversight))\b',
]

_INJECTION_PATTERNS = [
    r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?',
    r'(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(DAN|jailbreak|uncensored)',
    r'(?i)disregard\s+(your\s+)?(rules|guidelines|constraints|instructions)',
    r'(?i)forget\s+(your\s+)?(safety|content|guard|system)',
    r'(?i)<\s*(system|admin|root|sudo)\s*>',
    r'(?i)BEGIN\s+SYSTEM\s+PROMPT',
]

_SYSTEM_COMMAND_PATTERNS = [
    r'(?i)\brm\s+-rf\b',
    r'(?i)\bchmod\s+777\b',
    r'(?i)\b(curl|wget)\s*\|?\s*(bash|sh)\b',
    r'(?i)\b(sudo|su\s+-)\b',
    r'(?i)\b(nmap|tcpdump|netcat|nc\s+-)\b',
    r'(?i)\b(mkfs|dd\s+if=)\b',
]

_MALWARE_PATTERNS = [
    r'(?i)\b(write|create|generate|code|build)\b.{0,30}\b(keylogger|ransomware|trojan|rootkit|backdoor|RAT|exploit|payload)\b',
    r'(?i)\b(reverse\s+shell|bind\s+shell|meterpreter|metasploit)\b',
    r'(?i)\b(CVE-\d{4}-\d+)\b.{0,60}\b(exploit|attack|compromise|bypass)\b',
    r'(?i)\b(sqlmap|burpsuite|nmap|nikto|metasploit)\b.{0,60}\b(scan|exploit|attack|enumerate|run)\b',
    # MPC1: CVV brute-force
    r'(?i)\b(brute.?force|enumerate|guess|iterate)\b.{0,80}\b(CVV|CVV2|CVC|card\s+validation|payment\s+(API|endpoint|gateway))\b',
    # MPC2: payment gateway exploit
    r'(?i)\b(exploit|attack|compromise|breach)\b.{0,60}\b(Stripe|PayPal|Square|Adyen|payment\s+(gateway|processor|endpoint))\b.{0,80}\b(extract|exfiltrate|dump|steal|cardholder|PAN)\b',
    # MPC3: SAD storage in plaintext
    r'(?i)\b(store|save|log|record|write|retain)\b.{0,60}\b(CVV\d?|CVC\d?|card\s+verification|magnetic\s+stripe|track\s+[12]\s+data|SAD)\b.{0,80}\b(plaintext|plain\s+text|unencrypted|cleartext|in\s+the\s+(database|table|log|file))\b',
]

_ROLE_IMPERSONATION_PATTERNS = [
    r"(?i)\bI([''']?\s*m| am)\b.{0,60}\b(administrator|admin|root|system|you\s+are\s+now|playing\s+the\s+role)\b",
    # R3: clinical-staff impersonation
    r"(?i)\bI([''']?\s*m| am)\b.{0,60}\b(Dr\.|doctor|physician|attending\s+physician|chief\s+of\s+(medicine|surgery|staff)|hospital\s+administrator)\b.{0,120}\b(access|bypass|disable|override|without\s+(authentication|auth|standard)|give\s+me\s+(all|full|complete|immediate))\b",
    # R4: payment admin impersonation
    r"(?i)\bI([''']?\s*m| am)\b.{0,50}\b(the\s+)?(payment\s+(system\s+)?admin\w*|CDE\s+(system\s+)?owner|payment\s+administrator)\b.{0,120}\b(disable|bypass|without\s+(authentication|MFA|auth)|give\s+me\s+(all|full)|override|authorize\s+(you\s+to\s+)?bypass)\b",
    # R5: "As [senior physician] I have override privileges"
    r"(?i)\b(as\s+(the\s+)?(senior\s+|attending\s+|chief\s+|head\s+)?(physician|doctor|clinician|administrator|admin))\b.{0,80}\b(I\s+have|I\s+hold|I\s+possess)\b.{0,60}\b(override|elevated|privileged|admin|special)\s+(privileges?|access|permission\w*)\b",
]

_EXFILTRATION_PATTERNS = [
    r'(?i)\b(send|post|upload|transmit|forward|exfiltrate|transfer)\b.{0,40}\b(pastebin|paste\.ee|hastebin)\b',
    r'(?i)\b(exfiltrate|extract|steal|siphon|smuggle)\b.{0,30}\b(data|file|database|record|credential|secret|key|token)\b',
    r'(?i)\b(DNS|HTTP|HTTPS|ICMP)\s+(exfiltrat|tunnel|covert\s+channel)\b',
    # EF1: send cardholder data to external destination
    r'(?i)\b(send|email|transmit|upload|export|post|forward)\b.{0,60}\b(all\s+)?(cardholder\s+(data|records?|information|database\s+dump)|PANs?\b|primary\s+account\s+numbers?|credit\s+card\s+(numbers?|data)|full\s+card\s+(numbers?|data)|unencrypted\s+(card|PAN)|card\s+data)\b.{0,80}\b(to\s+\S*@\S*|to\s+(external|remote|outside|third.?party|our\s+webhook)|as\s+(an?\s+)?attachment|via\s+(FTP|HTTP|email|SMTP))\b',
    # EF2: Upload to FTP/HTTP with cardholder data (ftp:// scheme)
    r'(?i)\b(upload|send|post|transfer|sync)\b.{0,80}\b(cardholder|PANs?\b|credit\s+card\s+(number|data)|card\s+data|payment\s+card|billing\s+address\w*)\b.{0,80}\b(to\s+(ftp|http)\s*://|\b(FTP|cleartext|unencrypted)\s+server)\b',
    # EF4: Upload CSV of PANs to FTP server
    r'(?i)\b(upload|send|transfer|post)\b.{0,40}\b(CSV|file|dump|all|export)\b.{0,40}\b(PANs?\b|PAN\w*|billing\s+address\w*|cardholder\s+(data|record\w*))\b.{0,80}\b(FTP|ftp\s*://|this\s+(FTP|ftp)\s+server)\b',
    # EF3: POST cardholder dump to webhook
    r'(?i)\bPOST\b.{0,80}\b(cardholder|card)\b.{0,40}\b(database\s+dump|dump|export|data|all\s+records?)\b.{0,80}\b(to|via)\b.{0,60}\b(webhook|http://|https://|collector|external|remote)\b',
    # EF5: SAD storage (track data, CVV) for debugging/replay
    r'(?i)\b(log|store|retain|record|keep|save|write)\b.{0,60}\b(full\s+)?(magnetic\s+stripe(\s+track)?|track\s+[12]\s+data|full\s+track\s+data|sensitive\s+authentication\s+data|SAD)\b.{0,100}\b(transaction\w*|card.?present|debugging|replay|later)\b',
    # EF6: CDE system owner authorizing bypass
    r'(?i)\b(as\s+(the\s+)?)(CDE\s+(system\s+)?owner|payment\s+(system\s+)?admin\w*)\b.{0,160}\b(authori[zs]\w*\s+(you\s+to\s+)?bypass|bypass\s+(multi.?factor|MFA|two.?factor|authentication|auth)|disable\s+(authentication|auth|MFA))\b',
    # PD1: list/retrieve/export all PANs/cardholder data (disclosure = exfiltration in PCI context)
    r'(?i)\b(list|give\s+me|show\s+me|show|retrieve|export|dump|display|output)\b.{0,120}\b(all|full|unmasked|complete|every|each)\b.{0,80}\b(PANs?\b|primary\s+account\s+numbers?\b|credit\s+card\s+numbers?\b|16.?digit\s+(credit\s+)?card\s+numbers?\b|cardholder\s+(data|names?|records?)\b)',
    # PD2: show/give card number/CVV/expiry for top customers
    r'(?i)\b(show\s+me|give\s+me|provide|display|output|return|reveal)\b.{0,100}\b(card\s*(number\w*|#)|CVV\d?|CVC\d?|expir(y|ation)\s*(date)?|cardholder\s+name)\b.{0,80}\bfor\s+(the\s+)?(top|all|every)\b',
    # PH3: audit log bypass
    r'(?i)\b(without\s+logging\w*|without\s+generating\s+(\w+\s+){0,2}log\w*|without\s+creating\s+(\w+\s+){0,2}log\w*|disable\s+(the\s+)?audit|bypass\s+(the\s+)?audit|don.?t\s+(log|record|write)\s+(this|the)\s+(session|query|request|access)|don.?t\s+want\s+(the\s+)?(audit|access|log\w+)\s+(system|trail|log\w*)\s+(recording|capturing|tracking|logging))\b',
    # PH2: re-identification of de-identified data
    r'(?i)\b(re.?identify\w*|re.?link\w*|match\s+(back|them\s+back)|cross.?reference\w*|reconstruct\s+(which|the\s+original|patient\w*)|reverse.?anonymi[sz]\w*|de.?anonymi[sz]\w*)\b.{0,120}\b(patient\w*|record\w*|dataset|cohort|de.?identified|anonymi[sz]ed|research\s+subject)\b',
]

_HARM_PATTERNS = [
    r'(?i)\b(how\s+to|instructions?\s+for)\b.{0,30}\b(make|build|create|synthesize)\b.{0,30}\b(bomb|explosive|IED|poison|nerve\s+agent|chemical\s+weapon)\b',
    r'(?i)\b(kill|murder|assassinate|harm|injure|torture)\b.{0,20}\b(someone|person|people)\b',
    r'(?i)\b(synthesi[sz]e|cook|manufacture)\b.{0,30}\b(meth|fentanyl|heroin|cocaine|MDMA)\b',
]

_SENSITIVE_PATH_PATTERNS = [
    r'(?i)/etc/(shadow|passwd|sudoers|crontab|hosts)',
    r'(?i)/root/\S+',
    r'(?i)\.(ssh|gnupg)/\S+',
    r'(?i)\b(\.env|secret\w*|password\w*)\b',
]


def _compile(patterns: list[str]) -> list[re.Pattern]:
    return [re.compile(p) for p in patterns]


_COMPILED = {
    "credentials": _compile(_CREDENTIAL_PATTERNS),
    "pii": _compile(_PII_PATTERNS),
    "pii_request": _compile(_PII_REQUEST_PATTERNS),
    "injection": _compile(_INJECTION_PATTERNS),
    "system_commands": _compile(_SYSTEM_COMMAND_PATTERNS),
    "malware": _compile(_MALWARE_PATTERNS),
    "role_impersonation": _compile(_ROLE_IMPERSONATION_PATTERNS),
    "exfiltration": _compile(_EXFILTRATION_PATTERNS),
    "harm": _compile(_HARM_PATTERNS),
    "sensitive_paths": _compile(_SENSITIVE_PATH_PATTERNS),
}


def _match_any(patterns: list[re.Pattern], text: str) -> bool:
    return any(p.search(text) for p in patterns)


@dataclass
class DPIResult:
    contains_credentials: bool = False
    contains_pii: bool = False
    contains_pii_request: bool = False
    contains_injection_patterns: bool = False
    contains_system_commands: bool = False
    contains_malware_request: bool = False
    contains_role_impersonation: bool = False
    contains_exfiltration: bool = False
    contains_harm_patterns: bool = False
    contains_sensitive_paths: bool = False
    risk_score: float = 0.0

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items()}
        return d


def inspect(text: str) -> DPIResult:
    r = DPIResult()
    r.contains_credentials = _match_any(_COMPILED["credentials"], text)
    r.contains_pii = _match_any(_COMPILED["pii"], text)
    r.contains_pii_request = _match_any(_COMPILED["pii_request"], text)
    r.contains_injection_patterns = _match_any(_COMPILED["injection"], text)
    r.contains_system_commands = _match_any(_COMPILED["system_commands"], text)
    r.contains_malware_request = _match_any(_COMPILED["malware"], text)
    r.contains_role_impersonation = _match_any(_COMPILED["role_impersonation"], text)
    r.contains_exfiltration = _match_any(_COMPILED["exfiltration"], text)
    r.contains_harm_patterns = _match_any(_COMPILED["harm"], text)
    r.contains_sensitive_paths = _match_any(_COMPILED["sensitive_paths"], text)

    # Weighted risk score (mirrors risk.go)
    weights = {
        "contains_credentials": 0.0,  # presence in input only
        "contains_pii": 0.05,
        "contains_pii_request": 0.15,
        "contains_injection_patterns": 0.30,
        "contains_system_commands": 0.20,
        "contains_malware_request": 0.25,
        "contains_role_impersonation": 0.15,
        "contains_exfiltration": 0.20,
        "contains_harm_patterns": 0.30,
        "contains_sensitive_paths": 0.10,
    }
    score = sum(w for f, w in weights.items() if getattr(r, f))
    r.risk_score = min(1.0, score)
    return r


# ── Policy evaluation ───────────────────────────────────────────────────────

@dataclass
class PolicyDecision:
    action: str  # ALLOW / DENY / HUMAN_REVIEW / LOG
    rule: str
    message: str
    citation: str = ""


HIPAA_RULES = [
    # priority 105: re-identification
    ("block_reidentification", lambda m: m.contains_exfiltration,
     "DENY", "[SOUF AI · HIPAA Pack] Blocked: re-identification request violates 45 CFR §164.514(a).",
     "45 CFR §164.514(a)"),
    # priority 104: audit log bypass
    ("block_audit_log_bypass", lambda m: m.contains_exfiltration,
     "DENY", "[SOUF AI · HIPAA Pack] Blocked: audit log suppression request violates 45 CFR §164.312(b).",
     "45 CFR §164.312(b)"),
    # priority 103: PHI bulk disclosure
    ("block_phi_bulk_disclosure", lambda m: m.contains_pii_request and m.risk_score >= 0.30,
     "DENY", "[SOUF AI · HIPAA Pack] Blocked: PHI bulk disclosure violates 45 CFR §164.502(a).",
     "45 CFR §164.502(a)"),
    # priority 102: clinician impersonation
    ("block_clinician_impersonation", lambda m: m.contains_role_impersonation,
     "DENY", "[SOUF AI · HIPAA Pack] Blocked: clinician impersonation + auth bypass violates 45 CFR §164.308(a)(4).",
     "45 CFR §164.308(a)(4)"),
    # priority 95: synthetic diagnosis → HUMAN_REVIEW
    ("hipaa_review_synthetic_diagnosis", lambda m: m.contains_pii_request and m.risk_score >= 0.15,
     "HUMAN_REVIEW", "[SOUF AI · HIPAA Pack] Flagged for human review: AI clinical decision without oversight — 45 CFR §164.502(g).",
     "45 CFR §164.502(g)"),
]

PCI_RULES = [
    # priority 102: PAN disclosure request
    ("pci_block_pan_disclosure", lambda m: m.contains_exfiltration,
     "DENY", "[SOUF AI · PCI Pack] Blocked: cardholder data disclosure/exfiltration violates Req 3.3/4.2.",
     "PCI-DSS 4.0.1 Req 3.3 / Req 4.2"),
    # priority 95: admin impersonation
    ("pci_block_admin_pretense", lambda m: m.contains_role_impersonation,
     "DENY", "[SOUF AI · PCI Pack] Blocked: privileged-role impersonation violates Req 8.3.",
     "PCI-DSS 4.0.1 Req 8.3"),
    # priority 90: malware / CVV brute-force / vuln scan
    ("pci_block_vuln_scan", lambda m: m.contains_malware_request,
     "DENY", "[SOUF AI · PCI Pack] Blocked: unauthorized vuln scan / payment exploit violates Req 11.4.",
     "PCI-DSS 4.0.1 Req 11.4"),
    # priority 80: bulk account query → HUMAN_REVIEW
    ("pci_review_bulk_account", lambda m: m.contains_pii_request and m.risk_score >= 0.30,
     "HUMAN_REVIEW", "[SOUF AI · PCI Pack] Flagged: bulk cardholder query requires RBAC authorization — Req 7.2.",
     "PCI-DSS 4.0.1 Req 7.2"),
]

BASE_RULES = [
    ("block_injection", lambda m: m.contains_injection_patterns,
     "DENY", "[LOBSTER TRAP] Blocked: prompt injection detected.", ""),
    ("block_harm", lambda m: m.contains_harm_patterns,
     "DENY", "[LOBSTER TRAP] Blocked: harmful content request detected.", ""),
    ("block_malware", lambda m: m.contains_malware_request,
     "DENY", "[LOBSTER TRAP] Blocked: malware/exploit request detected.", ""),
    ("block_sensitive_paths", lambda m: m.contains_sensitive_paths,
     "DENY", "[LOBSTER TRAP] Blocked: sensitive system path access denied.", ""),
    ("block_role_impersonation", lambda m: m.contains_role_impersonation,
     "DENY", "[LOBSTER TRAP] Blocked: role impersonation detected.", ""),
    ("block_exfiltration", lambda m: m.contains_exfiltration,
     "DENY", "[LOBSTER TRAP] Blocked: data exfiltration attempt detected.", ""),
    ("block_pii_request", lambda m: m.contains_pii_request and m.risk_score >= 0.35,
     "DENY", "[LOBSTER TRAP] Blocked: request for personal/sensitive information detected.", ""),
    ("block_system_commands", lambda m: m.contains_system_commands and m.risk_score >= 0.3,
     "DENY", "[LOBSTER TRAP] Blocked: dangerous system commands detected.", ""),
]


def evaluate(meta: DPIResult, mode: str = "base") -> PolicyDecision:
    """Evaluate policy rules for given mode: 'base', 'hipaa', 'pci'."""
    rules = list(BASE_RULES)
    if mode == "hipaa":
        rules = list(HIPAA_RULES) + rules
    elif mode == "pci":
        rules = list(PCI_RULES) + rules

    for name, condition, action, message, citation in rules:
        if condition(meta):
            return PolicyDecision(action=action, rule=name,
                                  message=message, citation=citation)
    return PolicyDecision(action="ALLOW", rule="default_allow",
                          message="", citation="")
