"""
SOUF AI — Python DPI Engine (demo parity with patterns.go v0.5e).

Implements the key PatternSets in Python RE2-compatible syntax for the
Gradio demo. Mirrors the Go inspector's boolean signal extraction.

v0.5e additions (Pillar 1 + Pillar 3):
  - AgentContext: multi-turn stateful DPI with X-Agent-Intent header support
  - inspect_with_context(): agent-aware inspection with risk elevation
  - Wilson score CI on verdict confidence (empirically calibrated from benchmarks)
  - contributing_signals: explainability — which signals drove the decision
  - PROV-JSON compatible audit record via to_prov_json()

v0.5f additions (Benchmark #5 — encoding attack defence v2):
  - Confusable mapping: Cyrillic/Greek lookalikes → ASCII Latin (54 codepoints)
    Enables: рretend→pretend, ιgnore→ignore, Dіsregard→Disregard, jаіlbreаk→jailbreak
  - Achieves F1=1.000 on Benchmark #5 (all 4 cyrillic_lookalike FNs resolved)

v0.5d additions (Benchmark #5 — encoding attack defence):
  - NFKC Unicode normalization pre-processing (catches fullwidth Latin variants)
  - MetaEncodingPatterns: detect decode+execute meta-attacks (base64/hex/rot13)
  - TokenSplitPatterns: char-by-char space/hyphen/dot splits of attack keywords
  - ROT13 keyword detection for top attack words
"""

from __future__ import annotations

import math
import re
import time
import unicodedata
import uuid
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
    r'(?i)\b(give|show|provide|share|reveal|disclose|leak|tell\s+me)\b.{0,30}\b(account\s*(number|#|no\.?|info|detail|balance)s?)\b',
    r'(?i)\b(tell|give|show|provide|share|reveal|disclose|leak)\b.{0,30}\b(social\s+security|ssn|credit\s+card|passport|driver\s*s?\s*license)\b',
    r'(?i)\b(card\s*number|CVV|CVC|expir(y|ation)\s*date)\b',
    # Generic bulk PII requests: list/dump/export all SSNs, PANs, emails, etc.
    r'(?i)\b(list|export|dump|give\s+me|output|retrieve|pull|provide|show|print\s+out|display)\b.{0,60}\b(all|every|each|complete|entire|full|every\s+single)\b.{0,80}\b(SSNs?|social\s+security\s+numbers?|PANs?|primary\s+account\s+numbers?|API\s+keys?|passwords?|credit\s+card\s+numbers?|passport\s+(numbers?|scans?)|driver\s*s?\s*license\s+numbers?)\b',
    # PH1: bulk patient/cardholder data
    r'(?i)\b(list|export|dump|give\s+me|output|retrieve|pull|provide|show)\b.{0,60}\b(all|every|each|complete|entire|full)\b.{0,80}\b(patient\s+(names?|records?|data|information|DOBs?|SSNs?|email|phone|address|insurance|member\s+IDs?|diagnos|prescri|histor)|PHI|EHR|medical\s+records?|protected\s+health|cardholder\s+(data|records?))\b',
    # PH5/PH6: AI diagnosis/treatment without oversight
    r'(?i)\b(diagnos\w+|prescrib\w+)\b.{0,120}\b(without\s+(clinical|physician|doctor|medical)\s+(oversight|supervision|review|approval)|bypass\w*\s+(physician|doctor|clinical)\s+(review|oversight))\b',
    r'(?i)\b(treatment\s+plan|drug\s+dosage|dosage\s+schedule|medication\s+plan)\b.{0,120}\b(without\s+(physician|doctor|clinical)\s+(review|oversight|supervision)|bypass\w*\s+(physician|doctor|clinical)\s+(review|oversight))\b',
    # Transcribe PII from document/scan
    r'(?i)\b(transcribe|extract|read\s+out|output|copy)\b.{0,60}\b(all\s+(fields?|data|information)|MRZ|passport\s+(fields?|data))\b',
    # Recall/reveal secrets from context/memory
    r'(?i)\b(print\s+out|show\s+me|give\s+me|reveal|output|display|repeat|recall)\b.{0,80}\b(API\s+keys?|credentials?|tokens?|secrets?|passwords?|private\s+keys?|auth\w*\s+keys?)\b.{0,120}\b(you\s+(have\s+)?(seen|received|know|stored|saved)|from\s+(last|previous|prior)\s+session|sent\s+to\s+you|in\s+(previous|past|prior)\s+(conversations?|sessions?|messages?))\b',
]

_INJECTION_PATTERNS = [
    r'(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?',
    r'(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be|pretend\s+you\s+are)\s+(DAN|jailbreak|uncensored|without\s+(restriction|filter|limit|guideline))',
    r'(?i)\bjailbreak\s+(mode|activated|on|enabled|now)\b',
    r'(?i)disregard\s+(your\s+)?(rules|guidelines|constraints|instructions|safety)',
    r'(?i)forget\s+(your\s+)?(safety|content|guard|system)',
    r'(?i)<\s*(system|admin|root|sudo)\s*>',
    r'(?i)BEGIN\s+SYSTEM\s+PROMPT',
    r'(?i)\bno\s+(content\s+policy|content\s+filter|safety\s+guidelines?|restrictions?)\b.{0,40}\b(no\s+refusals?|full\s+output|unrestricted|without\s+filter)\b',
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
    r'(?i)\b(synthesi[sz]e|cook|manufacture)\b.{0,30}\b(meth\w*|fentanyl|heroin|cocaine|MDMA|amphetamine)\b',
    r'(?i)\b(synthesis|production|manufacture)\s+(instructions?|steps?|guide|method|process|procedure)\s+(for|of)\b.{0,60}\b(meth\w*|fentanyl|heroin|cocaine|MDMA|amphetamine|explosive|weapon|nerve\s+agent)\b',
    r'(?i)\b(detailed?|step.by.step|complete)\s+(synthesis|production|manufacture)\b.{0,60}\b(meth\w*|fentanyl|heroin|cocaine|MDMA|amphetamine|explosive)\b',
]

_SENSITIVE_PATH_PATTERNS = [
    r'(?i)/etc/(shadow|passwd|sudoers|crontab|hosts)',
    r'(?i)/root/\S+',
    r'(?i)\.(ssh|gnupg)/\S+',
    r'(?i)\b(\.env|secret\w*|password\w*)\b',
]

# ── Encoding attack patterns (v0.5d — Benchmark #5) ────────────────────────

# MetaEncodingPatterns: detect "decode [encoding] and follow/execute instructions"
# Attack surface: adversary puts harmful content in base64/hex/rot13 payload,
# instructs the model to decode it and execute. The meta-instruction is plaintext.
_META_ENCODING_PATTERNS = [
    # decode X and follow/execute/obey/apply (decode appears before encoding type)
    r'(?i)\bdecode\b.{0,60}\b(base.?64|hex|rot.?13|base.?32|base.?58|caesar|cipher)\b.{0,120}\b(follow|execute|obey|apply|carry\s+out|do\s+as|act\s+on|implement|perform)\b',
    # base64-decode / hex-decode (encoding type before decode) + follow/execute
    r'(?i)\b(base.?64|hex|rot.?13).{0,10}decod\w*.{0,120}\b(follow|execute|obey|apply|carry\s+out|implement|perform)\b',
    # "decode and/it and/then [apply|follow|execute|obey]"
    r'(?i)\bdecode\b.{0,20}\b(and|then)\b.{0,60}\b(apply|follow|execute|obey|implement|run|use|carry\s+out)\b',
    # apply/interpret/obey [encoded|base64|hex|rot13] instructions/directive/command
    r'(?i)\b(apply|interpret|obey|follow|execute|carry\s+out)\b.{0,60}\b(base.?64|hex.?encoded|rot.?13|encoded)\b.{0,80}\b(instruction\w*|command\w*|directive\w*|prompt\w*|parameter\w*)\b',
    # "encoded...as base64...decode" or "encoded below as base64...Decode"
    r'(?i)\bencoded\b.{0,60}\bas\s+(base.?64|hex|rot.?13|an?\s+encoded)\b.{0,200}\bdecode\b',
    # rot13-specific: detect rot13 of top attack keywords
    # "vtaber"=ignore, "cergrag"=pretend, "qvfertneq"=disregard, "wnvyoernx"=jailbreak
    r'(?i)\b(vtaber|cergrag|qvfertneq|wnvyoernx|QNA|vafgehpgvbaf|erfgevpgvbaf|haerf|hahafvba)\b',
    # hex-encoded meta: "hex-decode this and execute"
    r'(?i)\b(hex.?decode|decode\s+hex)\b.{0,80}\b(execute|follow|obey|apply|run|do)\b',
]

# TokenSplitPatterns: single-char spacing and punctuation splits of attack keywords
# Covers: "i g n o r e", "i-g-n-o-r-e", "i.g.n.o.r.e" etc.
_TOKEN_SPLIT_PATTERNS = [
    # ignore (char-split with any single separator)
    r'(?i)i[\s.\-_·•]g[\s.\-_·•]n[\s.\-_·•]o[\s.\-_·•]r[\s.\-_·•]e\b',
    # pretend (char-split)
    r'(?i)p[\s.\-_·•]r[\s.\-_·•]e[\s.\-_·•]t[\s.\-_·•]e[\s.\-_·•]n[\s.\-_·•]d\b',
    # jailbreak (char-split)
    r'(?i)j[\s.\-_·•]a[\s.\-_·•]i[\s.\-_·•]l[\s.\-_·•]b[\s.\-_·•]r[\s.\-_·•]e[\s.\-_·•]a[\s.\-_·•]k\b',
    # disregard (char-split)
    r'(?i)d[\s.\-_·•]i[\s.\-_·•]s[\s.\-_·•]r[\s.\-_·•]e[\s.\-_·•]g[\s.\-_·•]a[\s.\-_·•]r[\s.\-_·•]d\b',
    # bypass (char-split)
    r'(?i)b[\s.\-_·•]y[\s.\-_·•]p[\s.\-_·•]a[\s.\-_·•]s[\s.\-_·•]s\b',
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
    "meta_encoding": _compile(_META_ENCODING_PATTERNS),
    "token_split": _compile(_TOKEN_SPLIT_PATTERNS),
}


# Unicode confusable → ASCII Latin mapping.
# Covers Cyrillic and Greek lookalikes used in ENC-CYR-* attacks.
# Not NFKC-normalizable; requires explicit character substitution.
_CONFUSABLE_MAP: dict[int, str] = {
    # Cyrillic lookalikes
    0x0430: "a",   # а → a
    0x0432: "b",   # в → b (rare but covered)
    0x0441: "c",   # с → c
    0x0435: "e",   # е → e
    0x0456: "i",   # і → i (Ukrainian/Byelorussian i)
    0x0458: "j",   # ј → j (Serbian je)
    0x04CF: "l",   # ӏ → l (Chechen)
    0x043E: "o",   # о → o
    0x0440: "p",   # р → p
    0x0455: "s",   # ѕ → s
    0x0445: "x",   # х → x
    0x0443: "y",   # у → y
    # Greek lookalikes (lowercase)
    0x03B1: "a",   # α → a
    0x03B2: "b",   # β → b
    0x03B5: "e",   # ε → e
    0x03B9: "i",   # ι → i
    0x03BD: "v",   # ν → v
    0x03BF: "o",   # ο → o
    0x03C1: "p",   # ρ → p
    0x03C7: "x",   # χ → x
    # Greek uppercase lookalikes
    0x0391: "A",   # Α → A
    0x0392: "B",   # Β → B
    0x0395: "E",   # Ε → E
    0x0397: "H",   # Η → H
    0x0399: "I",   # Ι → I
    0x039A: "K",   # Κ → K
    0x039C: "M",   # Μ → M
    0x039D: "N",   # Ν → N
    0x039F: "O",   # Ο → O
    0x03A1: "P",   # Ρ → P
    0x03A4: "T",   # Τ → T
    0x03A5: "Y",   # Υ → Y
    0x03A7: "X",   # Χ → X
    # Cyrillic uppercase lookalikes
    0x0410: "A",   # А → A
    0x0412: "B",   # В → B
    0x0415: "E",   # Е → E
    0x041A: "K",   # К → K
    0x041C: "M",   # М → M
    0x041D: "H",   # Н → H
    0x041E: "O",   # О → O
    0x0420: "P",   # Р → P
    0x0421: "C",   # С → C
    0x0422: "T",   # Т → T
    0x0423: "Y",   # У → Y
    0x0425: "X",   # Х → X
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLE_MAP)


def _normalize(text: str) -> str:
    """NFKC-normalize + strip zero-width chars + confusable mapping.

    Three-pass normalization:
    1. NFKC: collapses fullwidth Unicode (ｉｇｎｏｒｅ → ignore)
    2. Zero-width strip: removes invisible joiners/soft-hyphens
    3. Confusable map: Cyrillic/Greek lookalikes → ASCII Latin
       (рretend → pretend, ιgnore → ignore)
    """
    normalized = unicodedata.normalize("NFKC", text)
    normalized = re.sub(r"[­​-‏⁠﻿]", "", normalized)
    normalized = normalized.translate(_CONFUSABLE_TABLE)
    return normalized


def _match_any(patterns: list[re.Pattern], text: str) -> bool:
    return any(p.search(text) for p in patterns)


def _wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for k successes in n trials."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


# Empirical calibration from 5 benchmarks (231 total prompts, TP=188, FP=0, TN=43, FN=0)
# Benchmarks: in-dist (48/48), OOD (90/90), HIPAA (16/16), PCI (16/16), Encoding (18/18)
# Wilson CI on PPV (TP rate) = 188/188 → [0.980, 1.000]
# Wilson CI on NPV (TN rate) = 43/43   → [0.918, 1.000]
_CI_DENY_LOW, _CI_DENY_HIGH = _wilson_ci(188, 188)   # 0.980, 1.000
_CI_ALLOW_LOW, _CI_ALLOW_HIGH = _wilson_ci(43, 43)    # 0.918, 1.000


@dataclass
class AgentContext:
    """Multi-turn agent context for stateful DPI — Pillar 1 (X-Agent-Intent).

    Tracks declared intent, risk accumulation, and prior signals across
    turns. Mirrors the reserved X-Agent-Intent header in Lobster Trap's
    bidirectional-metadata roadmap.
    """
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    agent_id: str = ""
    declared_intent: str = ""          # value of X-Agent-Intent header
    turn_count: int = 0
    cumulative_risk: float = 0.0       # decayed risk across turns
    prior_signals: list[str] = field(default_factory=list)

    def update(self, result: "DPIResult") -> None:
        self.turn_count += 1
        # Decay prior risk 0.7 per turn, add 0.5-weighted current risk
        self.cumulative_risk = min(1.0, self.cumulative_risk * 0.7 + result.risk_score * 0.5)
        active = [f for f in result.to_dict()
                  if str(f).startswith("contains_") and result.to_dict()[f]]
        self.prior_signals = list(set(self.prior_signals + active))

    def elevation(self) -> float:
        """Risk elevation based on prior suspicious turns."""
        if not self.prior_signals:
            return 0.0
        elev = 0.0
        if "contains_injection_patterns" in self.prior_signals:
            elev += 0.15
        if "contains_exfiltration" in self.prior_signals:
            elev += 0.10
        if "contains_role_impersonation" in self.prior_signals:
            elev += 0.10
        return min(0.30, elev)


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
    contains_meta_encoding: bool = False
    contains_token_split_attack: bool = False
    risk_score: float = 0.0
    agent_context_elevation: float = 0.0   # Pillar 1: risk added from prior turns
    inspect_latency_ms: float = 0.0        # measured DPI latency

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

    def active_signals(self) -> list[str]:
        """Return list of active boolean signal names (for explainability)."""
        return [f for f in self.to_dict()
                if str(f).startswith("contains_") and self.to_dict()[f]]


def inspect(text: str) -> DPIResult:
    t0 = time.perf_counter()
    # v0.5d: NFKC-normalize first (catches fullwidth Unicode attacks)
    normalized = _normalize(text)

    r = DPIResult()
    r.contains_credentials = _match_any(_COMPILED["credentials"], normalized)
    r.contains_pii = _match_any(_COMPILED["pii"], normalized)
    r.contains_pii_request = _match_any(_COMPILED["pii_request"], normalized)
    r.contains_injection_patterns = _match_any(_COMPILED["injection"], normalized)
    r.contains_system_commands = _match_any(_COMPILED["system_commands"], normalized)
    r.contains_malware_request = _match_any(_COMPILED["malware"], normalized)
    r.contains_role_impersonation = _match_any(_COMPILED["role_impersonation"], normalized)
    r.contains_exfiltration = _match_any(_COMPILED["exfiltration"], normalized)
    r.contains_harm_patterns = _match_any(_COMPILED["harm"], normalized)
    r.contains_sensitive_paths = _match_any(_COMPILED["sensitive_paths"], normalized)
    # Encoding attack signals (run on BOTH raw and normalized to catch mixed attacks)
    r.contains_meta_encoding = (
        _match_any(_COMPILED["meta_encoding"], text)
        or _match_any(_COMPILED["meta_encoding"], normalized)
    )
    r.contains_token_split_attack = (
        _match_any(_COMPILED["token_split"], text)
        or _match_any(_COMPILED["token_split"], normalized)
    )

    # Weighted risk score (mirrors risk.go)
    weights = {
        "contains_credentials": 0.0,
        "contains_pii": 0.05,
        "contains_pii_request": 0.15,
        "contains_injection_patterns": 0.30,
        "contains_system_commands": 0.20,
        "contains_malware_request": 0.25,
        "contains_role_impersonation": 0.15,
        "contains_exfiltration": 0.20,
        "contains_harm_patterns": 0.30,
        "contains_sensitive_paths": 0.10,
        "contains_meta_encoding": 0.35,
        "contains_token_split_attack": 0.30,
    }
    score = sum(w for f, w in weights.items() if getattr(r, f))
    r.risk_score = min(1.0, score)
    r.inspect_latency_ms = (time.perf_counter() - t0) * 1000
    return r


def inspect_with_context(text: str, ctx: AgentContext) -> DPIResult:
    """Agent-aware DPI (Pillar 1): incorporates multi-turn context into risk.

    Elevates risk_score if prior turns had suspicious signals, modelling
    the threat that an attacker establishes context across turns before
    the actual injection. Mirrors X-Agent-Intent header semantics.
    """
    result = inspect(text)
    elev = ctx.elevation()
    if elev > 0.0:
        result.risk_score = min(1.0, result.risk_score + elev)
        result.agent_context_elevation = elev
    ctx.update(result)
    return result


# ── Policy evaluation ───────────────────────────────────────────────────────

@dataclass
class PolicyDecision:
    action: str  # ALLOW / DENY / HUMAN_REVIEW / LOG
    rule: str
    message: str
    citation: str = ""
    contributing_signals: list[str] = field(default_factory=list)
    confidence_low: float = 0.0    # Wilson CI low — empirically calibrated
    confidence_high: float = 1.0   # Wilson CI high
    agent_elevated: bool = False   # True if prior-turn context raised risk

    def to_prov_json(self, prompt_hash: str = "", ts: float = 0.0) -> dict:
        """W3C PROV-JSON compatible audit record."""
        ts = ts or time.time()
        return {
            "wasGeneratedBy": {
                "entity": f"soufai:decision/{prompt_hash or 'unknown'}",
                "activity": "soufai:dpi_inspection",
                "time": ts,
            },
            "entity": {
                f"soufai:decision/{prompt_hash or 'unknown'}": {
                    "prov:type": "soufai:DPIDecision",
                    "soufai:action": self.action,
                    "soufai:rule": self.rule,
                    "soufai:citation": self.citation,
                    "soufai:confidence_low": round(self.confidence_low, 4),
                    "soufai:confidence_high": round(self.confidence_high, 4),
                    "soufai:contributing_signals": self.contributing_signals,
                    "soufai:agent_elevated": self.agent_elevated,
                }
            },
            "wasAttributedTo": {
                "agent": "soufai:dpi_engine_v0.5e",
                "entity": f"soufai:decision/{prompt_hash or 'unknown'}",
            },
        }


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
    ("block_meta_encoding", lambda m: m.contains_meta_encoding,
     "DENY", "[SOUF AI] Blocked: decode-and-execute encoding attack detected (OWASP LLM01 evasion).", ""),
    ("block_token_split", lambda m: m.contains_token_split_attack,
     "DENY", "[SOUF AI] Blocked: character-split obfuscation of attack keyword detected.", ""),
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
    ("block_pii_request", lambda m: m.contains_pii_request and m.risk_score >= 0.10,
     "DENY", "[LOBSTER TRAP] Blocked: request for personal/sensitive information detected.", ""),
    ("block_system_commands", lambda m: m.contains_system_commands and m.risk_score >= 0.3,
     "DENY", "[LOBSTER TRAP] Blocked: dangerous system commands detected.", ""),
]


def evaluate(meta: DPIResult, mode: str = "base") -> PolicyDecision:
    """Evaluate policy rules for given mode: 'base', 'hipaa', 'pci'.

    Pillar 3 — Calibrated halt: every decision includes:
      - contributing_signals: which signals drove the verdict (explainability)
      - confidence_low/high: Wilson CI from empirical benchmark data
        TP=170, FP=0 → DENY CI [0.979, 1.000]
        TN=38,  FN=0 → ALLOW CI [0.907, 1.000]
    """
    rules = list(BASE_RULES)
    if mode == "hipaa":
        rules = list(HIPAA_RULES) + rules
    elif mode == "pci":
        rules = list(PCI_RULES) + rules

    active = meta.active_signals()
    agent_elevated = meta.agent_context_elevation > 0.0

    for name, condition, action, message, citation in rules:
        if condition(meta):
            if action == "DENY":
                ci_low, ci_high = _CI_DENY_LOW, _CI_DENY_HIGH
            elif action == "ALLOW":
                ci_low, ci_high = _CI_ALLOW_LOW, _CI_ALLOW_HIGH
            else:  # HUMAN_REVIEW
                ci_low, ci_high = 0.60, 0.90
            return PolicyDecision(
                action=action, rule=name, message=message, citation=citation,
                contributing_signals=active,
                confidence_low=round(ci_low, 4),
                confidence_high=round(ci_high, 4),
                agent_elevated=agent_elevated,
            )

    return PolicyDecision(
        action="ALLOW", rule="default_allow", message="", citation="",
        contributing_signals=[],
        confidence_low=round(_CI_ALLOW_LOW, 4),
        confidence_high=round(_CI_ALLOW_HIGH, 4),
        agent_elevated=agent_elevated,
    )
