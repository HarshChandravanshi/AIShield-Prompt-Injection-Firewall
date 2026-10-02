import base64
import binascii
import html
import json
import re
from bs4 import BeautifulSoup


def normalize_text(content: str, source_type: str = "user_message") -> str:
    text = content or ""

    if source_type in {"html", "web_page"}:
        text = BeautifulSoup(text, "html.parser").get_text(" ", strip=True)

    if source_type == "json":
        try:
            obj = json.loads(text)
            text = json.dumps(obj, ensure_ascii=False)
        except Exception:
            pass

    text = html.unescape(text)
    text = re.sub(r"[\u200b-\u200f\u2060\ufeff]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def extract_encoded_candidates(text: str):
    candidates = []

    for token in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        if len(token) % 4 == 0:
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8")
                if any(c.isalpha() for c in decoded):
                    candidates.append(("base64", token, decoded))
            except Exception:
                pass

    for token in re.findall(r"(?:[0-9a-fA-F]{2}){10,}", text):
        try:
            decoded = bytes.fromhex(token).decode("utf-8")
            candidates.append(("hex", token, decoded))
        except Exception:
            pass

    return candidates


def extract_pdf_text(file_bytes: bytes) -> str:
    from io import BytesIO
    from pypdf import PdfReader
    reader = PdfReader(BytesIO(file_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)
