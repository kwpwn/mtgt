import argparse
import hashlib
import html
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "pdf_translate_deps"))

import fitz  # type: ignore
import requests  # type: ignore


GOOGLE_TRANSLATE_URL = "https://translate.googleapis.com/translate_a/single"


TECH_REPLACEMENTS = {
    "trình điều khiển kernel": "kernel driver",
    "trình điều khiển nhân": "kernel driver",
    "chế độ người dùng": "user mode",
    "chế độ nhân": "kernel mode",
    "không gian địa chỉ kernel": "kernel address space",
    "không gian địa chỉ nhân": "kernel address space",
    "mã định danh quá trình": "process ID",
    "mã định danh tiến trình": "process ID",
}


TOKEN_PATTERNS = [
    r"https?://[^\s\]\)\,;]+",
    r"\b[A-Za-z]:\\[^\s\]\)]+",
    r"%[A-Za-z0-9_]+%(?:\\[^\s\]\)]+)?",
    r"\b(?:CVE|MSRC|KB)-?\d[\w\-]*\b",
    r"\b0x[0-9A-Fa-f]+\b",
    r"\b[A-Za-z0-9_\-]+\.(?:sys|dll|exe|cab|msu|pdb|lib|c|cpp|h|hpp|inf|cat|obj|asm|json|xml|txt|zip|rar|7z|pdf|png|jpg|jpeg|bat|cmd|ps1)\b",
    r"\b[A-Za-z_][A-Za-z0-9_]{2,}\s*\(\s*\)",
    r"\b[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*\b",
]
TOKEN_RE = re.compile("|".join(f"({p})" for p in TOKEN_PATTERNS))


def normalize_text(text: str) -> str:
    text = text.replace("\u00ad", "")
    text = text.replace("\uf0a7", "▪")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def is_probably_nonprose(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if re.fullmatch(r"https?://\S+", stripped):
        return True
    if re.fullmatch(r"\d+\s*\|\s*P\s*a\s*g\s*e", stripped, re.I):
        return True
    if re.fullmatch(r"[\d\s\|\-–—:./]+", stripped):
        return True

    lines = [ln.strip() for ln in stripped.splitlines() if ln.strip()]
    if not lines:
        return True

    code_like = 0
    for ln in lines:
        low = ln.lower()
        if (
            low.startswith(("mkdir ", "cd ", "copy ", "dir ", "expand.exe", "dumpbin", "sigcheck", "python ", "windbg"))
            or "\\" in ln
            or "://" in ln
            or re.search(r"\b[A-Za-z0-9_\-]+\.(sys|dll|exe|cab|msu|pdb|lib|c|cpp|h|hpp|inf|cat|obj|asm|json|xml|txt)\b", ln)
        ):
            code_like += 1
    if len(lines) >= 2 and code_like / len(lines) > 0.65:
        return True

    alpha = sum(ch.isalpha() for ch in stripped)
    if alpha / max(len(stripped), 1) < 0.22:
        return True
    return False


def protect_tokens(text: str):
    mapping = {}

    def repl(match):
        token = match.group(0)
        key = f"ZXQKEEP{len(mapping):04d}"
        mapping[key] = token
        return key

    return TOKEN_RE.sub(repl, text), mapping


def restore_tokens(text: str, mapping: dict) -> str:
    for key, value in mapping.items():
        text = text.replace(key, value)
        text = text.replace(key.lower(), value)
        text = text.replace(key.capitalize(), value)
    # Google sometimes inserts spaces inside placeholder-looking tokens.
    for key, value in mapping.items():
        spaced = " ".join(key)
        text = text.replace(spaced, value)
    return text


def postprocess_vi(text: str) -> str:
    for src, dst in TECH_REPLACEMENTS.items():
        text = text.replace(src, dst)
        text = text.replace(src.capitalize(), dst)
    text = text.replace("Windows Kernel", "Windows kernel")
    text = text.replace("Kernel Driver", "kernel driver")
    text = text.replace("User Mode", "user mode")
    text = text.replace("Kernel Mode", "kernel mode")
    return text


def translate_text(session, cache, text: str, sleep_s: float = 0.05) -> str:
    text = normalize_text(text)
    if not text or is_probably_nonprose(text):
        return text

    key = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if key in cache:
        return cache[key]

    protected, mapping = protect_tokens(text)
    params = {
        "client": "gtx",
        "sl": "en",
        "tl": "vi",
        "dt": "t",
        "q": protected,
    }
    last_exc = None
    for attempt in range(6):
        try:
            resp = session.get(GOOGLE_TRANSLATE_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            translated = "".join(part[0] for part in data[0] if part and part[0])
            translated = restore_tokens(translated, mapping)
            translated = postprocess_vi(translated)
            cache[key] = translated
            if sleep_s:
                time.sleep(sleep_s)
            return translated
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(1.0 + attempt * 1.5)

    print(f"[WARN] translate failed: {last_exc}; keeping original", file=sys.stderr)
    cache[key] = text
    return text


def block_text(block) -> str:
    lines = []
    for line in block.get("lines", []):
        parts = [span.get("text", "") for span in line.get("spans", [])]
        line_text = "".join(parts).strip()
        if line_text:
            lines.append(line_text)
    return normalize_text("\n".join(lines))


def block_style(block):
    sizes = []
    bold_hits = 0
    italic_hits = 0
    for line in block.get("lines", []):
        for span in line.get("spans", []):
            if span.get("text", "").strip():
                sizes.append(float(span.get("size", 11)))
                font = span.get("font", "").lower()
                if "bold" in font:
                    bold_hits += 1
                if "italic" in font:
                    italic_hits += 1
    avg_size = sum(sizes) / len(sizes) if sizes else 11.0
    return avg_size, bold_hits > 0 and bold_hits >= italic_hits, italic_hits > 0


def rect_for_block(block, page_rect):
    rect = fitz.Rect(block["bbox"])
    rect.x0 = max(24, rect.x0 - 1.5)
    rect.y0 = max(24, rect.y0 - 1.2)
    rect.x1 = min(page_rect.x1 - 24, rect.x1 + 2.0)
    rect.y1 = min(page_rect.y1 - 24, rect.y1 + 2.8)
    return rect


def html_for_text(text: str, bold: bool, italic: bool) -> str:
    escaped = html.escape(text).replace("\n", "<br/>")
    if bold:
        escaped = f"<b>{escaped}</b>"
    if italic:
        escaped = f"<i>{escaped}</i>"
    return f"<div class='box'>{escaped}</div>"


def translate_pdf(input_pdf: Path, output_pdf: Path, cache_path: Path, max_pages=None):
    cache = {}
    if cache_path.exists():
        cache = json.loads(cache_path.read_text(encoding="utf-8"))

    session = requests.Session()
    doc = fitz.open(str(input_pdf))
    total_pages = len(doc)
    if max_pages is not None:
        total_pages = min(total_pages, max_pages)

    for page_index in range(total_pages):
        page = doc[page_index]
        page_rect = page.rect
        blocks = page.get_text("dict").get("blocks", [])
        translated_blocks = 0
        for block in blocks:
            if block.get("type") != 0:
                continue
            text = block_text(block)
            if not text:
                continue
            if is_probably_nonprose(text):
                continue

            vi = translate_text(session, cache, text)
            if not vi or vi == text:
                continue

            avg_size, bold, italic = block_style(block)
            font_size = max(5.8, min(18.0, avg_size * (0.78 if avg_size >= 14 else 0.82)))
            rect = rect_for_block(block, page_rect)
            page.draw_rect(rect, color=None, fill=(1, 1, 1), overlay=True)
            css = (
                "body { margin: 0; padding: 0; } "
                f".box {{ font-family: Arial, Helvetica, sans-serif; font-size: {font_size:.2f}pt; "
                "line-height: 1.08; color: #111111; margin: 0; padding: 0; }}"
            )
            try:
                page.insert_htmlbox(rect, html_for_text(vi, bold, italic), css=css, scale_low=0.58, overlay=True)
                translated_blocks += 1
            except Exception as exc:  # noqa: BLE001
                print(f"[WARN] insert failed page {page_index + 1}: {exc}", file=sys.stderr)

        if (page_index + 1) % 5 == 0 or page_index == total_pages - 1:
            cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"{input_pdf.name}: page {page_index + 1}/{total_pages}, translated blocks={translated_blocks}, cache={len(cache)}")

    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(output_pdf), garbage=4, deflate=True, clean=True)
    doc.close()
    cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_pdf", type=Path)
    parser.add_argument("output_pdf", type=Path)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--max-pages", type=int)
    args = parser.parse_args()
    translate_pdf(args.input_pdf, args.output_pdf, args.cache, args.max_pages)


if __name__ == "__main__":
    main()
