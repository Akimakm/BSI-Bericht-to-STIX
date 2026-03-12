from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, Any, Set, Tuple, List, Optional

# ================== CONFIG ==================
INPUT_DIR = Path("preprocessed_bsi")
OUTPUT_DIR = Path("Extracted_entities")

# Qwen3 14B via Ollama
OLLAMA_MODEL = "qwen3:14b"
OLLAMA_TIMEOUT_SECONDS = 300

# Fail-fast behavior:
# - If True: any subsection that yields invalid LLM output stops the whole run.
# - If False: it will raise, but you could catch in main and continue (NOT enabled here).
FAIL_FAST = True
# ============================================

# ---------- Regex (KEEP: deterministic for CVE/IOC/CVSS) ----------
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CVSS_RE = re.compile(r"\b([0-9]\.[0-9])\s*/\s*10\b")

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"\bhttps?://[^\s<>()\"]+\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


# ================== Helpers ==================

def split_subsection(sub: str | None) -> Tuple[str | None, str | None]:
    if not sub:
        return None, None
    parts = sub.split(" ", 1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1]


def normalize_urls(urls_field) -> List[str]:
    if not urls_field:
        return []
    if isinstance(urls_field, list):
        return urls_field
    if isinstance(urls_field, str):
        return [u.strip() for u in urls_field.split(";") if u.strip()]
    return []


def strip_code_fences(s: str) -> str:
    s = (s or "").strip()
    # Remove ```json ... ``` or ``` ... ```
    s = re.sub(r"^\s*```(?:json)?\s*", "", s, flags=re.IGNORECASE)
    s = re.sub(r"\s*```\s*$", "", s, flags=re.IGNORECASE)
    return s.strip()


def iter_balanced_brace_blocks(text: str) -> List[str]:
    blocks: List[str] = []
    i = 0
    while i < len(text):
        start = text.find("{", i)
        if start == -1:
            break

        brace_count = 0
        end: Optional[int] = None
        for j in range(start, len(text)):
            if text[j] == "{":
                brace_count += 1
            elif text[j] == "}":
                brace_count -= 1
                if brace_count == 0:
                    end = j
                    break

        if end is None:
            break

        blocks.append(text[start:end + 1].strip())
        i = end + 1

    return blocks


def extract_first_schema_json(raw: str, required_keys: List[str]) -> str:
    raw = strip_code_fences(raw or "").strip()
    if not raw:
        raise RuntimeError("LLM output is empty after stripping fences.")

    blocks = iter_balanced_brace_blocks(raw)
    if not blocks:
        raise RuntimeError(
            "No JSON-like {...} blocks found in LLM output.\n"
            f"---RAW (first 800 chars)---\n{raw[:800]}"
        )

    # Prefer blocks that contain at least one required key marker (cheap pre-filter)
    required_markers = [f"\"{k}\"" for k in required_keys]

    candidates = []
    for b in blocks:
        if any(m in b for m in required_markers):
            candidates.append(b)

    if not candidates:
        raise RuntimeError(
            "Found {...} blocks but none contain required schema keys.\n"
            f"---FIRST BLOCK (first 300 chars)---\n{blocks[0][:300]}\n"
            f"---RAW (first 800 chars)---\n{raw[:800]}"
        )

    # Now try JSON parsing on candidates until one parses.
    # This avoids selecting junk like "{ and end with }".
    parse_errors = []
    for cand in candidates:
        try:
            json.loads(cand)
            return cand
        except json.JSONDecodeError as e:
            parse_errors.append((str(e), cand[:200]))

    # If none parse, fail with useful info
    msg = "\n".join([f"- {err} | snippet={snip!r}" for err, snip in parse_errors[:3]])
    raise RuntimeError(
        "Candidates contained schema keys but none were valid JSON.\n"
        f"{msg}\n"
        f"---RAW (first 800 chars)---\n{raw[:800]}"
    )


# ================== Extraction ==================

def extract_deterministic_entities(text: str) -> Dict[str, Set[str]]:
    ents: Dict[str, Set[str]] = {
        "cve_ids": set(),
        "cvss_scores": set(),
        "ioc_urls": set(),
        "ioc_domains": set(),
        "ioc_ipv4": set(),
        "ioc_emails": set(),
        "ioc_hashes": set(),
    }

    t = (text or "").strip()
    if not t:
        return ents

    for m in CVE_RE.findall(t):
        ents["cve_ids"].add(m.upper())
    for m in CVSS_RE.findall(t):
        ents["cvss_scores"].add(m)

    for u in URL_RE.findall(t):
        ents["ioc_urls"].add(u)
    for ip in IPV4_RE.findall(t):
        ents["ioc_ipv4"].add(ip)
    for em in EMAIL_RE.findall(t):
        ents["ioc_emails"].add(em)

    url_hosts = set()
    for u in ents["ioc_urls"]:
        try:
            host = re.sub(r"^https?://", "", u, flags=re.IGNORECASE).split("/")[0]
            if host:
                url_hosts.add(host.lower())
        except Exception:
            pass

    for d in DOMAIN_RE.findall(t):
        if d.lower() not in url_hosts:
            ents["ioc_domains"].add(d)

    for h in MD5_RE.findall(t):
        ents["ioc_hashes"].add(h.lower())
    for h in SHA1_RE.findall(t):
        ents["ioc_hashes"].add(h.lower())
    for h in SHA256_RE.findall(t):
        ents["ioc_hashes"].add(h.lower())

    return ents


def extract_entities_with_qwen_de(text_de: str) -> Dict[str, Any]:
    text_de = (text_de or "").strip()
    if not text_de:
        raise ValueError("Qwen extractor: empty German text")

    required_keys = [
        "organizations",
        "products",
        "threat_actors",
        "malware",
        "attack_types",
        "exploitation_status",
        "recommended_measures",
    ]

    prompt = f"""
Du bist ein erfahrener Cybersecurity-Analyst.

AUFGABE:
Extrahiere aus dem TEXT die relevanten Cybersecurity-Informationen und gib NUR EIN JSON-Objekt zurück.

KRITISCH (muss eingehalten werden):
- Gib NUR JSON zurück. Kein Markdown. Keine ```-Blöcke. Keine Erklärungen. Kein "Thinking...".
- Ausgabe muss mit '{{' beginnen und mit '}}' enden.
- Das JSON muss GENAU diese Keys enthalten (keine zusätzlichen Keys):

{{
  "organizations": [],
  "products": [],
  "threat_actors": [],
  "malware": [],
  "attack_types": [],
  "exploitation_status": "",
  "recommended_measures": []
}}

REGELN:
- organizations/products/threat_actors/malware/attack_types/recommended_measures sind Arrays von Strings.
- exploitation_status ist ein einzelner String.
- Werte (attack_types, exploitation_status, recommended_measures) sollen AUF DEUTSCH sein.
  (Eigennamen wie Produkt-/Firmennamen bleiben natürlich unverändert.)
- attack_types: beschreibe den/die Angriffstyp(en) kurz in Deutsch (z.B. "Remote-Code-Ausführung", "Informationsabfluss", ...),
  aber du musst KEINE vorgegebene Liste verwenden.
- exploitation_status: kurze deutsche Aussage (z.B. ob aktiv ausgenutzt / PoC vorhanden / keine Hinweise / unbekannt).
- recommended_measures: kurze deutsche Handlungsempfehlungen, wenn im Text empfohlen oder naheliegend. Sonst [].
- Nur extrahieren, was im Text erwähnt oder plausibel daraus folgt.
- Duplikate entfernen, kurze Strings.

TEXT:
\"\"\"{text_de}\"\"\"
""".strip()

    try:
        proc = subprocess.run(
            ["ollama", "run", OLLAMA_MODEL],
            input=prompt,
            text=True,
            capture_output=True,
            timeout=OLLAMA_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="strict",
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Ollama timed out after {OLLAMA_TIMEOUT_SECONDS}s running {OLLAMA_MODEL}"
        )

    if proc.returncode != 0:
        raise RuntimeError(
            f"Ollama failed (code={proc.returncode}) for model {OLLAMA_MODEL}: "
            f"{(proc.stderr or '').strip()}"
        )

    raw = (proc.stdout or "").strip()
    if not raw:
        raise RuntimeError("LLM returned empty output (expected JSON).")

    # Extract the first JSON object matching our schema
    json_str = extract_first_schema_json(raw, required_keys)

    # Parse JSON
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Invalid JSON returned by LLM: {e}\n"
            f"---JSON STR (first 1200 chars)---\n{json_str[:1200]}\n"
            f"---RAW (first 800 chars)---\n{raw[:800]}"
        )

    # Validate schema & types
    for k in required_keys:
        if k not in data:
            raise RuntimeError(
                f"Invalid LLM JSON: missing key '{k}'.\n"
                f"---JSON STR (first 1200 chars)---\n{json_str[:1200]}"
            )

    list_keys = [
        "organizations", "products", "threat_actors",
        "malware", "attack_types", "recommended_measures"
    ]
    for k in list_keys:
        if not isinstance(data[k], list):
            raise RuntimeError(
                f"Invalid LLM JSON: key '{k}' must be a list.\n"
                f"---JSON STR (first 1200 chars)---\n{json_str[:1200]}"
            )

    if not isinstance(data["exploitation_status"], str):
        raise RuntimeError(
            "Invalid LLM JSON: key 'exploitation_status' must be a string.\n"
            f"---JSON STR (first 1200 chars)---\n{json_str[:1200]}"
        )

    # Normalize
    out: Dict[str, Any] = {
        "organizations": set(str(x).strip() for x in data["organizations"] if str(x).strip()),
        "products": set(str(x).strip() for x in data["products"] if str(x).strip()),
        "threat_actors": set(str(x).strip() for x in data["threat_actors"] if str(x).strip()),
        "malware": set(str(x).strip() for x in data["malware"] if str(x).strip()),
        "attack_types": set(str(x).strip() for x in data["attack_types"] if str(x).strip()),
        "recommended_measures": [str(x).strip() for x in data["recommended_measures"] if str(x).strip()],
        "exploitation_status": data["exploitation_status"].strip(),
    }

    # If empty, keep empty string (LLM decided); downstream we will store it as-is.
    return out


# ================== Processing ==================

def process_preprocessed_report(pre_file: Path, meta_file: Path | None) -> List[Dict[str, Any]]:
    rows = json.loads(pre_file.read_text(encoding="utf-8"))
    if not rows:
        return []

    base_meta = {
        "report_date": rows[0].get("report_date"),
        "tlp": None,
        "period_from": None,
        "period_to": None,
        "report_file": pre_file.name,
    }

    if meta_file and meta_file.exists():
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        base_meta.update({
            "report_date": meta.get("report_date", base_meta["report_date"]),
            "tlp": meta.get("tlp"),
            "period_from": meta.get("period_from"),
            "period_to": meta.get("period_to"),
        })

    # Group rows by (section, subsection)
    groups: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(lambda: {
        "text_blocks": [],
        "sources": set(),
    })

    for row in rows:
        section = row.get("section")
        subsection = row.get("subsection")
        if not subsection:
            continue

        key = (section, subsection)
        group = groups[key]

        if row.get("is_source_block"):
            for u in normalize_urls(row.get("urls")):
                group["sources"].add(u)
            continue

        txt = (row.get("text") or "").strip()
        if txt:
            group["text_blocks"].append(txt)

    subsection_objects: List[Dict[str, Any]] = []

    for (section, subsection), data in groups.items():
        if not data["text_blocks"]:
            continue

        text_de = "\n\n".join(data["text_blocks"]).strip()
        if not text_de:
            continue

        # Deterministic extraction
        det = extract_deterministic_entities(text_de)

        # LLM extraction
        llm = extract_entities_with_qwen_de(text_de)

        entities: Dict[str, List[str]] = {
            "cve_ids": sorted(det["cve_ids"]),
            "cvss_scores": sorted(det["cvss_scores"]),
            "ioc_urls": sorted(det["ioc_urls"]),
            "ioc_domains": sorted(det["ioc_domains"]),
            "ioc_ipv4": sorted(det["ioc_ipv4"]),
            "ioc_emails": sorted(det["ioc_emails"]),
            "ioc_hashes": sorted(det["ioc_hashes"]),
            "organizations": sorted(llm["organizations"]),
            "products": sorted(llm["products"]),
            "threat_actors": sorted(llm["threat_actors"]),
            "malware": sorted(llm["malware"]),
            "attack_types": sorted(llm["attack_types"]),
            "status_phrases": [llm["exploitation_status"]] if llm["exploitation_status"] else [],
            "measures": sorted(llm["recommended_measures"]),
        }

        # Keep only subsections that have at least some extracted value
        if not any(entities[k] for k in entities.keys()):
            continue

        sub_id, sub_title = split_subsection(subsection)

        subsection_objects.append({
            **base_meta,
            "section": section,
            "subsection": subsection,
            "subsection_id": sub_id,
            "subsection_title": sub_title,
            "text_de": text_de,
            "sources": sorted(data["sources"]),
            "entities": entities,
            "llm_model": OLLAMA_MODEL,
        })

    return subsection_objects


def main():
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    date_dirs = [d for d in INPUT_DIR.iterdir() if d.is_dir() and d.name != "_combined"]
    if not date_dirs:
        print(f"[!] No date folders found in {INPUT_DIR}")
        return

    all_subsections: List[Dict[str, Any]] = []

    for d in sorted(date_dirs):
        pre_files = list(d.glob("bsi_preprocessed_*.json"))
        if not pre_files:
            print(f"[-] No bsi_preprocessed_*.json in {d}")
            continue

        pre_file = pre_files[0]
        meta_files = list(d.glob("bsi_report_meta_*.json"))
        meta_file = meta_files[0] if meta_files else None

        print(f"[+] Processing {pre_file.name}")

        try:
            subsection_objs = process_preprocessed_report(pre_file, meta_file)
        except Exception as e:
            if FAIL_FAST:
                raise
            else:
                print(f"[!] ERROR processing {pre_file.name}: {e}")
                continue

        out_dir = OUTPUT_DIR / d.name
        out_dir.mkdir(parents=True, exist_ok=True)

        out_path = out_dir / f"subsections_{d.name}.json"
        out_path.write_text(
            json.dumps(subsection_objs, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        print(f"    -> {len(subsection_objs)} subsections written to {out_path}")

        all_subsections.extend(subsection_objs)

    combined_dir = OUTPUT_DIR / "_combined"
    combined_dir.mkdir(parents=True, exist_ok=True)

    combined_path = combined_dir / "subsections_all.json"
    combined_path.write_text(
        json.dumps(all_subsections, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    print(f"\n[✓] Done. Total subsections with entities: {len(all_subsections)}")
    print(f"    Combined file: {combined_path}")


if __name__ == "__main__":
    main()
