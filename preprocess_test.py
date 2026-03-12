import re
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

# ========= CONFIG =========
INPUT_DIR  = Path("raw_texts")
OUTPUT_DIR = Path("preprocessed_bsi")
# ==========================

SECTION_RE = re.compile(r"^(?P<num>[1-4])\.\s+(?P<title>.+)$")
SUBSEC_RE  = re.compile(r"^(?P<num>\d+\.\d+)\.\s*(?P<title>.+)$")
QUELLEN_RE = re.compile(r"^Quelle\(n\)\s*:\s*$", re.IGNORECASE)

def normalize_text(t: str) -> str:
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"[ \t]+", " ", t)
    t = "\n".join(line.strip() for line in t.split("\n"))
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t

def extract_meta(text: str) -> Dict[str, Optional[str]]:
    date = tlp = period_from = period_to = None
    m = re.search(r"Tageslagebericht\s+vom\s+(\d{2}\.\d{2}\.\d{4})", text)
    if m:
        date = m.group(1)
    tlp_m = re.search(r"\bTLP\s*:\s*([A-Z]+)\b", text)
    if tlp_m:
        tlp = tlp_m.group(1)
    p = re.search(r"Berichtszeitraum\s+vom\s+(.+?)\s+bis\s+(.+?)\b", text)
    if p:
        period_from, period_to = p.group(1).strip(), p.group(2).strip()
    return {"report_date": date, "tlp": tlp, "period_from": period_from, "period_to": period_to}

def extract_urls_from_quellen_block(block: str) -> List[str]:
    # unwrap hyphen line breaks often used in URLs across line wraps
    joined = re.sub(r"-\n", "", block)
    joined = joined.replace("\n", " ")
    urls = re.findall(r"https?://[^\s)]+", joined)
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out

def preprocess_one_text(text: str) -> Dict[str, list]:
    """
    Output format (rows):
      - narrative rows: one row per Unterabschnitt (no sentence splitting)
        {is_source_block: False, text: "<full subsection text>"}
      - source rows: Quelle(n) blocks with extracted urls
        {is_source_block: True, text: "<source block>", urls:[...]}
    Only sections 1.* and 2.*.
    """
    text = normalize_text(text)
    meta = extract_meta(text)
    lines = text.split("\n")

    # Find section boundaries
    section_marks = []
    for i, line in enumerate(lines):
        m = SECTION_RE.match(line)
        if m:
            section_marks.append({"start": i, "num": m.group("num"), "title": m.group("title")})
    for j in range(len(section_marks)):
        section_marks[j]["end"] = section_marks[j+1]["start"] if j+1 < len(section_marks) else len(lines)

    target_secs = [s for s in section_marks if s["num"] in {"1", "2"}]

    # Accumulate narrative text per (section, subsection)
    narrative: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    sources: Dict[Tuple[str, str], List[str]] = defaultdict(list)

    rows = []

    for sec in target_secs:
        section_label = f"{sec['num']}. {sec['title']}"
        block_lines = lines[sec["start"]:sec["end"]]

        current_subsec = None
        i = 0
        while i < len(block_lines):
            line = block_lines[i]

            # Update current subsection
            msub = SUBSEC_RE.match(line)
            if msub:
                current_subsec = f"{msub.group('num')} {msub.group('title')}"
                i += 1
                continue

            # Collect Quelle(n) block
            if QUELLEN_RE.match(line):
                src_lines = [line]
                j = i + 1
                while j < len(block_lines):
                    t = block_lines[j]
                    if not t.strip():
                        src_lines.append(t)
                        j += 1
                        break
                    if SUBSEC_RE.match(t) or SECTION_RE.match(t):
                        break
                    src_lines.append(t)
                    j += 1

                src_block = "\n".join(src_lines).strip()
                urls = extract_urls_from_quellen_block(src_block)

                rows.append({
                    "report_date": meta["report_date"],
                    "section": section_label,
                    "subsection": current_subsec,
                    "is_source_block": True,
                    "text": src_block,
                    "urls": urls,
                })

                # also store sources keyed to subsection (optional)
                if current_subsec:
                    sources[(section_label, current_subsec)].extend(urls)

                i = j
                continue

            # Narrative line (NO sentence splitting)
            if line.strip() and current_subsec:
                narrative[(section_label, current_subsec)].append(line.strip())

            i += 1

    # Emit one narrative row per subsection
    for (section_label, subsec), chunks in narrative.items():
        text_block = "\n".join(chunks).strip()
        if not text_block:
            continue
        rows.append({
            "report_date": meta["report_date"],
            "section": section_label,
            "subsection": subsec,
            "is_source_block": False,
            "text": text_block,
            "urls": None,
        })

    # Sort rows to keep things stable
    rows.sort(key=lambda r: (r.get("section") or "", r.get("subsection") or "", 0 if r.get("is_source_block") else 1))

    return {"meta": meta, "rows": rows}

def main():
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    txt_files = sorted(INPUT_DIR.glob("*.txt"))
    if not txt_files:
        print(f"No .txt files found in {INPUT_DIR}")
        return

    all_rows, all_meta = [], []

    for txt in txt_files:
        print(f"[+] Processing {txt.name}")
        text = txt.read_text(encoding="utf-8", errors="ignore")
        result = preprocess_one_text(text)
        meta, rows = result["meta"], result["rows"]

        report_date = meta["report_date"] or txt.stem
        date_slug = report_date.replace(".", "")

        per_dir = OUTPUT_DIR / date_slug
        per_dir.mkdir(parents=True, exist_ok=True)

        (per_dir / f"bsi_preprocessed_{date_slug}.json").write_text(
            json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (per_dir / f"bsi_report_meta_{date_slug}.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        for r in rows:
            r["source_file"] = str(txt)
        all_rows.extend(rows)
        meta_w = dict(meta)
        meta_w["source_file"] = str(txt)
        all_meta.append(meta_w)

    combined = OUTPUT_DIR / "_combined"
    combined.mkdir(parents=True, exist_ok=True)
    (combined / "bsi_preprocessed_all.json").write_text(
        json.dumps(all_rows, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (combined / "bsi_report_meta_all.json").write_text(
        json.dumps(all_meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"\n✅ Done. Processed {len(txt_files)} files.")
    print("Included: sections 1 & 2, one text block per subsection + Quelle(n) blocks (with URLs).")
    print(f"Combined JSONs: {combined}")

if __name__ == "__main__":
    main()
