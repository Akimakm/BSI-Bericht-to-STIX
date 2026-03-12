#!/usr/bin/env python3
# demo_ui_opencti_style.py
# OpenCTI-like sequential demo UI (Next button) + large previews + structured entity view.

from __future__ import annotations

import os
import sys
import json
import time
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from flask import Flask, redirect, url_for, render_template_string, request

# ===================== CONFIG: EDIT THESE =====================
STEP1_SCRIPT = "ingestion_script.py"
STEP2_SCRIPT = "preprocess_test.py"
STEP3_SCRIPT = "extract_entitities.py"
STEP4_SCRIPT = "stix_export.py"

WORKDIR: Optional[str] = None  # e.g. r"C:\Users\malik\Downloads\TP3_Ingestion_Fertig\Demo"

# Where to find outputs (relative to WORKDIR)
OUTPUT_LOCATIONS = {
    "raw_txt": {"base": "raw_texts", "pattern": "*.txt"},
    "preprocessed": {"base": "preprocessed_bsi", "pattern": "_combined/bsi_preprocessed_*.json"},
    "entities": {"base": "Extracted_entities", "pattern": "**/subsections_*.json"},
    "stix": {"base": ".", "pattern": "stix_output.json"},
}

HOST = "127.0.0.1"
PORT = 5057
MAX_CHARS = 40000  # larger preview
# =============================================================

app = Flask(__name__)

STATE: Dict[str, Any] = {
    "step": 0,
    "steps": [],
    "active_tab": "entities",  # entities | preprocessed | stix | raw
    "active_item_idx": 0,      # which subsection item to show (entities/preprocessed)
}

HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>BSI Pipeline Demo (OpenCTI UI)</title>
  <style>
    :root{
      --bg:#0b1220;
      --panel:#0f1a2b;
      --panel2:#111f33;
      --text:#e8eefc;
      --muted:#9fb0d0;
      --border:#1e2b44;
      --accent:#4f8cff;
      --good:#2bd46a;
      --bad:#ff4d6d;
      --chip:#1a2a45;
    }
    * { box-sizing: border-box; }
    body { margin:0; font-family: Inter, Arial, sans-serif; background:var(--bg); color:var(--text); }
    .wrap { max-width: 1400px; margin: 0 auto; padding: 18px; }
    .topbar { display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom: 14px; }
    .title { font-size: 20px; font-weight: 800; letter-spacing: 0.2px; }
    .pill { padding:8px 12px; border:1px solid var(--border); border-radius: 999px; background: rgba(255,255,255,0.03); color: var(--muted); }
    .grid { display:grid; grid-template-columns: 420px 1fr; gap: 14px; }
    .card { background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02)); border:1px solid var(--border); border-radius: 14px; padding: 14px; }
    .card h3 { margin: 0 0 10px 0; font-size: 14px; color: var(--muted); font-weight: 800; text-transform: uppercase; letter-spacing: .7px; }
    .btnrow { display:flex; gap:10px; margin-top: 10px; }
    .btn { border:1px solid var(--border); background: rgba(255,255,255,0.04); color: var(--text); padding: 10px 12px; border-radius: 12px; font-weight: 800; cursor:pointer; }
    .btn-primary { background: rgba(79,140,255,0.20); border-color: rgba(79,140,255,0.50); }
    .btn:disabled { opacity: 0.5; cursor:not-allowed; }
    .steps { display:flex; gap:8px; flex-wrap:wrap; }
    .stepchip { padding:8px 10px; border-radius: 12px; background: rgba(255,255,255,0.03); border:1px solid var(--border); color: var(--muted); font-weight: 800; }
    .stepchip.active { border-color: rgba(79,140,255,0.7); color: var(--text); }
    code { background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 8px; border:1px solid rgba(255,255,255,0.06); color: var(--text); }
    .kv { display:grid; grid-template-columns: 120px 1fr; gap: 8px; margin: 6px 0; font-size: 13px; }
    .k { color: var(--muted); font-weight: 800; }
    .v { overflow:hidden; text-overflow: ellipsis; }
    .tabs { display:flex; gap:8px; margin-bottom: 10px; flex-wrap: wrap; }
    .tab { padding:8px 10px; border-radius: 12px; border:1px solid var(--border); background: rgba(255,255,255,0.03); color: var(--muted); font-weight: 800; cursor:pointer; text-decoration:none; }
    .tab.active { border-color: rgba(79,140,255,0.7); color: var(--text); background: rgba(79,140,255,0.12); }
    .split { display:grid; grid-template-columns: 420px 1fr; gap: 14px; }
    .list { max-height: 74vh; overflow:auto; border-radius: 12px; border:1px solid var(--border); background: rgba(0,0,0,0.20); }
    .row { padding: 10px 12px; border-bottom:1px solid rgba(255,255,255,0.06); cursor:pointer; }
    .row:hover { background: rgba(255,255,255,0.03); }
    .row.active { outline: 2px solid rgba(79,140,255,0.6); background: rgba(79,140,255,0.10); }
    .row .t { font-weight: 900; }
    .row .s { color: var(--muted); font-size: 12px; margin-top: 4px; }
    .detail { max-height: 74vh; overflow:auto; border-radius: 12px; border:1px solid var(--border); background: rgba(0,0,0,0.20); padding: 14px; }
    .chips { display:flex; flex-wrap:wrap; gap:8px; margin: 8px 0 14px 0; }
    .chip { background: rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); padding: 6px 10px; border-radius: 999px; font-weight: 800; font-size: 12px; }
    .sectiontitle { margin-top: 16px; margin-bottom: 8px; font-size: 13px; font-weight: 900; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; }
    table { width:100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.06); vertical-align: top; }
    th { color: var(--muted); text-align: left; font-weight: 900; }
    pre { white-space: pre-wrap; word-break: break-word; font-size: 12px; line-height: 1.35; background: rgba(0,0,0,0.35); border:1px solid rgba(255,255,255,0.08); padding: 12px; border-radius: 12px; }
    .logok { color: var(--good); font-weight: 900; }
    .logbad { color: var(--bad); font-weight: 900; }
    details summary { cursor:pointer; font-weight: 900; color: var(--muted); }
  </style>
</head>
<body>
<div class="wrap">

  <div class="topbar">
    <div class="title">BSI Pipeline Live Demo</div>
    <div class="pill">Step: <b>{{ step }}/4</b></div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Control</h3>

      <div class="steps" style="margin-bottom:10px;">
        <div class="stepchip {% if step >= 1 %}active{% endif %}">1) Ingestion</div>
        <div class="stepchip {% if step >= 2 %}active{% endif %}">2) Preprocess</div>
        <div class="stepchip {% if step >= 3 %}active{% endif %}">3) Extraction</div>
        <div class="stepchip {% if step >= 4 %}active{% endif %}">4) STIX</div>
      </div>

      <div class="kv"><div class="k">Workdir</div><div class="v"><code>{{ workdir }}</code></div></div>
      <div class="kv"><div class="k">Python</div><div class="v"><code>{{ py }}</code></div></div>
      <div class="kv"><div class="k">Next</div><div class="v"><code>{{ next_script }}</code></div></div>

      <div class="btnrow">
        {% if step < 4 %}
        <form method="post" action="{{ url_for('next_step') }}">
          <button class="btn btn-primary" type="submit">Next ▶</button>
        </form>
        {% endif %}
        <form method="post" action="{{ url_for('reset') }}">
          <button class="btn" type="submit">Reset</button>
        </form>
      </div>

      <h3 style="margin-top:14px;">Views</h3>
      <div class="tabs">
        <a class="tab {% if tab=='entities' %}active{% endif %}" href="{{ url_for('set_tab', tab='entities') }}">Entities (lesbar)</a>
        <a class="tab {% if tab=='preprocessed' %}active{% endif %}" href="{{ url_for('set_tab', tab='preprocessed') }}">Preprocessed</a>
        <a class="tab {% if tab=='stix' %}active{% endif %}" href="{{ url_for('set_tab', tab='stix') }}">STIX</a>
        <a class="tab {% if tab=='raw' %}active{% endif %}" href="{{ url_for('set_tab', tab='raw') }}">Raw TXT</a>
      </div>

      <h3>Logs</h3>
      {% if steps|length == 0 %}
        <div style="color:var(--muted);">Noch keine Schritte ausgeführt.</div>
      {% else %}
        {% for s in steps %}
          <div style="margin:10px 0; padding-top:10px; border-top:1px solid rgba(255,255,255,0.06);">
            <div style="font-weight:900;">
              {{ s.name }} —
              {% if s.rc==0 %}<span class="logok">OK</span>{% else %}<span class="logbad">FAILED</span>{% endif %}
              <span style="color:var(--muted); font-weight:700;"> ({{ "%.2f"|format(s.seconds) }}s)</span>
            </div>
            <div style="color:var(--muted); font-size:12px;"><b>Cmd:</b> {{ s.cmd }}</div>
            <details {% if s.rc!=0 %}open{% endif %}>
              <summary>STDOUT</summary>
              <pre>{{ s.stdout }}</pre>
            </details>
            <details {% if s.rc!=0 %}open{% endif %}>
              <summary>STDERR</summary>
              <pre>{{ s.stderr }}</pre>
            </details>
          </div>
        {% endfor %}
      {% endif %}
    </div>

    <div class="card">
      <h3>Preview</h3>
      <div class="split">
        <div class="list">
          {% if list_items|length == 0 %}
            <div class="row"><div class="t">Keine Items gefunden</div><div class="s">Führe zuerst Schritte aus.</div></div>
          {% else %}
            {% for it in list_items %}
              <a href="{{ url_for('select_item', idx=loop.index0) }}" style="text-decoration:none; color:inherit;">
                <div class="row {% if loop.index0==active_idx %}active{% endif %}">
                  <div class="t">{{ it.title }}</div>
                  <div class="s">{{ it.subtitle }}</div>
                </div>
              </a>
            {% endfor %}
          {% endif %}
        </div>

        <div class="detail">
          {% if detail is none %}
            <div style="color:var(--muted);">Kein Detail verfügbar.</div>
          {% else %}
            <div style="font-size:16px; font-weight:900;">{{ detail.header }}</div>
            <div style="color:var(--muted); margin-top:6px;">{{ detail.meta }}</div>

            {% if detail.chips %}
            <div class="chips">
              {% for c in detail.chips %}
                <div class="chip">{{ c }}</div>
              {% endfor %}
            </div>
            {% endif %}

            {% for section in detail.sections %}
              <div class="sectiontitle">{{ section.name }}</div>
              {% if section.type == "table" %}
                <table>
                  <thead><tr><th>Feld</th><th>Wert</th></tr></thead>
                  <tbody>
                    {% for k,v in section["rows"] %}
                      <tr><td style="width:220px;"><b>{{ k }}</b></td><td>{{ v }}</td></tr>
                    {% endfor %}
                  </tbody>
                </table>
              {% elif section.type == "list" %}
                <div class="chips">
                  {% for x in section["items"] %}
                    <div class="chip">{{ x }}</div>
                  {% endfor %}
                </div>
              {% elif section.type == "raw" %}
                <pre>{{ section.text }}</pre>
              {% endif %}
            {% endfor %}
          {% endif %}
        </div>

      </div>
    </div>
  </div>

</div>
</body>
</html>
"""


def truncate(s: str, n: int = MAX_CHARS) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + f"\n\n...[truncated to {n} chars]..."


def get_workdir() -> Path:
    if WORKDIR:
        return Path(WORKDIR).resolve()
    return Path(__file__).resolve().parent


def run_cmd(cmd: List[str], cwd: Path) -> Tuple[int, str, str, float]:
    t0 = time.time()
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    return p.returncode, p.stdout or "", p.stderr or "", time.time() - t0


def newest_file(root: Path, pattern: str) -> Optional[Path]:
    files = list(root.glob(pattern))
    files = [f for f in files if f.is_file()]
    if not files:
        return None
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0]


def load_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def find_outputs(workdir: Path) -> Dict[str, Optional[Path]]:
    out = {}
    for k, spec in OUTPUT_LOCATIONS.items():
        base = (workdir / spec["base"]).resolve()
        if base.exists():
            out[k] = newest_file(base, spec["pattern"])
        else:
            out[k] = None
    return out


def stringify(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (int, float, bool)):
        return str(v)
    if isinstance(v, str):
        return v
    return json.dumps(v, ensure_ascii=False)


def make_entities_view(entities_json: Any) -> Tuple[List[Dict[str, str]], Optional[Dict[str, Any]]]:
    """
    Build OpenCTI-like list + detail for "Extracted Entities JSON".

    Supports both:
    - list of subsection objects
    - dict with 'subsections' list
    """
    if entities_json is None:
        return [], None

    if isinstance(entities_json, dict) and "subsections" in entities_json and isinstance(entities_json["subsections"], list):
        items = entities_json["subsections"]
    elif isinstance(entities_json, list):
        items = entities_json
    else:
        items = []

    list_items: List[Dict[str, str]] = []
    for i, it in enumerate(items):
        section = it.get("section", "")
        sub = it.get("subsection", "") or it.get("subsection_title", "")
        title = f"{section} – {sub}" if section or sub else f"Item {i+1}"
        subtitle = it.get("report_date", "") or it.get("subsection_id", "") or ""
        list_items.append({"title": title, "subtitle": subtitle})

    idx = int(STATE["active_item_idx"] or 0)
    if not items:
        return list_items, None
    idx = max(0, min(idx, len(items) - 1))
    it = items[idx]

    ents = it.get("entities", it)  # sometimes entities are nested
    # Build detail sections
    header = list_items[idx]["title"]
    meta = f"report_date={it.get('report_date','')} | tlp={it.get('tlp','')} | subsection_id={it.get('subsection_id','')}"
    chips = []
    if it.get("tlp"):
        chips.append(f"TLP: {it['tlp']}")
    if it.get("llm_model"):
        chips.append(f"LLM: {it['llm_model']}")

    # Table: meta fields
    table_rows = []
    for k in ["report_date", "period_from", "period_to", "section", "subsection", "subsection_id"]:
        if it.get(k):
            table_rows.append((k, stringify(it.get(k))))

    # Lists: extracted fields (if present)
    list_sections = []
    if isinstance(ents, dict):
        for key in [
            "cve_ids", "cvss_scores", "ioc_ipv4", "ioc_domains", "ioc_urls", "ioc_emails", "ioc_hashes",
            "organizations", "products", "threat_actors", "malware",
            "attack_types", "status_phrases", "measures",
        ]:
            val = ents.get(key)
            if isinstance(val, list) and val:
                list_sections.append({"name": key, "type": "list", "items": [stringify(x) for x in val]})
            elif isinstance(val, str) and val:
                list_sections.append({"name": key, "type": "list", "items": [val]})

    # Raw text preview
    text_de = it.get("text_de", "")
    raw_text = text_de if text_de else it.get("text", "")
    raw_section = {"name": "text (preview)", "type": "raw", "text": truncate(raw_text, 2500)}

    detail = {
        "header": header,
        "meta": meta,
        "chips": chips,
        "sections": [
            {"name": "Metadata", "type": "table", "rows": table_rows},
            *list_sections,
            raw_section,
        ]
    }
    return list_items, detail


def make_preprocessed_view(pre_json: Any) -> Tuple[List[Dict[str, str]], Optional[Dict[str, Any]]]:
    if pre_json is None:
        return [], None

    items = pre_json if isinstance(pre_json, list) else pre_json.get("subsections", []) if isinstance(pre_json, dict) else []
    list_items = []
    for i, it in enumerate(items):
        section = it.get("section", "")
        sub = it.get("subsection", "") or it.get("subsection_title", "")
        title = f"{section} – {sub}" if section or sub else f"Item {i+1}"
        subtitle = it.get("report_date", "") or it.get("subsection_id", "") or ""
        list_items.append({"title": title, "subtitle": subtitle})

    idx = int(STATE["active_item_idx"] or 0)
    if not items:
        return list_items, None
    idx = max(0, min(idx, len(items) - 1))
    it = items[idx]
    header = list_items[idx]["title"]
    meta = f"report_date={it.get('report_date','')} | subsection_id={it.get('subsection_id','')}"
    text_de = it.get("text_de", "") or it.get("text", "")
    detail = {
        "header": header,
        "meta": meta,
        "chips": [],
        "sections": [
            {"name": "Text", "type": "raw", "text": truncate(text_de, 7000)},
            {"name": "Raw JSON", "type": "raw", "text": truncate(json.dumps(it, ensure_ascii=False, indent=2), 9000)},
        ]
    }
    return list_items, detail


def make_stix_view(stix_json: Any) -> Tuple[List[Dict[str, str]], Optional[Dict[str, Any]]]:
    if stix_json is None:
        return [], None

    objects = []
    if isinstance(stix_json, dict) and "objects" in stix_json and isinstance(stix_json["objects"], list):
        objects = stix_json["objects"]
    elif isinstance(stix_json, list):
        objects = stix_json
    else:
        objects = []

    list_items = []
    for i, obj in enumerate(objects):
        t = obj.get("type", f"obj{i}")
        name = obj.get("name") or obj.get("pattern") or obj.get("id", f"Object {i+1}")
        list_items.append({"title": f"{t}: {name}", "subtitle": obj.get("id", "")})

    idx = int(STATE["active_item_idx"] or 0)
    if not objects:
        return list_items, None
    idx = max(0, min(idx, len(objects) - 1))
    obj = objects[idx]
    header = list_items[idx]["title"]
    meta = obj.get("id", "")
    # show key fields first + raw JSON
    rows = []
    for k in ["type", "id", "name", "created", "modified", "published", "confidence"]:
        if obj.get(k):
            rows.append((k, stringify(obj.get(k))))
    detail = {
        "header": header,
        "meta": meta,
        "chips": [],
        "sections": [
            {"name": "Core Fields", "type": "table", "rows": rows},
            {"name": "Raw STIX JSON", "type": "raw", "text": truncate(json.dumps(obj, ensure_ascii=False, indent=2), 20000)},
        ]
    }
    return list_items, detail


def make_raw_view(txt: str) -> Tuple[List[Dict[str, str]], Optional[Dict[str, Any]]]:
    if not txt:
        return [], None
    items = [{"title": "Raw TXT (latest)", "subtitle": ""}]
    detail = {
        "header": "Raw TXT",
        "meta": "",
        "chips": [],
        "sections": [{"name": "Text", "type": "raw", "text": truncate(txt, 20000)}]
    }
    return items, detail


def next_script_for_step(step: int) -> str:
    mapping = {0: STEP1_SCRIPT, 1: STEP2_SCRIPT, 2: STEP3_SCRIPT, 3: STEP4_SCRIPT}
    return mapping.get(step, "(done)")


@app.get("/")
def index():
    wd = get_workdir()
    outs = find_outputs(wd)

    tab = STATE["active_tab"]

    items: List[Dict[str, str]] = []
    detail: Optional[Dict[str, Any]] = None

    if tab == "entities" and outs.get("entities"):
        data = load_json(outs["entities"])
        items, detail = make_entities_view(data)
    elif tab == "preprocessed" and outs.get("preprocessed"):
        data = load_json(outs["preprocessed"])
        items, detail = make_preprocessed_view(data)
    elif tab == "stix" and outs.get("stix"):
        data = load_json(outs["stix"])
        items, detail = make_stix_view(data)
    elif tab == "raw_txt" and outs.get("raw_txt"):
        txt = (outs["raw_txt"].read_text(encoding="utf-8", errors="replace"))
        items, detail = make_raw_view(txt)
    elif tab == "raw":
        # alias
        if outs.get("raw_txt"):
            txt = outs["raw_txt"].read_text(encoding="utf-8", errors="replace")
            items, detail = make_raw_view(txt)

    # keep idx in range
    if items:
        STATE["active_item_idx"] = max(0, min(int(STATE["active_item_idx"]), len(items) - 1))
    else:
        STATE["active_item_idx"] = 0

    return render_template_string(
        HTML,
        step=STATE["step"],
        steps=STATE["steps"],
        tab=tab if tab != "raw_txt" else "raw",
        list_items=items,
        detail=detail,
        active_idx=int(STATE["active_item_idx"]),
        workdir=str(wd),
        py=sys.executable,
        next_script=next_script_for_step(STATE["step"]),
    )


@app.get("/tab/<tab>")
def set_tab(tab: str):
    # reset selection when switching tab
    if tab not in ("entities", "preprocessed", "stix", "raw"):
        tab = "entities"
    STATE["active_tab"] = tab
    STATE["active_item_idx"] = 0
    return redirect(url_for("index"))


@app.get("/select/<int:idx>")
def select_item(idx: int):
    STATE["active_item_idx"] = idx
    return redirect(url_for("index"))


@app.post("/reset")
def reset():
    STATE["step"] = 0
    STATE["steps"] = []
    STATE["active_item_idx"] = 0
    return redirect(url_for("index"))


@app.post("/next")
def next_step():
    wd = get_workdir()

    step = STATE["step"]
    script = next_script_for_step(step)
    if script == "(done)":
        return redirect(url_for("index"))

    script_path = (wd / script).resolve()
    names = {0: "1) Ingestion", 1: "2) Preprocessing", 2: "3) Extraction", 3: "4) STIX Export"}

    if not script_path.exists():
        STATE["steps"].append({
            "name": names.get(step, f"Step {step+1}"),
            "cmd": f"{sys.executable} {script_path}",
            "rc": 1,
            "stdout": "",
            "stderr": f"Script not found: {script_path}",
            "seconds": 0.0,
        })
        return redirect(url_for("index"))

    cmd = [sys.executable, str(script_path)]
    rc, out, err, seconds = run_cmd(cmd, cwd=wd)

    STATE["steps"].append({
        "name": names.get(step, f"Step {step+1}"),
        "cmd": " ".join(cmd),
        "rc": rc,
        "stdout": truncate(out, 12000),
        "stderr": truncate(err, 12000),
        "seconds": seconds,
    })

    if rc == 0:
        STATE["step"] = min(4, STATE["step"] + 1)

    return redirect(url_for("index"))


# map endpoints
app.add_url_rule("/next", "next_step", next_step, methods=["POST"])
app.add_url_rule("/reset", "reset", reset, methods=["POST"])


def main():
    wd = get_workdir()
    missing = [s for s in [STEP1_SCRIPT, STEP2_SCRIPT, STEP3_SCRIPT, STEP4_SCRIPT] if not (wd / s).exists()]
    if missing:
        print("[!] Missing demo scripts in workdir:")
        for m in missing:
            print("   -", m)
        print("Edit STEP1_SCRIPT..STEP4_SCRIPT at the top of demo_ui_opencti_style.py")

    print(f"[+] Open: http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)


if __name__ == "__main__":
    main()
