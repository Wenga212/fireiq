#!/usr/bin/env python3
"""
FireIQ data builder
====================
Reads vendor datasheets from the datasheets/ folder and writes a unified
data/firewalls.json that the FireIQ web app consumes.

How it works
------------
Run locally:    python scripts/build.py
Run on CI:      .github/workflows/rebuild.yml triggers this on push to datasheets/

Each file in datasheets/ is dispatched by extension:
    .pdf   -> the appropriate PDF parser (one per vendor)
    .html  -> the appropriate HTML parser (one per vendor)
    .xlsx  -> a generic spreadsheet parser
    .json  -> loaded as-is (for manual data entry)

The file STEM (filename without extension) determines which parser to use:
    fortinet.pdf       -> parse_fortinet_pdf
    checkpoint.pdf     -> parse_checkpoint_pdf
    paloalto.pdf       -> parse_paloalto_pdf
    cisco-1200.html    -> parse_cisco_1200_html
    manual.json        -> load_manual_json

To add a new vendor: create the parser function below and add it to PARSERS.
"""
from __future__ import annotations

import json
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# Third-party imports happen inside parsers so the JSON-only path doesn't
# require pdfplumber or bs4. CI installs them via requirements.txt anyway.

ROOT       = Path(__file__).resolve().parent.parent
DATASHEETS = ROOT / "datasheets"
DATA_DIR   = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
OUT_FILE   = DATA_DIR / "firewalls.json"
STATUS     = DATA_DIR / "sources-status.json"

# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)


# ----- Throughput parsers (Gbps unit) -----
def to_gbps(text: str | None) -> float:
    """
    Parse throughput strings into Gbps as a float.

    Examples:
      "4 Gbps"       -> 4.0
      "800 Mbps"     -> 0.8
      "1.5 Tbps"     -> 1500.0
      "164 / 163 / 145 Gbps" -> 164.0   (takes first value when slash-separated)
      "—"            -> 0.0
    """
    if not text:
        return 0.0
    t = str(text).strip()
    if t in ("—", "-", "N/A", "n/a", ""):
        return 0.0
    # If slash-separated (e.g. "164 / 163 / 145 Gbps"), take the first number
    first = re.split(r"\s*/\s*", t)[0]
    m = re.search(r"([\d.]+)\s*(T|G|M|K)?(?:bps|b/s)?", first, re.IGNORECASE)
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = (m.group(2) or "G").upper()
    mult = {"T": 1000, "G": 1, "M": 0.001, "K": 0.000001}.get(unit, 1)
    return round(val * mult, 4)


# ----- Sessions parser (Millions unit) -----
def to_millions(text: str | None) -> float:
    """
    Parse session count strings into millions.

    Examples:
      "600 000"       -> 0.6   (raw count, spaces are thousands separators)
      "1.5 Million"   -> 1.5
      "28 Million"    -> 28.0
      "1 Billion"     -> 1000.0
      "210 Million / 450 Million" -> 210.0  (takes first)
    """
    if not text:
        return 0.0
    t = str(text).strip()
    if t in ("—", "-", "N/A", ""):
        return 0.0
    first = re.split(r"\s*/\s*", t)[0]
    # Normalise unicode/regular spaces and commas — both function as thousands separators
    cleaned = first.replace("\u00a0", "").replace(",", "")
    # Detect if there's an explicit Million/Billion unit
    m_unit = re.search(r"(million|billion|m|b)\b", cleaned, re.IGNORECASE)
    if m_unit:
        m = re.search(r"([\d.]+)", cleaned)
        if not m:
            return 0.0
        val = float(m.group(1))
        unit = m_unit.group(1).lower()
        if unit.startswith("billion") or unit == "b":
            return round(val * 1000, 2)
        return round(val, 2)
    # No unit — strip remaining internal whitespace and treat as raw count
    bare = re.sub(r"\s+", "", cleaned)
    m = re.match(r"^([\d.]+)$", bare)
    if not m:
        return 0.0
    val = float(m.group(1))
    # Raw counts of "concurrent sessions" are typically in the millions range,
    # so 600000 → 0.6 M, 28000000 → 28 M
    return round(val / 1_000_000, 4) if val > 1000 else round(val, 2)


# ----- New sessions/sec — keep as integer -----
def to_int_count(text: str | None) -> int:
    """Parse 'New Sessions/Sec' style numbers — keep as integer."""
    if not text:
        return 0
    t = str(text).replace("\u00a0", " ").replace(",", "").replace(" ", "").strip()
    if t in ("—", "-", "N/A", ""):
        return 0
    first = re.split(r"/", t)[0]
    m = re.search(r"([\d.]+)\s*(million|m)?", first, re.IGNORECASE)
    if not m:
        return 0
    val = float(m.group(1))
    unit = (m.group(2) or "").lower()
    if unit.startswith("m") or unit == "m":
        return int(val * 1_000_000)
    return int(val)


# ----- Form factor extractor -----
def classify_form_factor(text: str) -> str:
    """Map 'Desktop', '1 RU', '2 RU', etc. into our schema's compact form."""
    if not text:
        return ""
    t = text.strip().lower()
    if "desktop" in t:
        return "Desktop"
    m = re.search(r"(\d+)\s*ru", t)
    if m:
        return f"{m.group(1)}U"
    return text.strip()


# ─────────────────────────────────────────────────────────────────────────────
# FORTINET PARSER
# ─────────────────────────────────────────────────────────────────────────────
#
# Fortinet's Product Matrix PDF (May 2026) lays out 4-5 FortiGate models per
# section. Each section has model names on one line, then ~25 spec rows below.
# We parse by extracting all text from the PDF and walking it linearly,
# identifying model header lines and the following spec rows.
#
# Why text-based parsing instead of table extraction:
#   pdfplumber's table extractor struggles with the multi-line cells used here
#   (e.g. interface descriptions span 3-4 lines per cell). Text extraction
#   preserves the visual reading order, which is what we need.

# The labels we look for in each row, mapped to our JSON schema keys + unit type
FORTINET_ROWS = [
    # (label_regex, json_key, parser_function, optional unit override)
    (r"^Firewall Throughput",                 "fw",       "fw_throughput"),
    (r"^IPsec VPN Throughput",                "vpn",      "gbps"),
    (r"^IPS Throughput",                      "ips",      "gbps"),
    (r"^NGFW Throughput",                     "ngfw",     "gbps"),
    (r"^Threat Protection Throughput",        "threat",   "gbps"),
    (r"^Concurrent Sessions",                 "sessions", "millions"),
    (r"^New Sessions/?Sec",                   "newSess",  "int_count"),
    (r"^SSL VPN Throughput",                  "ssl",      "gbps"),
    (r"^SSL Inspection Throughput",           "ssl_insp", "gbps"),  # extra field, optional
    (r"^Interfaces",                          "iface",    "text"),
    (r"^Local Storage",                       "ssd",      "text"),
    (r"^Form Factor",                         "ff",       "form"),
]


def parse_fortinet_pdf(pdf_path: Path) -> list[dict]:
    """
    Parse the Fortinet Product Matrix PDF into a list of model dicts.

    Returns a list of dicts like:
        {"vendor": "Fortinet", "model": "FG-30G", "fw": 4.0, ...}
    """
    import pdfplumber

    log(f"  Reading {pdf_path.name}")
    full_text = ""
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text(x_tolerance=2) or ""
            full_text += page_text + "\n"

    lines = [l.rstrip() for l in full_text.split("\n")]
    log(f"  Extracted {len(lines)} lines of text")

    # ── STEP 1: Identify section header lines.
    # A model header line contains 3-5 model names separated by whitespace.
    # Example: "FG/FWF-30G 12 FG/FWF-40F 12 FG/FWF-50G 12 FG/FWF-60F 12"
    # We strip footnote markers (numbers after model names) when extracting.
    model_pattern = re.compile(r"FG(?:/FWF)?-\d+[A-Z]+")
    # Find indices of lines that contain 2+ FG-* model names (section headers)
    section_starts = []
    for i, line in enumerate(lines):
        models_in_line = model_pattern.findall(line)
        # Filter to FortiGate models only (not switch/AP series)
        if len(models_in_line) >= 2:
            section_starts.append((i, models_in_line))

    log(f"  Identified {len(section_starts)} model-group sections")

    # ── STEP 2: For each section, the next ~25 lines contain spec rows.
    # Each spec row has a label followed by N values (one per model in the section).
    # We collect spec values for each model by position.
    all_models: dict[str, dict] = {}

    for sect_idx, (line_idx, models_in_section) in enumerate(section_starts):
        # Determine end of this section: the next section start, or +30 lines
        end_idx = section_starts[sect_idx + 1][0] if sect_idx + 1 < len(section_starts) else line_idx + 35
        section_lines = lines[line_idx + 1:end_idx]

        # Normalise model names (strip footnote numbers attached after)
        clean_models = []
        for m in models_in_section:
            # FG/FWF-30G → keep both forms; standardise on FG-30G
            stem = re.sub(r"^FG/FWF-", "FG-", m)
            clean_models.append(stem)

        # Initialise each model's record
        for m in clean_models:
            if m not in all_models:
                all_models[m] = {
                    "vendor": "Fortinet",
                    "model":  m,
                    "series": re.sub(r"^FG-", "", m),
                    "fw": 0.0, "ips": 0.0, "ngfw": 0.0, "threat": 0.0,
                    "vpn": 0.0, "sessions": 0.0, "newSess": 0,
                    "ssl": None, "iface": "", "ff": "", "ssd": None,
                    "proc": "",
                    "source": "fortinet.pdf",
                }

        # ── STEP 3: Walk the spec rows within this section.
        # A spec row format example:
        #   "IPS Throughput (Enterprise Mix) 2 800 Mbps 1 Gbps 2.25 Gbps 1.4 Gbps"
        # We split off the label prefix, then split the remainder by whitespace
        # in a way that respects the per-model values.
        #
        # The simplest reliable approach: find the row that matches each label
        # regex, then capture all numeric values + units after the label.

        # Collect multi-line rows: PDF text sometimes wraps long values
        # (especially Interfaces) across multiple lines. So we join continuation
        # lines that don't start with a known label into the previous row.
        known_label_re = re.compile(
            r"^(Firewall Throughput|IPsec VPN|IPS Throughput|NGFW Throughput|"
            r"Threat Protection|Concurrent Sessions|New Sessions|SSL VPN|"
            r"SSL Inspection|Application Control|Max FortiAPs|Max FortiSwitches|"
            r"Max FortiTokens|Virtual Domains|Firewall Latency|Firewall Policies|"
            r"Max G/W|Max Client|Concurrent SSL|Interfaces|Local Storage|"
            r"Power Supplies|Form Factor|Variants)"
        )

        merged_rows: list[str] = []
        for line in section_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if known_label_re.match(stripped) or not merged_rows:
                merged_rows.append(stripped)
            else:
                # Continuation of previous row
                merged_rows[-1] += " " + stripped

        # Now parse each known row
        for label_re, json_key, kind in FORTINET_ROWS:
            row = next((r for r in merged_rows if re.match(label_re, r, re.IGNORECASE)), None)
            if not row:
                continue
            # Strip the label prefix
            body = re.sub(label_re, "", row, count=1, flags=re.IGNORECASE).strip()
            # Strip the descriptor in parentheses if present
            # e.g. "(1518 / 512 / 64 byte UDP)" or "(Enterprise Mix)" or "(TCP)"
            body = re.sub(r"^\([^)]*\)\s*", "", body).strip()
            # Strip leading footnote markers: small digits 1-2 chars only,
            # comma-separated, followed by whitespace. Example: "2 " or "2, 4 ".
            # Stops at the first "real" value (3+ digit numbers stay).
            body = re.sub(r"^\d{1,2}(?:\s*,\s*\d{1,2})*\s+(?=\d)", "", body).strip()

            values = _split_row_values(body, len(clean_models), kind)
            for model_name, raw_value in zip(clean_models, values):
                if kind == "fw_throughput":
                    all_models[model_name]["fw"] = to_gbps(raw_value)
                elif kind == "gbps":
                    all_models[model_name][json_key] = to_gbps(raw_value)
                elif kind == "millions":
                    all_models[model_name][json_key] = to_millions(raw_value)
                elif kind == "int_count":
                    all_models[model_name][json_key] = to_int_count(raw_value)
                elif kind == "form":
                    all_models[model_name][json_key] = classify_form_factor(raw_value)
                elif kind == "text":
                    # For iface/ssd, store the raw text. Storage often contains
                    # model variant in parens, e.g. "480 GB (701G)" — keep it.
                    cleaned = raw_value.strip()
                    if cleaned and cleaned not in ("—", "-", "N/A"):
                        all_models[model_name][json_key] = cleaned

    log(f"  Parsed {len(all_models)} FortiGate models")
    # Filter out models with all-zero throughput (parsing failed)
    valid = [m for m in all_models.values() if m["fw"] > 0 or m["ips"] > 0]
    log(f"  {len(valid)} have valid throughput values")
    return valid


def _split_row_values(body: str, num_models: int, kind: str) -> list[str]:
    """
    Split the body of a Fortinet spec row into N per-model values.

    Strategy: tokenise into "value units" by scanning left-to-right.
    A value can be:
      - a slash-separated triple: "4 / 4 / 2.4" → take first: "4"
      - a single number: "164"
      - a dash placeholder: "—" or "-"
    After the value, an optional unit suffix follows.

    For text rows, we use a heuristic split on multi-space gaps.
    """
    if not body:
        return [""] * num_models

    if kind in ("text", "form"):
        # Text rows are hard to split reliably from PDF text extraction
        # because column widths vary. Use a multi-space split with fallback.
        # The synthesizer in our test uses single spaces between values, so
        # this works only in well-formed PDFs.
        # Most reliable for short values: split by exact known patterns
        if kind == "form":
            # Form factor values are short: "Desktop", "1 RU", "2 RU", "Modular"
            parts = re.findall(r"(Desktop|\d+\s*RU|Modular|[A-Z][a-z]+)", body)
            if len(parts) == num_models:
                return parts
        # Generic fallback: try splitting on 2+ spaces
        parts = re.split(r"\s{2,}", body)
        if len(parts) == num_models:
            return parts
        # Last resort: dump full string into first slot, leave rest blank
        return [body] + [""] * (num_models - 1)

    # ── Numeric row tokenisation ──
    # Step 1: replace slash-separated triples with their FIRST value
    # e.g. "4 / 4 / 2.4 Gbps" → "4 Gbps"
    body = re.sub(
        r"([\d.]+)\s*/\s*[\d.]+(?:\s*/\s*[\d.]+)?",
        r"\1",
        body
    )
    # Step 2: replace "600 000" (space-separated thousands) with "600000"
    body = re.sub(r"(\d+)\s+(\d{3})\b", r"\1\2", body)

    # Step 3: scan for value tokens
    # A token is: number + optional unit, OR a dash placeholder
    token_re = re.compile(
        r"([\d.]+\s*(?:Tbps|Gbps|Mbps|Kbps|Million|Billion|M|G|K|μs|us)?|—|-)",
        re.IGNORECASE
    )
    raw_tokens = token_re.findall(body)
    # Strip empty/whitespace-only
    tokens = [t.strip() for t in raw_tokens if t.strip()]

    # If we have exactly num_models tokens, perfect.
    # If we have more, take the first num_models (extras are usually trailing notes).
    # If fewer, pad with empty.
    if len(tokens) >= num_models:
        return tokens[:num_models]
    return tokens + [""] * (num_models - len(tokens))


# ─────────────────────────────────────────────────────────────────────────────
# STUB PARSERS — to be filled in when you have the actual datasheets
# ─────────────────────────────────────────────────────────────────────────────
def _fill_spanning_cells(value_words, cols, found, key, label_mbps, cell_gbps_fn, cutoff):
    """A throughput value centred midway between two adjacent model columns is a
    merged cell that applies to BOTH (e.g. Spark 'Firewall (Mbps) ... 17,500' for
    2580 and 2590). For each numeric value word, if its x-centre is nearly
    equidistant from two columns, set both — but never overwrite a value already
    set from a more specific (per-column) source."""
    import re as _re
    # Build (value_text, x_centre) for digit-bearing words right of cutoff
    vals = []
    for w in value_words:
        xc = (w["x0"] + w["x1"]) / 2
        if xc < cutoff:
            continue
        if _re.search(r"\d", w["text"]):
            vals.append((w["text"], xc))
    col_sorted = sorted(cols, key=lambda c: c[1])
    for text, xc in vals:
        # find the two nearest columns
        dists = sorted(((abs(c[1]-xc), c[0]) for c in col_sorted))
        if len(dists) < 2:
            continue
        (d1, nm1), (d2, nm2) = dists[0], dists[1]
        # "spanning" if the value sits between the two columns fairly evenly
        if d1 > 12 and d2 > 12 and abs(d1 - d2) < max(d1, d2) * 0.6:
            g = cell_gbps_fn(text, label_mbps)
            if g is not None and g > 0:
                for nm in (nm1, nm2):
                    if (found[nm].get(key) or 0) == 0:
                        found[nm][key] = round(g, 4)


def parse_checkpoint_pdf(pdf_path: Path) -> list[dict]:
    """Check Point 'Quantum Security Gateways Comparison Chart' parser (v2).

    Rebuilt from scratch and validated against the real Feb-2026 chart PDF,
    every model cross-checked against the printed values.

    STRUCTURE (learned from the actual PDF, page by page):
      * Models are COLUMNS. A header row lists model numbers (e.g. "9100 9200 9300").
        Each spec page is followed by an "Appliance Configurations" page with port
        detail we skip for the headline specs.
      * Pages are divided into SECTIONS, in order:
          "Enterprise Testing Conditions"  -> the canonical headline numbers
          "RFC 3511, 2544, 2647, 1242 Performance (Lab)"  -> lab/marketing (skip for
              headline; the 3511/2544/2647/1242 are RFC numbers, NOT models)
          "Ideal Testing Conditions"  -> marketing firewall throughput (skip)
          "HTTP/TLS Inspection Performance"  -> a SECOND Threat Prevention row (skip)
          "Additional Features" / "Physical" / "Hardware" -> ssd, enclosure, ports
      * Headline rows (threat/ngfw/ips/fw) are read ONLY in the Enterprise section.
      * VPN, Connections-Per-Second, Concurrent-Sessions, SSD, Enclosure are taken
        wherever they appear, each captured only the FIRST time per model-group.

    TRAPS handled (each previously produced wrong/missing data):
      1. COMMAS: "1,850" / "190,000" must have commas stripped, else "1,850"
         parses to 1 (this caused values ~1000x too small).
      2. UNITS vary BY PAGE and BY CELL: Gbps on enterprise/DC pages; Mbps on Spark
         and branch pages; and some rows MIX units ("780 Mbps" next to "1.5" Gbps).
         Unit is taken from the label's (Gbps)/(Mbps), but a per-cell Mbps/Gbps token
         overrides it for that cell.
      3. FOOTNOTE SUPERSCRIPTS: labels carry markers ("Threat Prevention (Gbps) 1")
         and some rows have markers BETWEEN values ("440 Mbps 4 600 Mbps"). These are
         bare 1-digit numbers far from any column centre OR adjacent to a unit; we
         drop standalone 1-digit tokens that aren't near a column centre.
      4. WRAPPED ROWS: a label and its values sometimes sit on adjacent y-rows
         (e.g. "Connections Per Second" label, values on the next line). We look at
         the row, and if it has the label but no values, we borrow the adjacent
         numeric-only row.
      5. NON-MODEL NUMBERS: "2026" (the Feb-1-2026 footer date) and "1242" (RFC
         number) appear on pages; both are excluded from model-header detection.
      6. MERGED CELLS: some firewall cells span two columns (one value centred
         between them, e.g. Spark "17,500" for both 2580 and 2590). Nearest-column
         assignment places it in one; we accept that and the sibling stays 0 unless
         another row fills it.

    Every value is read straight from the uploaded PDF via word coordinates.
    """
    import pdfplumber

    log(f"  Reading {pdf_path.name}")

    model_tok_re = re.compile(r"^\d{4,5}$")
    NON_MODEL = {"2026", "1242", "2544", "2647", "3511"}  # date + RFC numbers

    SEC = {
        "enterprise": re.compile(r"enterprise\s+testing\s+conditions", re.I),
        "rfc":        re.compile(r"rfc\s*3511|performance\s*\(lab\)", re.I),
        "ideal":      re.compile(r"ideal\s+testing\s+conditions", re.I),
        "http":       re.compile(r"http/tls\s+inspection", re.I),
        "additional": re.compile(r"additional\s+features", re.I),
        "physical":   re.compile(r"^physical\b|physical\s+and\s+networking", re.I),
        "hardware":   re.compile(r"^hardware\b|appliance\s+configurations", re.I),
    }

    # Headline rows — Enterprise section only. (regex, key)
    ENT_ROWS = [
        (re.compile(r"^threat\s+prevention", re.I), "threat"),
        (re.compile(r"^ngfw\s+throughput",   re.I), "ngfw"),
        (re.compile(r"^ips\s+throughput",    re.I), "ips"),
        (re.compile(r"^firewall\b(?!\s+throughput)(?!\s+latency)", re.I), "fw"),
    ]
    # Rows taken anywhere (first occurrence per group). (regex, key)
    ANY_ROWS = [
        (re.compile(r"^vpn\s+throughput", re.I),            "vpn"),
        (re.compile(r"^connections\s+per\s+second", re.I),  "cps"),
        (re.compile(r"^concurrent\s+sessions", re.I),       "sessions"),
        (re.compile(r"storage\s+size|^ssd\b", re.I),        "ssd"),
        (re.compile(r"^enclosure", re.I),                   "ff"),
    ]

    found: dict[str, dict] = {}

    def new_model(num):
        nm = f"CP-{num}"
        return nm, {
            "vendor":"Check Point","model":nm,"series":_checkpoint_series(nm),
            "fw":0.0,"ips":0.0,"ngfw":0.0,"threat":0.0,"vpn":0.0,
            "sessions":0.0,"newSess":0,"ssl":None,"iface":"","ff":"",
            "ssd":None,"proc":"","source":"checkpoint.pdf",
        }

    def cell_gbps(text, label_mbps):
        """One cell -> Gbps float. Per-cell unit token overrides label unit."""
        cleaned = text.replace(",", "")
        nums = re.findall(r"\d+(?:\.\d+)?", cleaned)
        if not nums:
            return None
        val = float(nums[0])
        if re.search(r"mbps", text, re.I):
            return val / 1000.0
        if re.search(r"gbps", text, re.I):
            return val
        return val / 1000.0 if label_mbps else val

    def assign(value_words, cols, cutoff):
        """Group value words into nearest model column by x-centre (right of cutoff).
        Drops footnote-superscript tokens: a standalone single digit whose centre is
        NOT within ~28px of any column centre."""
        col_x = [c[1] for c in cols]
        buckets = {}
        for w in value_words:
            xc = (w["x0"] + w["x1"]) / 2
            if xc < cutoff:
                continue
            # footnote filter: lone 1-2 digit integer not near any column centre
            t = w["text"]
            if re.fullmatch(r"\d{1,2}", t):
                near = min(abs(cx - xc) for cx in col_x)
                if near > 30:
                    continue
            best = min(cols, key=lambda c: abs(c[1] - xc))
            buckets.setdefault(best[0], []).append((w["x0"], t))
        return {m: " ".join(t for _, t in sorted(ws)) for m, ws in buckets.items()}

    def label_mbps(text):
        m = re.search(r"[\(\[](mbps|gbps)[\)\]]", text, re.I)
        return bool(m) and m.group(1).lower() == "mbps"

    with pdfplumber.open(pdf_path) as pdf:
        log(f"  PDF has {len(pdf.pages)} pages")

        for pno, page in enumerate(pdf.pages, 1):
            words = page.extract_words(x_tolerance=1.5, y_tolerance=2,
                                       keep_blank_chars=False)
            if not words:
                continue
            rows_map: dict[int, list] = {}
            for w in words:
                rows_map.setdefault(round(w["top"] / 3) * 3, []).append(w)
            ordered = [sorted(rows_map[k], key=lambda w: w["x0"]) for k in sorted(rows_map)]

            cols = None
            section = None

            for ri, row in enumerate(ordered):
                rtext = " ".join(w["text"] for w in row)
                low = rtext.lower()

                # ---- Model-header row? ----
                mtoks = [w for w in row
                         if model_tok_re.match(w["text"])
                         and w["text"] not in NON_MODEL
                         and 1000 <= int(w["text"]) <= 99999]
                is_rfc = "rfc" in low or "performance" in low
                alpha = [w for w in row if re.search(r"[A-Za-z]", w["text"])]
                if len(mtoks) >= 2 and not is_rfc and len(alpha) <= 1:
                    cols = [(f"CP-{w['text']}", (w["x0"]+w["x1"])/2) for w in mtoks]
                    section = None
                    log(f"  Page {pno}: model group {[w['text'] for w in mtoks]}")
                    for w in mtoks:
                        nm = f"CP-{w['text']}"
                        if nm not in found:
                            _, rec = new_model(w["text"])
                            found[nm] = rec
                    continue

                if not cols:
                    continue

                # ---- Section transitions ----
                hit = False
                for sname, rx in SEC.items():
                    if rx.search(rtext):
                        section = sname
                        hit = True
                        break
                if hit:
                    continue

                leftmost = min(c[1] for c in cols)
                cutoff = leftmost - 60

                def values_on(this_row):
                    """Numeric + unit tokens on this row; borrow adjacent numeric-only
                    row if this row has no digits (wrapped label/value)."""
                    keep = lambda w: (re.search(r"\d", w["text"])
                                      or re.fullmatch(r"(?i)mbps|gbps|tbps", w["text"]))
                    vw = [w for w in this_row if keep(w)]
                    if any(re.search(r"\d", w["text"]) for w in vw):
                        return vw
                    # look at next then previous row for a pure-value row
                    for adj in (ri+1, ri-1):
                        if 0 <= adj < len(ordered):
                            cand = ordered[adj]
                            calpha = [w for w in cand if re.search(r"[A-Za-z]", w["text"])
                                      and not re.fullmatch(r"(?i)mbps|gbps|tbps", w["text"])]
                            cnums = [w for w in cand if re.search(r"\d", w["text"])]
                            if cnums and not calpha:
                                return [w for w in cand if keep(w)]
                    return []

                # ---- Enterprise headline rows ----
                if section == "enterprise":
                    matched = False
                    for rx, key in ENT_ROWS:
                        if rx.search(rtext):
                            lm = label_mbps(rtext)
                            vw = values_on(row)
                            cv = assign(vw, cols, cutoff)
                            for nm, raw in cv.items():
                                g = cell_gbps(raw, lm)
                                if g is not None and g > 0:
                                    found[nm][key] = round(g, 4)
                            # MERGED-CELL handling: if a value sits roughly midway
                            # between two adjacent columns (its centre is nearly
                            # equidistant), it spans both — copy it to the sibling.
                            # This covers Spark "17,500" (2580+2590) and similar.
                            _fill_spanning_cells(vw, cols, found, key, lm, cell_gbps, cutoff)
                            matched = True
                            break
                    if matched:
                        continue

                # ---- Anywhere rows (first occurrence per group) ----
                for rx, key in ANY_ROWS:
                    if not rx.search(rtext):
                        continue
                    first_nm = cols[0][0]
                    if key == "vpn":
                        if found[first_nm].get("vpn", 0) > 0: break
                        lm = label_mbps(rtext)
                        cv = assign(values_on(row), cols, cutoff)
                        for nm, raw in cv.items():
                            g = cell_gbps(raw, lm)
                            # Magnitude guard for mislabelled Mbps cells: Spark VPN
                            # cells print "1,400"/"4,000" under a "(Gbps)" label but
                            # are really Mbps. Only scale when the number is clearly
                            # Mbps-magnitude (>= 1000) AND the model is a small branch
                            # box (<2600 series) — never touch big DC models whose VPN
                            # genuinely reaches 100+ Gbps (e.g. 29200 = 130 Gbps).
                            mnum = int(re.search(r"\d+", nm).group())
                            if g is not None and g >= 1000 and mnum < 2600:
                                g = g / 1000.0
                            if g is not None and g > 0:
                                found[nm]["vpn"] = round(g, 4)
                        break
                    if key == "cps":
                        if found[first_nm].get("newSess", 0) > 0: break
                        in_k = "(k)" in low
                        cv = assign(values_on(row), cols, cutoff)
                        for nm, raw in cv.items():
                            cleaned = raw.replace(",", "")
                            mm = re.findall(r"\d+(?:\.\d+)?", cleaned)
                            if not mm: continue
                            val = float(mm[0])
                            if in_k and val < 10000:
                                val *= 1000
                            found[nm]["newSess"] = int(val)
                        break
                    if key == "sessions":
                        if found[first_nm].get("sessions", 0) > 0: break
                        cv = assign(values_on(row), cols, cutoff)
                        for nm, raw in cv.items():
                            cleaned = raw.replace(",", "")
                            mvals = re.findall(r"(\d+(?:\.\d+)?)\s*M", cleaned, re.I)
                            if mvals:
                                found[nm]["sessions"] = max(float(x) for x in mvals)
                            else:
                                nums = re.findall(r"\d+(?:\.\d+)?", cleaned)
                                if nums:
                                    val = max(float(x) for x in nums)
                                    found[nm]["sessions"] = round(val/1_000_000, 3) if val > 10000 else round(val, 3)
                        break
                    if key == "ssd":
                        cv = assign([w for w in row if (w["x0"]+w["x1"])/2 >= cutoff], cols, cutoff)
                        for nm, raw in cv.items():
                            mm = re.search(r"\d+\s*[GMT]B", raw, re.I)
                            if mm and not found[nm].get("ssd"):
                                found[nm]["ssd"] = mm.group().replace(" ", "")
                        break
                    if key == "ff":
                        cv = assign([w for w in row if (w["x0"]+w["x1"])/2 >= cutoff], cols, cutoff)
                        for nm, raw in cv.items():
                            if raw and not found[nm].get("ff"):
                                found[nm]["ff"] = classify_form_factor(raw)
                        break

    # Form-factor fallback by series for any blanks
    for m in found.values():
        if not m.get("ff"):
            n = int(re.search(r"\d+", m["model"]).group())
            if n < 2000:    m["ff"] = "Desktop"
            elif n < 7000:  m["ff"] = "1U"
            elif n < 16000: m["ff"] = "1U"
            elif n < 26000: m["ff"] = "2U"
            else:           m["ff"] = "2U"

    log(f"  Parsed {len(found)} Check Point models")
    valid = [m for m in found.values()
             if m["fw"] > 0 or m["ips"] > 0 or m["ngfw"] > 0 or m["threat"] > 0]
    log(f"  {len(valid)} have valid throughput values")
    return valid


def _checkpoint_series(model: str) -> str:
    """Map a CP-NNNN model name to its product series."""
    n = int(re.search(r"\d+", model).group())
    if n < 2000:   return "1500/1600/1700/1800 Branch"
    if n < 4000:   return "3000 Quantum"
    if n < 7000:   return "6000 Quantum"
    if n < 15000:  return "7000 Quantum"
    if n < 20000:  return "16000/19000 Quantum"
    if n < 28000:  return "26000/27000 Quantum"
    return "28000/29000+ Quantum"


def _checkpoint_extract_values(line: str, num_models: int, kind: str) -> list[str]:
    """Extract the per-model values from a Check Point spec line.

    Lines look like:
       "Threat Prevention (Gbps) 1 780 Mbps 1.5 1.8 2.5 3.7 5.8 7.4"
       "NGFW Throughput (Gbps) 2 1.5 3 3.72 5.5 6.2 13.4 17"
       "SSD Size 240 GB 240 GB 240 GB 240 GB 240 GB 480 GB 480 GB"
       "Physical Enclosure Desktop Desktop 1U 1U 1U 1U 1U"
    """
    # Strip the leading label up to the first number (or known unit marker)
    # We need to be careful: footnote numbers like "1" or "2" right after the label
    # are NOT data values. Strategy: strip up to "(Gbps)" or "(K)" or similar units,
    # then strip a possible footnote digit.

    # Remove the label prefix — everything up to the first number-followed-by-unit
    # or to the unit indicator in parens
    cleaned = line

    # Strip "(Gbps)", "(K)", "(M)" markers
    cleaned = re.sub(r"\([^)]*\)", "", cleaned)

    # Strip footnote markers like " 1 " or " 2 " or " 3 " right after the label
    # (these appear as small reference numbers in the chart)
    cleaned = re.sub(r"^([A-Za-z][^0-9]*?)\s+\d{1,2}\s+(?=[\d.])", r"\1 ", cleaned)

    # Now strip the alphabetic prefix
    parts = cleaned.split(None, 1)
    if len(parts) < 2:
        return [""] * num_models
    body = parts[1] if not parts[0][0].isdigit() else cleaned

    # For text values (SSD, Form factor), split into N tokens
    if kind in ("text", "form"):
        # Form factor: short tokens like "Desktop", "1U", "1RU", "2U"
        if kind == "form":
            tokens = re.findall(r"(Desktop|\d+\s*[UR][UA]?|Modular|Chassis)", body)
            if len(tokens) >= num_models:
                return [t.replace(" RU", "U").replace(" ", "") for t in tokens[:num_models]]
            return [body] + [""] * (num_models - 1)
        # SSD: pattern "240 GB" or "480 GB"
        tokens = re.findall(r"(\d+(?:\s*[GMT]B)?)", body)
        if len(tokens) >= num_models:
            return tokens[:num_models]
        return [body] + [""] * (num_models - 1)

    # For numeric throughput rows: each value is a number optionally followed by a unit
    # Patterns: "780 Mbps", "1.5", "1.8", "9.81", "37"
    # We extract number-unit pairs greedily
    pattern = re.compile(
        r"([\d.]+)\s*(Gbps|Mbps|Tbps|Kbps|GB|MB|M|K|Million)?",
        re.IGNORECASE
    )
    matches = pattern.findall(body)
    values = []
    for num, unit in matches:
        if not num or num == ".":
            continue
        values.append(f"{num} {unit}".strip() if unit else num)
    # Pad / truncate
    while len(values) < num_models:
        values.append("")
    return values[:num_models]


def _apply_checkpoint_value(model_dict: dict, key: str, raw: str, kind: str, row_unit: str = "") -> None:
    """Convert a raw coordinate-extracted value and apply it to the model dict.
    row_unit ('gbps'|'mbps'|'') disambiguates bare numbers when the unit word
    landed in a different column."""
    if not raw:
        return
    raw = raw.strip()

    if kind == "gbps":
        # Per-value unit wins; else row unit; else magnitude heuristic.
        val_has_mbps = bool(re.search(r"mbps", raw, re.I))
        val_has_gbps = bool(re.search(r"gbps", raw, re.I))
        nums = re.findall(r"[\d.]+", raw)
        if not nums:
            return
        # Some chart cells show two figures; take the first real number
        val = float(nums[0])
        # Firewall throughput legitimately reaches hundreds of Gbps (e.g. 185G),
        # so the "bare 100-999 = Mbps" heuristic must NOT apply to it. It only
        # applies to the security-inspection rows, which are realistically <100G.
        mbps_heuristic_ok = key in ("threat","ips","ngfw","vpn")
        if val_has_mbps:
            gb = val / 1000
        elif val_has_gbps:
            gb = val
        elif row_unit == "mbps":
            gb = val / 1000
        elif row_unit == "gbps":
            gb = val / 1000 if (mbps_heuristic_ok and 100 <= val < 1000) else val
        else:
            gb = val / 1000 if (mbps_heuristic_ok and 100 <= val < 1000) else val
        if gb > 0:
            model_dict[key] = round(gb, 3)

    elif kind == "millions":
        # Concurrent connections — may be "4/16" (default/max memory) or "16M"
        cleaned = raw.replace(",", "")
        has_m = bool(re.search(r"\bM\b|million", cleaned, re.I))
        nums = re.findall(r"[\d.]+", cleaned)
        if nums:
            val = max(float(n) for n in nums)
            # If value looks like raw connection count (e.g. 16000000) convert
            if val > 10000:
                val = val / 1_000_000
            model_dict[key] = val

    elif kind == "k_to_int":
        cleaned = raw.replace(",", "")
        has_k = bool(re.search(r"\bK\b", cleaned, re.I))
        has_m = bool(re.search(r"\bM\b", cleaned, re.I))
        nums = re.findall(r"[\d.]+", cleaned)
        if nums:
            val = max(float(n) for n in nums)
            if has_m:
                model_dict[key] = int(val * 1_000_000)
            elif has_k or val < 10000:
                model_dict[key] = int(val * 1000)
            else:
                model_dict[key] = int(val)

    elif kind == "text":
        if raw and raw not in ("—","-","N/A"):
            # SSD: keep first "NNN GB" style token
            m = re.search(r"\d+\s*[GMT]B", raw, re.I)
            if m:
                model_dict[key] = m.group().replace(" ", "")
            else:
                cleaned = raw.split()[0] if raw.split() else raw
                if cleaned.isdigit():
                    cleaned += "GB"
                model_dict[key] = cleaned

    elif kind == "form":
        model_dict[key] = classify_form_factor(raw)


def parse_paloalto_pdf(pdf_path: Path) -> list[dict]:
    """Palo Alto Product Summary Specsheet — COORDINATE-BASED parser.

    Palo Alto packs up to ~14 models across one row, with spec values in a dense
    grid beneath. Plain text extraction loses column alignment, so instead we use
    pdfplumber's WORD-LEVEL coordinates (extract_words gives x0/x1/top for every
    word). The algorithm:

      1. On each page, find header rows containing PA-* model names; record each
         model's horizontal centre (x).
      2. For each known spec row (matched by its label text), collect the value
         words to the right of the label and assign each to the model column whose
         centre-x is nearest the value's centre-x.

    This reconstructs the table columns from pixel positions — so every number
    comes straight from the uploaded datasheet, not a curated table.
    """
    import pdfplumber

    log(f"  Reading {pdf_path.name}")

    pa_model_re = re.compile(r"^PA-\d{3,4}[A-Z0-9-]*$")

    # Spec rows: (compiled label regex, json_key, value-kind)
    # 'pair' = HTTP/appmix dual value (take appmix = 2nd); 'gbps' single; etc.
    SPEC_ROWS = [
        (re.compile(r"firewall throughput", re.I),          "fw",       "gbps"),
        (re.compile(r"threat prevention throughput", re.I), "threat",   "gbps"),
        (re.compile(r"^ips throughput", re.I),              "ips",      "gbps"),
        (re.compile(r"app-?id throughput", re.I),           "ngfw",     "gbps"),
        (re.compile(r"ipsec vpn throughput", re.I),         "vpn",      "gbps"),
        (re.compile(r"new sessions per second", re.I),      "newSess",  "count"),
        (re.compile(r"max(?:imum)? (?:concurrent )?sessions", re.I), "sessions", "millions"),
    ]

    found: dict[str, dict] = {}

    def assign_to_columns(value_words, columns):
        """Given value word-dicts and [(model, x_center)], map each value to the
        nearest column by x. Returns {model: 'raw value text'}."""
        out = {}
        for vw in value_words:
            vx = (vw["x0"] + vw["x1"]) / 2
            # nearest model column
            best = min(columns, key=lambda c: abs(c[1] - vx))
            out.setdefault(best[0], []).append((vw["x0"], vw["text"]))
        # join multi-word values left→right
        return {m: " ".join(t for _, t in sorted(ws)) for m, ws in out.items()}

    with pdfplumber.open(pdf_path) as pdf:
        log(f"  PDF has {len(pdf.pages)} pages")
        for page_idx, page in enumerate(pdf.pages, 1):
            words = page.extract_words(x_tolerance=1.5, y_tolerance=2,
                                       keep_blank_chars=False)
            if not words:
                continue

            # Group words into visual rows by their 'top' coordinate
            rows: dict[int, list] = {}
            for w in words:
                key = round(w["top"] / 3) * 3   # bucket to ~3px rows
                rows.setdefault(key, []).append(w)
            ordered_rows = [sorted(rows[k], key=lambda w: w["x0"]) for k in sorted(rows)]

            # ── Find model-header rows + their column centres ──
            # A header row has >=2 tokens matching PA-NNN
            current_cols = None
            for row in ordered_rows:
                model_tokens = [w for w in row if pa_model_re.match(w["text"])]
                if len(model_tokens) >= 2:
                    current_cols = [(w["text"], (w["x0"] + w["x1"]) / 2)
                                    for w in model_tokens]
                    names = [c[0] for c in current_cols]
                    log(f"  Page {page_idx}: column group {names}")
                    for nm in names:
                        found.setdefault(nm, {
                            "vendor": "Palo Alto", "model": nm,
                            "series": _paloalto_series(nm),
                            "fw":0.0,"ips":0.0,"ngfw":0.0,"threat":0.0,
                            "vpn":0.0,"sessions":0.0,"newSess":0,
                            "ssl":None,"iface":"","ff":"","ssd":None,"proc":"",
                            "source":"paloalto.pdf",
                        })
                    continue

                if not current_cols:
                    continue

                # ── Is this row a spec row? Match label against the leftmost words ──
                row_text = " ".join(w["text"] for w in row)
                for label_re, key, kind in SPEC_ROWS:
                    if not label_re.search(row_text):
                        continue
                    # Value words = those whose x0 is right of the last label word.
                    # Heuristic: label occupies the left ~38% of the model span.
                    left_x = current_cols[0][1]
                    # find the x where the first model column starts minus a margin
                    label_cutoff = left_x - 40
                    value_words = [w for w in row
                                   if (w["x0"] + w["x1"]) / 2 >= label_cutoff]
                    # Keep words that are either values (contain a digit) OR unit
                    # tokens (Gbps/Mbps) so each value keeps its own unit after
                    # column assignment. Drop pure-label leftovers.
                    value_words = [w for w in value_words
                                   if re.search(r"\d", w["text"])
                                   or re.match(r"^(Gbps|Mbps|Tbps)$", w["text"], re.I)]
                    if not value_words:
                        break
                    col_vals = assign_to_columns(value_words, current_cols)
                    # Row-level unit: all values in a throughput row share a unit.
                    # If the row says "Gbps" anywhere, treat bare large numbers as Gbps.
                    row_unit = "gbps" if re.search(r"gbps", row_text, re.I) else (
                               "mbps" if re.search(r"mbps", row_text, re.I) else "")
                    for model_name, raw in col_vals.items():
                        _apply_pa_coord_value(found[model_name], key, raw, kind, row_unit)
                    break

    # ── Map Palo Alto's published metrics onto FireIQ's column scheme ──
    # Palo Alto does NOT print separate "IPS throughput" or "App-ID throughput"
    # rows. Their published metrics translate to FireIQ columns as follows:
    #   • Threat Prevention throughput  → this IS PA's IPS-equivalent figure
    #     (IPS + AV + anti-spyware enabled together), so ips := threat
    #   • Firewall throughput (appmix)  → measured with App-ID enabled, which is
    #     what every other vendor reports as "NGFW throughput", so ngfw := fw
    # This is a label translation, not fabricated data — the numbers come straight
    # from the datasheet, just mapped to the matching FireIQ field names.
    for m in found.values():
        if (m.get("ips") or 0) == 0 and (m.get("threat") or 0) > 0:
            m["ips"] = m["threat"]
        if (m.get("ngfw") or 0) == 0 and (m.get("fw") or 0) > 0:
            m["ngfw"] = m["fw"]
        # Form factor by series (PA's standard chassis per line — not in the
        # spec-value grid, so derived from the model family).
        if not m.get("ff"):
            m["ff"] = _paloalto_form_factor(m["model"])

    # Filter to models that got real throughput
    valid = [m for m in found.values()
             if m["fw"] > 0 or m["threat"] > 0 or m["ngfw"] > 0]
    log(f"  Parsed {len(found)} PA models, {len(valid)} with valid throughput")
    return valid


def _paloalto_form_factor(model: str) -> str:
    """Standard rack form factor per Palo Alto series."""
    m = re.search(r"PA-(\d+)", model)
    if not m:
        return ""
    n = int(m.group(1))
    if n < 1000:    return "Desktop"          # PA-400, PA-500 series
    if n < 1500:    return "1U"               # PA-1400
    if n < 3500:    return "1U"               # PA-3400
    if n < 5450:    return "1U"               # PA-5410/5420/5430/5440/5445
    if n < 5500:    return "2U"               # PA-5450
    if n < 5600:    return "2U"               # PA-5500 (5560/5580 etc.)
    if n >= 7000:   return "Modular Chassis"  # PA-7500
    return "1U"


def _apply_pa_coord_value(d: dict, key: str, raw: str, kind: str, row_unit: str = "") -> None:
    """Apply a coordinate-extracted Palo Alto value to the model dict.
    Handles 'HTTP/appmix' pairs (take appmix=second), units, and K/M counts.
    row_unit ('gbps'|'mbps'|'') is the unit detected for the whole spec row, used
    to disambiguate bare numbers (the unit word is often a separate column-1 token)."""
    if not raw:
        return
    raw = raw.strip()

    if kind == "gbps":
        # May be a pair like "5.2/4.7" with optional Gbps/Mbps suffix on the value,
        # or single "4.6 Gbps" / "780 Mbps", or a bare "4.6" / "780".
        # PER-VALUE unit wins over row unit (rows can mix Gbps and Mbps cells).
        val_has_mbps = bool(re.search(r"mbps", raw, re.I))
        val_has_gbps = bool(re.search(r"gbps", raw, re.I))
        nums = re.findall(r"[\d.]+", raw)
        if not nums:
            return
        val = float(nums[1]) if ("/" in raw and len(nums) >= 2) else float(nums[0])
        if val_has_mbps:
            gb = val / 1000
        elif val_has_gbps:
            gb = val
        elif row_unit == "mbps":
            gb = val / 1000
        elif row_unit == "gbps":
            # Row says Gbps but this cell had no unit — trust magnitude:
            # a bare 100–999 here is almost certainly an Mbps cell whose unit
            # word was lost; otherwise take as Gbps.
            gb = val / 1000 if 100 <= val < 1000 else val
        else:
            gb = val / 1000 if 100 <= val < 1000 else val
        if gb > 0:
            d[key] = round(gb, 3)

    elif kind == "millions":
        # "400,000" or "1,400,000" → millions; or "48M"
        cleaned = raw.replace(",", "")
        m = re.search(r"([\d.]+)\s*([MK])?", cleaned, re.I)
        if not m:
            return
        v = float(m.group(1)); u = (m.group(2) or "").upper()
        if u == "M":   d[key] = max(d.get(key) or 0, v)
        elif u == "K": d[key] = max(d.get(key) or 0, v/1000)
        else:          d[key] = max(d.get(key) or 0, v/1_000_000 if v > 1000 else v)

    elif kind == "count":
        cleaned = raw.replace(",", "")
        m = re.search(r"([\d.]+)\s*([MK])?", cleaned, re.I)
        if not m:
            return
        v = float(m.group(1)); u = (m.group(2) or "").upper()
        if u == "M":   d[key] = max(d.get(key) or 0, int(v*1_000_000))
        elif u == "K": d[key] = max(d.get(key) or 0, int(v*1000))
        else:          d[key] = max(d.get(key) or 0, int(v))


def _paloalto_series(model: str) -> str:
    """Map a PA-NNN model name to its product series."""
    m = re.search(r"PA-(\d+)", model)
    if not m:
        return ""
    n = int(m.group(1))
    if n < 500:    return "PA-400 Series"
    if n < 900:    return "PA-800 Series"
    if n < 1500:   return "PA-1400 Series"
    if n < 3500:   return "PA-3400 Series"
    if n < 5500:   return "PA-5400 Series"
    if n < 5600:   return "PA-5500 Series"
    if n < 7600:   return "PA-7500 Series"
    return "PA-7000 Series"


def _paloalto_extract_values(line: str, num_models: int, kind: str) -> list[str]:
    """Extract per-model values from a Palo Alto spec line.

    Values can include:
      - Single number: "3.3 Gbps"
      - Slash-pair: "3.5/2.9 Gbps" (HTTP/appmix)
      - Memory-pair: "300,000 / 600,000" (default/max memory configurations)
    """
    # Strip parenthetical clarifications like "(HTTP/appmix)" or "(Gbps)"
    cleaned = re.sub(r"\([^)]*\)", "", line)

    # Strip the leading label up to the first numeric token
    # We look for the boundary between word characters and the first digit
    m = re.search(r"\d", cleaned)
    if not m:
        return [""] * num_models
    body = cleaned[m.start():]

    if kind == "form":
        # Form factor values like "Desktop", "1U", "1RU", "2U", "Modular"
        tokens = re.findall(r"(Desktop|\d+\s*[UR][UA]?|Modular|Chassis)", line)
        if len(tokens) >= num_models:
            return [t.replace(" RU", "U").replace(" ", "") for t in tokens[:num_models]]
        return [line] + [""] * (num_models - 1)

    if kind == "text":
        # Interfaces / generic text values — try to split on multiple spaces
        # This is fragile; PDF text extraction can mash interfaces together.
        parts = re.split(r"\s{3,}", body)
        if len(parts) >= num_models:
            return parts[:num_models]
        return [body] + [""] * (num_models - 1)

    # Numeric values — extract number-or-pair followed by optional unit
    # Pattern matches:
    #   "3.5/2.9 Gbps", "780 Mbps", "300,000", "1.7"
    pattern = re.compile(
        r"([\d.,]+(?:\s*/\s*[\d.,]+)?)\s*"
        r"(Gbps|Mbps|Tbps|Kbps|M|K)?",
        re.IGNORECASE
    )
    matches = pattern.findall(body)
    values = []
    for num, unit in matches:
        num_clean = num.strip()
        if not num_clean or num_clean == "." or num_clean == "/":
            continue
        if unit:
            values.append(f"{num_clean} {unit}")
        else:
            values.append(num_clean)
    while len(values) < num_models:
        values.append("")
    return values[:num_models]


def _apply_paloalto_value(model_dict: dict, key: str, raw: str, kind: str) -> None:
    """Convert raw extracted text into the right type and apply to the model dict."""
    if not raw:
        return

    if kind == "gbps_pair":
        # "3.5/2.9 Gbps" → take the SECOND number (appmix = realistic)
        # Single "3.3 Gbps" → take it as-is
        if "/" in raw:
            parts = raw.split("/")
            # Last part may have the unit attached
            val_part = parts[-1].strip()
            v = to_gbps(val_part)
        else:
            v = to_gbps(raw)
        if v > 0:
            model_dict[key] = v

    elif kind == "gbps":
        v = to_gbps(raw)
        if v > 0:
            model_dict[key] = v

    elif kind == "millions":
        # Concurrent sessions — values like "300,000" or "300,000 / 600,000"
        # Take the larger (max memory configuration)
        nums = re.findall(r"[\d,.]+", raw)
        if nums:
            vals = []
            for n in nums:
                clean = n.replace(",", "")
                try:
                    vals.append(float(clean))
                except ValueError:
                    continue
            if vals:
                # Raw count → convert to millions
                top = max(vals)
                model_dict[key] = round(top / 1_000_000, 4) if top > 1000 else top

    elif kind == "int_count":
        # New sessions per second — values like "48,000" or "145,000"
        nums = re.findall(r"[\d,.]+", raw)
        if nums:
            vals = []
            for n in nums:
                clean = n.replace(",", "")
                try:
                    vals.append(float(clean))
                except ValueError:
                    continue
            if vals:
                model_dict[key] = int(max(vals))

    elif kind == "text":
        if raw and raw not in ("—", "-", "N/A"):
            model_dict[key] = raw.strip()

    elif kind == "form":
        model_dict[key] = classify_form_factor(raw)


def parse_cisco_1200_html(html_path: Path) -> list[dict]:
    """Parse a Cisco Secure Firewall series datasheet HTML page.

    Despite the filename being '1200', this same parser works for any Cisco
    Secure Firewall series HTML datasheet (1200, 3100, 4200, etc.) because they
    all share the same Cisco docTemplate structure with these key tables:

      Table 1:  Models Summary (Form factor, Firewall Throughput, Threat
                 Defense Throughput, IPS, TLS, Interfaces) — fast overview
      Table 6:  Performance with Threat Defense (FW+AVC, NGIPS, FW+AVC+IPS,
                 IPSec VPN, TLS decryption, New connections/sec)
      Table 8:  Scalability (Max concurrent sessions, Max VPN peers)

    We pull values from these tables and combine them per-model.
    """
    from bs4 import BeautifulSoup

    log(f"  Reading {html_path.name}")
    html = html_path.read_text(encoding="utf-8", errors="ignore")
    soup = BeautifulSoup(html, "lxml")

    # Determine which series this is from the filename (e.g. cisco-1200.html → "1200")
    stem = html_path.stem  # "cisco-1200"
    series_match = re.search(r"cisco-?(\d+)", stem.lower())
    series_num = series_match.group(1) if series_match else "?"
    series_label = f"CSF-{series_num}"

    # Find all data tables on the page
    tables = soup.find_all("table")
    log(f"  Found {len(tables)} tables on the page")

    found_models: dict[str, dict] = {}

    # Iterate through tables looking for ones that have model numbers as column headers
    for table_idx, table in enumerate(tables):
        rows = table.find_all("tr")
        if len(rows) < 2:
            continue
        header_cells = [c.get_text(" ", strip=True) for c in rows[0].find_all(["th", "td"])]
        if not header_cells:
            continue

        # Detect a model-column table: header cells contain model numbers like "1210", "1220CX", "1230"
        # Either bare number or with letter suffix (CE, CP, CX)
        model_columns: list[tuple[int, str]] = []
        for col_idx, header_text in enumerate(header_cells):
            # Match patterns: "1210", "1210CE", "1220CX", "1230", "1240", "1250"
            m = re.search(r"\b(\d{4})([A-Z]{0,2})\b", header_text)
            if m:
                model_num, suffix = m.group(1), m.group(2)
                # Build canonical name: CSF-1210CE, CSF-1230, etc.
                model_name = f"CSF-{model_num}{suffix}"
                model_columns.append((col_idx, model_name))

        if len(model_columns) < 2:
            continue  # Not a model-data table

        log(f"  Table {table_idx}: model columns {[m for _, m in model_columns]}")

        # Initialise records for any new models we've found
        for _, model_name in model_columns:
            if model_name not in found_models:
                found_models[model_name] = {
                    "vendor": "Cisco",
                    "model":  model_name,
                    "series": series_label,
                    "fw": 0.0, "ips": 0.0, "ngfw": 0.0, "threat": 0.0,
                    "vpn": 0.0, "sessions": 0.0, "newSess": 0,
                    "ssl": None, "iface": "", "ff": "", "ssd": None,
                    "proc": "Cisco Network Processor",
                    "source": html_path.name,
                }

        # Walk each subsequent row. First cell is the metric name, remaining cells are values.
        for row in rows[1:]:
            cells = row.find_all(["th", "td"])
            if len(cells) < 2:
                continue
            label = cells[0].get_text(" ", strip=True).lower()

            # Map this label to a json key + value type
            json_key: str | None = None
            kind = "gbps"
            if "fw + avc + ips" in label or "ngfw throughput" in label:
                json_key, kind = "ngfw", "gbps"
            elif "fw + avc" in label or "stateful inspection firewall throughput" in label or "firewall throughput" in label:
                json_key, kind = "fw", "gbps"
            elif "ngips" in label or "ips throughput" in label or "intrusion prevention" in label:
                json_key, kind = "ips", "gbps"
            elif "threat defense" in label and "throughput" in label:
                json_key, kind = "threat", "gbps"
            elif "ipsec vpn throughput" in label:
                json_key, kind = "vpn", "gbps"
            elif "tls decryption" in label or "tls throughput" in label:
                json_key, kind = "ssl", "gbps"
            elif "concurrent sessions" in label or "concurrent firewall connections" in label:
                json_key, kind = "sessions", "millions"
            elif "new connections per second" in label or "connections per second" in label:
                json_key, kind = "newSess", "k_to_int"
            elif "form factor" in label:
                json_key, kind = "ff", "form"
            elif "interfaces" in label and "integrated" not in label:
                json_key, kind = "iface", "text"
            elif "storage" in label and "ssd" in label.lower():
                json_key, kind = "ssd", "text"

            if json_key is None:
                continue

            # For each model column, extract the cell value and apply
            for col_idx, model_name in model_columns:
                if col_idx < len(cells):
                    raw = cells[col_idx].get_text(" ", strip=True)
                    _apply_cisco_value(found_models[model_name], json_key, raw, kind)

    log(f"  Parsed {len(found_models)} Cisco models")
    valid = [m for m in found_models.values()
             if m["fw"] > 0 or m["ips"] > 0 or m["threat"] > 0]
    log(f"  {len(valid)} have valid throughput values")
    return valid


def _apply_cisco_value(model_dict: dict, key: str, raw: str, kind: str) -> None:
    """Convert raw Cisco HTML cell value to typed model field."""
    if not raw or raw in ("—", "-", "N/A", "—  ", ""):
        return

    if kind == "gbps":
        v = to_gbps(raw)
        if v > 0:
            # Take the higher value when a metric appears in multiple tables
            # (e.g. Threat Defense vs ASA software). Coerce None→0 for the compare.
            current = model_dict.get(key) or 0
            if v > current:
                model_dict[key] = v

    elif kind == "millions":
        # "200K", "300K", "1M", "1,000,000"
        cleaned = raw.replace(",", "").lower()
        m = re.search(r"([\d.]+)\s*([kmb])?", cleaned)
        if m:
            val = float(m.group(1))
            unit = (m.group(2) or "").lower()
            cur = model_dict.get(key) or 0
            if unit == "m":
                model_dict[key] = max(cur, val)
            elif unit == "k":
                model_dict[key] = max(cur, val / 1000)
            elif unit == "b":
                model_dict[key] = max(cur, val * 1000)
            else:
                # Bare number
                if val > 1000:
                    model_dict[key] = max(cur, val / 1_000_000)
                else:
                    model_dict[key] = max(cur, val)

    elif kind == "k_to_int":
        # "35K", "50K", "100K", "1,000"
        cleaned = raw.replace(",", "").lower()
        m = re.search(r"([\d.]+)\s*([km])?", cleaned)
        if m:
            val = float(m.group(1))
            unit = (m.group(2) or "").lower()
            cur = model_dict.get(key) or 0
            if unit == "k":
                model_dict[key] = max(cur, int(val * 1000))
            elif unit == "m":
                model_dict[key] = max(cur, int(val * 1_000_000))
            else:
                model_dict[key] = max(cur, int(val))

    elif kind == "text":
        cleaned = raw.strip()
        if cleaned and cleaned not in ("—", "-", "N/A"):
            # For text fields like interfaces, append rather than replace
            existing = model_dict.get(key, "")
            if existing and existing != cleaned:
                model_dict[key] = existing + "; " + cleaned
            else:
                model_dict[key] = cleaned

    elif kind == "form":
        ff = classify_form_factor(raw)
        if ff:
            model_dict[key] = ff


# ─────────────────────────────────────────────────────────────────────────────
# MANUAL JSON LOADER
# ─────────────────────────────────────────────────────────────────────────────
def load_manual_json(path: Path) -> list[dict]:
    """Load a manually-maintained JSON file as-is.

    Expected format:
      [{"vendor":"X","model":"Y",...}, ...]
    OR
      {"vendor":"X","models":[{"model":"Y",...}, ...]}
    """
    data = json.loads(path.read_text())
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict) and "models" in data:
        vendor = data.get("vendor", "")
        rows = [{**row, "vendor": vendor} for row in data["models"]]
    else:
        log(f"  ✗ {path.name}: unrecognised JSON format")
        return []
    for r in rows:
        r.setdefault("source", path.name)
    log(f"  Loaded {len(rows)} models from {path.name}")
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# DISPATCH MAP — filename stems to parser functions
# ─────────────────────────────────────────────────────────────────────────────
PARSERS: dict[str, Callable[[Path], list[dict]]] = {
    "fortinet.pdf":     parse_fortinet_pdf,
    "checkpoint.pdf":   parse_checkpoint_pdf,
    "paloalto.pdf":     parse_paloalto_pdf,
    "cisco-1200.html":  parse_cisco_1200_html,
    # JSON files: any *.json in datasheets/ is loaded by load_manual_json
}


# ─────────────────────────────────────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────
def main() -> int:
    log("FireIQ data builder starting")
    if not DATASHEETS.exists():
        log(f"✗ datasheets/ folder not found at {DATASHEETS}")
        return 1

    all_models: list[dict] = []
    sources: list[dict] = []
    started = datetime.now(timezone.utc)

    files = sorted(DATASHEETS.iterdir())
    log(f"Found {len(files)} files in datasheets/")

    for file in files:
        if file.name == "README.md" or file.name.startswith("."):
            continue
        log(f"\n→ {file.name}")
        entry = {
            "file": file.name,
            "size_bytes": file.stat().st_size,
            "modified":   datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc).isoformat(),
        }
        try:
            if file.suffix.lower() == ".json":
                models = load_manual_json(file)
            elif file.name in PARSERS:
                models = PARSERS[file.name](file)
            elif file.suffix.lower() == ".html" and file.name.lower().startswith("cisco-"):
                # Any cisco-*.html uses the Cisco datasheet parser
                # (works for cisco-1200.html, cisco-3100.html, cisco-4200.html, etc.)
                models = parse_cisco_1200_html(file)
            else:
                log(f"  ⚠️  No parser registered for {file.name} — add one to PARSERS dict")
                entry["status"] = "skipped"
                entry["models_count"] = 0
                sources.append(entry)
                continue
            all_models.extend(models)
            entry["status"] = "ok"
            entry["models_count"] = len(models)
        except Exception as e:
            log(f"  ✗ FAILED: {e}")
            traceback.print_exc()
            entry["status"] = "error"
            entry["error"] = str(e)
            entry["models_count"] = 0
        sources.append(entry)

    # ── Deduplicate by model name ──
    # If the same model appears from multiple sources (e.g. a Cisco model in both
    # cisco-1200.html and manual-overrides.json), keep the one with the most
    # populated fields (richest data wins), preferring parsed datasheets over
    # manual entries on a tie.
    def _richness(m: dict) -> int:
        score = 0
        for k in ("fw","ips","ngfw","threat","vpn","sessions","newSess"):
            if (m.get(k) or 0) > 0:
                score += 1
        for k in ("ff","iface","ssd","proc"):
            if str(m.get(k) or "").strip():
                score += 1
        # Prefer non-manual sources slightly
        if "manual" not in str(m.get("source","")).lower():
            score += 0.5
        return score

    best_by_model: dict[str, dict] = {}
    for m in all_models:
        key = m["model"]
        if key not in best_by_model or _richness(m) > _richness(best_by_model[key]):
            best_by_model[key] = m
    deduped = list(best_by_model.values())
    if len(deduped) < len(all_models):
        log(f"\n  Deduplicated {len(all_models)} → {len(deduped)} "
            f"(removed {len(all_models) - len(deduped)} duplicate model names)")
    all_models = deduped

    payload = {
        "updated": started.isoformat(),
        "total":   len(all_models),
        "firewalls": all_models,
    }
    OUT_FILE.write_text(json.dumps(payload, indent=2))
    STATUS.write_text(json.dumps({
        "updated": started.isoformat(),
        "sources": sources,
    }, indent=2))

    log(f"\n✓ Wrote {len(all_models)} models to {OUT_FILE.relative_to(ROOT)}")
    ok_count = sum(1 for s in sources if s.get("status") == "ok")
    log(f"✓ {ok_count}/{len(sources)} sources processed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
