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
def parse_checkpoint_pdf(pdf_path: Path) -> list[dict]:
    """Check Point Appliance Comparison Chart PDF parser.

    Structure of the Check Point chart (different from Fortinet):
      - Models are in COLUMNS (header row has model numbers like "3600 3800 6200 ...")
      - Specs are in ROWS below (Threat Prevention, NGFW, IPS, Firewall, VPN, etc.)
      - Each page has a different group of models (Branch / Mid-Enterprise / Enterprise / Datacenter)
      - "Enterprise Testing Conditions" block has the realistic numbers we want
        (the "Ideal Testing Conditions" block above has unrealistic marketing numbers)

    Approach: extract text from each page, find rows whose first token looks like
    model numbers, then read the spec rows that follow until the next model-header row.
    """
    import pdfplumber

    log(f"  Reading {pdf_path.name}")

    # Patterns we look for
    # Check Point model numbers are 4-digit (e.g. 3600, 6200, 16600, 26000, 28600)
    # plus newer Quantum Force naming (e.g. 19100, 19200, 19500, 19800, 29100, 29200, 29300)
    # plus older Maestro (e.g. 39000) and Branch (e.g. 1500, 1600, 1700, 1800)
    model_re = re.compile(r"\b(\d{4,5})\b")

    # Spec row labels: each maps to (json_key, value_parser)
    SPEC_ROWS = [
        # Throughput specs (Gbps)
        (re.compile(r"^Threat Prevention.*Gbps", re.I),         "threat",   "gbps"),
        (re.compile(r"^NGFW Throughput.*Gbps", re.I),           "ngfw",     "gbps"),
        (re.compile(r"^IPS Throughput.*Gbps", re.I),            "ips",      "gbps"),
        (re.compile(r"^Firewall(?: Throughput)?.*Gbps", re.I),  "fw",       "gbps"),
        (re.compile(r"^VPN Throughput.*Gbps", re.I),            "vpn",      "gbps"),
        # Counts
        (re.compile(r"^Connections? Per Second", re.I),         "newSess",  "k_to_int"),
        (re.compile(r"^Concurrent Sessions", re.I),             "sessions", "millions"),
        (re.compile(r"^SSD Size", re.I),                        "ssd",      "text"),
        (re.compile(r"^Physical Enclosure", re.I),              "ff",       "form"),
    ]

    found_models: dict[str, dict] = {}

    with pdfplumber.open(pdf_path) as pdf:
        log(f"  PDF has {len(pdf.pages)} pages")

        for page_idx, page in enumerate(pdf.pages, 1):
            text = page.extract_text(x_tolerance=2) or ""
            lines = [l.strip() for l in text.split("\n") if l.strip()]
            if not lines:
                continue

            # Find the header row(s) containing 3+ model numbers
            # Often there's a "QUANTUM SECURITY GATEWAYS" line followed by the models
            for header_idx, line in enumerate(lines):
                model_matches = model_re.findall(line)
                # Filter to plausible model numbers (4 or 5 digit, between 1000 and 99999)
                models_in_line = [m for m in model_matches if 1000 <= int(m) <= 99999]
                if len(models_in_line) < 3:
                    continue

                # Skip lines that look like spec values, not model headers
                # (e.g. "Connections Per Second (K) 32 60 67 90 ..." has numbers but starts with a label)
                # Heuristic: model headers usually have ONLY model numbers (maybe with some category words)
                non_numeric_words = re.findall(r"[A-Za-z]+", line)
                if any(w.lower() in ("threat", "ngfw", "ips", "firewall", "vpn",
                                      "connections", "concurrent", "ssd", "memory",
                                      "physical", "appliance", "mbps", "gbps", "tbps")
                       for w in non_numeric_words):
                    continue

                # Looks like a model header. Capture this group.
                log(f"  Page {page_idx}: model group {models_in_line}")
                current_models = [f"CP-{m}" for m in models_in_line]

                # Initialise records
                for cm in current_models:
                    if cm not in found_models:
                        found_models[cm] = {
                            "vendor": "Check Point",
                            "model":  cm,
                            "series": _checkpoint_series(cm),
                            "fw": 0.0, "ips": 0.0, "ngfw": 0.0, "threat": 0.0,
                            "vpn": 0.0, "sessions": 0.0, "newSess": 0,
                            "ssl": None, "iface": "", "ff": "", "ssd": None,
                            "proc": "",
                            "source": "checkpoint.pdf",
                        }

                # Walk subsequent lines and try to match spec rows.
                # Stop when we hit the next model header or end of page.
                for spec_line in lines[header_idx + 1:]:
                    # Check if this is another model header (then break)
                    next_model_matches = [m for m in model_re.findall(spec_line)
                                          if 1000 <= int(m) <= 99999]
                    next_non_numeric = re.findall(r"[A-Za-z]+", spec_line)
                    is_pure_model_line = (len(next_model_matches) >= 3 and
                                          not any(w.lower() in ("threat","ngfw","ips","firewall",
                                                                 "vpn","connections","concurrent",
                                                                 "ssd","memory","physical")
                                                  for w in next_non_numeric))
                    if is_pure_model_line:
                        break

                    # Try to match this line against known spec rows
                    for pattern, json_key, kind in SPEC_ROWS:
                        if pattern.match(spec_line):
                            # Extract values after the label
                            # Find where the label ends and numbers begin
                            values = _checkpoint_extract_values(
                                spec_line, len(current_models), kind
                            )
                            for cm, raw in zip(current_models, values):
                                _apply_checkpoint_value(found_models[cm], json_key, raw, kind)
                            break

    log(f"  Parsed {len(found_models)} Check Point models")
    valid = [m for m in found_models.values() if m["fw"] > 0 or m["ips"] > 0 or m["ngfw"] > 0]
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


def _apply_checkpoint_value(model_dict: dict, key: str, raw: str, kind: str) -> None:
    """Convert a raw extracted value and apply it to the model dict."""
    if not raw:
        return
    if kind == "gbps":
        v = to_gbps(raw)
        if v > 0:
            model_dict[key] = v
    elif kind == "millions":
        # Connections values like "4/16" or "2/8" — sessions in default/max memory format
        # Take the larger number (max memory configuration)
        nums = re.findall(r"[\d.]+", raw)
        if nums:
            val = max(float(n) for n in nums)
            model_dict[key] = val
    elif kind == "k_to_int":
        # "Connections Per Second (K)" — values are in thousands
        nums = re.findall(r"[\d.]+", raw)
        if nums:
            # Take the max (some have multiple values for different conditions)
            val = max(float(n) for n in nums)
            model_dict[key] = int(val * 1000)
    elif kind == "text":
        if raw and raw not in ("—", "-", "N/A"):
            # Format SSD nicely: "240" → "240GB"
            cleaned = raw.strip()
            if cleaned.isdigit():
                cleaned += "GB"
            model_dict[key] = cleaned
    elif kind == "form":
        model_dict[key] = classify_form_factor(raw)


def parse_paloalto_pdf(pdf_path: Path) -> list[dict]:
    """Palo Alto Product Summary PDF parser.

    NOT YET IMPLEMENTED. See Check Point note above.
    """
    log(f"  ⚠️  Palo Alto parser not implemented yet — skipping {pdf_path.name}")
    return []


def parse_cisco_1200_html(html_path: Path) -> list[dict]:
    """Cisco Secure Firewall 1200 Series HTML parser.

    NOT YET IMPLEMENTED.
    """
    log(f"  ⚠️  Cisco 1200 parser not implemented yet — skipping {html_path.name}")
    return []


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
