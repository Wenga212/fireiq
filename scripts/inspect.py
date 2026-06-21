#!/usr/bin/env python3
"""
Inspect a vendor datasheet to help write or fix its parser.

Usage:
    python scripts/inspect.py datasheets/fortinet.pdf
    python scripts/inspect.py datasheets/cisco-1200.html

Outputs the structure of the file (text content, tables, headings) so you
can see what the parser needs to handle.
"""
from __future__ import annotations
import sys
from pathlib import Path


def inspect_pdf(path: Path) -> None:
    import pdfplumber
    print(f"\n=== {path.name} ===")
    with pdfplumber.open(path) as pdf:
        print(f"Pages: {len(pdf.pages)}")
        for i, page in enumerate(pdf.pages, 1):
            print(f"\n--- Page {i} ---")
            text = page.extract_text() or ""
            # Print first 40 lines of each page
            lines = text.split("\n")
            for line in lines[:40]:
                print(f"  {line}")
            if len(lines) > 40:
                print(f"  ... ({len(lines) - 40} more lines)")
            # Also report any tables found
            tables = page.extract_tables() or []
            if tables:
                print(f"\n  Tables on this page: {len(tables)}")
                for ti, t in enumerate(tables):
                    print(f"    Table {ti}: {len(t)} rows × {max((len(r) for r in t), default=0)} cols")


def inspect_html(path: Path) -> None:
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(path.read_text(encoding="utf-8", errors="ignore"), "lxml")
    print(f"\n=== {path.name} ===")
    tables = soup.find_all("table")
    print(f"Tables: {len(tables)}")
    for i, t in enumerate(tables):
        rows = t.find_all("tr")
        if not rows:
            continue
        header = [c.get_text(strip=True)[:30] for c in rows[0].find_all(["th", "td"])]
        print(f"\n  Table {i}: {len(rows)} rows")
        print(f"    Header: {header}")
        if len(rows) > 1:
            sample = [c.get_text(strip=True)[:30] for c in rows[1].find_all(["th", "td"])]
            print(f"    Row 1:  {sample}")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python scripts/inspect.py <path-to-datasheet>")
        return 1
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        return 1
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        inspect_pdf(path)
    elif suffix in (".html", ".htm"):
        inspect_html(path)
    else:
        print(f"Unsupported file type: {suffix}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
