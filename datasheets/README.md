# Datasheets — source of truth for FireIQ

This folder holds the raw vendor datasheets that drive `data/firewalls.json`.
When you commit a new or updated file here, GitHub Actions automatically
re-runs the parser and rebuilds the JSON consumed by the FireIQ web app.

## How the parser picks up files

Files are matched by **exact filename** to a parser in `scripts/build.py`:

| Filename                  | Parser                       | Vendor             | Status                |
|---------------------------|------------------------------|--------------------|----------------------|
| `fortinet.pdf`            | `parse_fortinet_pdf`         | Fortinet           | ✅ Implemented       |
| `checkpoint.pdf`          | `parse_checkpoint_pdf`       | Check Point        | ⚠️  Stub (TODO)      |
| `paloalto.pdf`            | `parse_paloalto_pdf`         | Palo Alto          | ⚠️  Stub (TODO)      |
| `cisco-1200.html`         | `parse_cisco_1200_html`      | Cisco              | ⚠️  Stub (TODO)      |
| `manual-overrides.json`   | `load_manual_json`           | Any vendor         | ✅ Implemented       |

Any `.json` file in this folder is loaded as-is — useful for vendors without
parseable docs or to add a single newly-released model without waiting for a
parser fix.

---

## How to refresh each vendor

### Fortinet (twice a year)
1. Download from https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/Fortinet_Product_Matrix.pdf
2. Save as `fortinet.pdf` (replace existing)
3. Commit + push. Action runs automatically.

### Check Point (~yearly)
1. Download https://www.checkpoint.com/downloads/products/check-point-appliance-comparison-chart.pdf
2. Save as `checkpoint.pdf`
3. Commit + push

### Palo Alto (~yearly)
1. Download https://www.paloaltonetworks.com/apps/pan/public/downloadResource?pagePath=/content/pan/en_US/resources/datasheets/product-summary-specsheet
2. Save as `paloalto.pdf`
3. Commit + push

### Cisco (per-family)
Cisco doesn't publish a unified comparison PDF. For each series:
1. Open the datasheet page (e.g. https://www.cisco.com/c/en/us/products/collateral/security/firewalls/secure-firewall-1200-series-ds.html)
2. Browser → File → Save Page As → "Webpage, Complete"
3. Save as `cisco-<series>.html` (e.g. `cisco-1200.html`)
4. Commit + push

### Manual JSON (fallback for anything else)

Create `manual-overrides.json` (or any other `.json` name):

```json
{
  "vendor": "Cisco",
  "models": [
    {
      "model": "CSF-1230",
      "series": "CSF-1200",
      "fw": 13.0, "ips": 13.0, "ngfw": 11.0, "threat": 9.0,
      "vpn": 13.0, "sessions": 0.4, "newSess": 50000, "ssl": 2.5,
      "ssd": "960GB", "ff": "1U",
      "iface": "8x GE RJ45, 4x SFP+",
      "proc": "Cisco Network Processor"
    }
  ]
}
```

---

## Verifying a refresh worked

1. After committing, watch the **Actions tab** on GitHub
2. "Rebuild Firewall Data" should show a green ✓ within ~2 minutes
3. Check `data/sources-status.json` for per-source model counts
4. If counts drop unexpectedly → see "Fixing a broken parser" below

## Fixing a broken parser

When a vendor PDF layout changes and the model count drops:

1. Locally (or in Codespaces):
   ```
   pip install -r scripts/requirements.txt
   python scripts/inspect.py datasheets/fortinet.pdf
   ```
   Prints the PDF structure so you can see what changed.
2. Edit `scripts/build.py`, find the `parse_<vendor>_pdf` function
3. Adjust regex/row labels to match the new layout
4. Commit. Next run uses the fix.

## Schema (output JSON)

Each model in `data/firewalls.json`:

| Field      | Type     | Unit   |
|------------|----------|--------|
| vendor     | string   |        |
| model      | string   |        |
| series     | string   |        |
| fw         | number   | Gbps   |
| ips        | number   | Gbps   |
| ngfw       | number   | Gbps   |
| threat     | number   | Gbps   |
| vpn        | number   | Gbps   |
| sessions   | number   | M      |
| newSess    | integer  |        |
| ssl        | number?  | Gbps   |
| iface      | string   |        |
| ff         | string   |        |
| ssd        | string?  |        |
| proc       | string   |        |
