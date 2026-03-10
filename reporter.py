"""
fim/reporter.py - Report generation for GuardianFIM (HTML, JSON, TXT)
"""

import json
from datetime import datetime
from pathlib import Path


class Reporter:
    def generate(self, results: dict, output_path: str, fmt: str = "html"):
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        if fmt == "html":
            self._generate_html(results, output_path)
        elif fmt == "json":
            self._generate_json(results, output_path)
        elif fmt == "txt":
            self._generate_txt(results, output_path)

        print(f"[✔] Report saved: {output_path}")

    def _generate_json(self, results: dict, path: str):
        with open(path, "w") as f:
            json.dump(results, f, indent=2)

    def _generate_txt(self, results: dict, path: str):
        lines = [
            "=" * 60,
            "  GUARDIANFIM INTEGRITY SCAN REPORT",
            "=" * 60,
            f"  Scan Time   : {results.get('scan_time', 'N/A')}",
            f"  Baseline    : {results.get('baseline_time', 'N/A')}",
            f"  Algorithm   : {results.get('algorithm', 'N/A').upper()}",
            "",
        ]
        s = results.get("summary", {})
        lines += [
            "  SUMMARY",
            f"  Unchanged        : {s.get('unchanged', 0)}",
            f"  Modified         : {s.get('modified', 0)}",
            f"  New Files        : {s.get('added', 0)}",
            f"  Deleted          : {s.get('deleted', 0)}",
            f"  Perm Changed     : {s.get('permission_changed', 0)}",
            "",
            "  FINDINGS",
            "-" * 60,
        ]
        for f in results.get("findings", []):
            lines += [
                f"  [{f['severity']}] {f['type']}",
                f"  Path   : {f['path']}",
                f"  Detail : {f['detail']}",
                "",
            ]
        with open(path, "w") as fp:
            fp.write("\n".join(lines))

    def _generate_html(self, results: dict, path: str):
        s = results.get("summary", {})
        findings = results.get("findings", [])
        total = len(findings)
        scan_time = results.get("scan_time", "N/A")
        baseline_time = results.get("baseline_time", "N/A")
        algo = results.get("algorithm", "N/A").upper()

        severity_colors = {
            "CRITICAL": ("#ff4444", "#fff0f0"),
            "HIGH":     ("#ff8800", "#fff8f0"),
            "MEDIUM":   ("#ffcc00", "#fffef0"),
            "LOW":      ("#00cc66", "#f0fff8"),
        }

        rows = ""
        for f in findings:
            sev = f.get("severity", "LOW")
            badge_color, row_bg = severity_colors.get(sev, ("#999", "#fff"))
            rows += f"""
            <tr style="background:{row_bg}">
              <td><span class="badge" style="background:{badge_color}">{sev}</span></td>
              <td><strong>{f['type']}</strong></td>
              <td class="mono">{f['path']}</td>
              <td>{f['detail']}</td>
              <td class="mono small">{(f.get('baseline_hash') or '')[:16]}…</td>
              <td class="mono small">{(f.get('current_hash') or '')[:16]}…</td>
            </tr>"""

        status_class = "status-clean" if total == 0 else "status-alert"
        status_text = "✔ ALL FILES INTACT" if total == 0 else f"⚠ {total} FINDING(S) DETECTED"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>GuardianFIM Scan Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }}
    .header {{ background: linear-gradient(135deg, #161b22, #21262d); border-bottom: 1px solid #30363d; padding: 24px 40px; }}
    .header h1 {{ color: #58a6ff; font-size: 2rem; letter-spacing: 2px; }}
    .header p {{ color: #8b949e; margin-top: 4px; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 40px; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 30px; }}
    .meta-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 20px; }}
    .meta-card label {{ color: #8b949e; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; }}
    .meta-card value {{ display: block; color: #e6edf3; font-size: 1rem; margin-top: 4px; font-family: monospace; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 30px; }}
    .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }}
    .stat-card .num {{ font-size: 2rem; font-weight: bold; }}
    .stat-card .lbl {{ font-size: 0.75rem; color: #8b949e; margin-top: 4px; text-transform: uppercase; }}
    .stat-card.crit .num {{ color: #ff4444; }}
    .stat-card.high .num {{ color: #ff8800; }}
    .stat-card.med .num {{ color: #ffcc00; }}
    .stat-card.good .num {{ color: #00cc66; }}
    .stat-card.info .num {{ color: #58a6ff; }}
    .status-banner {{ border-radius: 8px; padding: 16px 24px; margin-bottom: 24px; font-size: 1.1rem; font-weight: bold; text-align: center; }}
    .status-clean {{ background: #0d4429; border: 1px solid #238636; color: #3fb950; }}
    .status-alert {{ background: #3d1a1a; border: 1px solid #da3633; color: #f85149; }}
    table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #30363d; }}
    th {{ background: #21262d; color: #8b949e; font-size: 0.75rem; text-transform: uppercase; padding: 12px 16px; text-align: left; letter-spacing: 1px; }}
    td {{ padding: 10px 16px; border-top: 1px solid #21262d; font-size: 0.875rem; color: #c9d1d9; vertical-align: top; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: bold; color: white; }}
    .mono {{ font-family: 'Courier New', monospace; }}
    .small {{ font-size: 0.75rem; }}
    .section-title {{ color: #8b949e; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }}
    .footer {{ text-align: center; color: #484f58; padding: 20px; font-size: 0.8rem; border-top: 1px solid #21262d; margin-top: 40px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>⛨ GUARDIANFIM</h1>
    <p>File Integrity Monitor — Scan Report</p>
  </div>
  <div class="container">
    <div class="meta-grid">
      <div class="meta-card"><label>Scan Time</label><value>{scan_time}</value></div>
      <div class="meta-card"><label>Baseline Created</label><value>{baseline_time}</value></div>
      <div class="meta-card"><label>Hash Algorithm</label><value>{algo}</value></div>
    </div>
    <div class="summary-grid">
      <div class="stat-card crit"><div class="num">{s.get('modified', 0)}</div><div class="lbl">Modified</div></div>
      <div class="stat-card high"><div class="num">{s.get('deleted', 0)}</div><div class="lbl">Deleted</div></div>
      <div class="stat-card high"><div class="num">{s.get('added', 0)}</div><div class="lbl">New Files</div></div>
      <div class="stat-card med"><div class="num">{s.get('permission_changed', 0)}</div><div class="lbl">Perm Changed</div></div>
      <div class="stat-card good"><div class="num">{s.get('unchanged', 0)}</div><div class="lbl">Unchanged</div></div>
    </div>
    <div class="status-banner {status_class}">{status_text}</div>
    <p class="section-title">Findings ({total})</p>
    <table>
      <thead>
        <tr>
          <th>Severity</th><th>Type</th><th>File Path</th><th>Detail</th>
          <th>Baseline Hash</th><th>Current Hash</th>
        </tr>
      </thead>
      <tbody>
        {rows if rows else '<tr><td colspan="6" style="text-align:center;padding:24px;color:#3fb950">✔ No integrity violations found</td></tr>'}
      </tbody>
    </table>
  </div>
  <div class="footer">Generated by GuardianFIM v1.0 · {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
</body>
</html>"""

        with open(path, "w") as f:
            f.write(html)
