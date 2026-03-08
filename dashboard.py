#!/usr/bin/env python3
"""Guardian Web Dashboard — view security scan results in a browser.

Usage:
    python3 dashboard.py              # starts on port 8845
    python3 dashboard.py --port 9000  # custom port

Opens at http://127.0.0.1:8845 — Ctrl+C to stop.
100% stdlib, no external dependencies.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

GUARDIAN_DIR = Path.home() / ".guardian"
REPORTS_DIR = GUARDIAN_DIR / "reports"
SCORES_FILE = GUARDIAN_DIR / "scores.json"

TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")

# ─── HTML Dashboard ──────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Guardian Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--border:#30363d;
  --text:#e6edf3;--text2:#8b949e;--accent:#58a6ff;
  --ok:#3fb950;--info:#58a6ff;--warn:#d29922;--crit:#f85149;
  --high:#f85149;--medium:#d29922;--low:#58a6ff;
}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;min-height:100vh}
a{color:var(--accent);text-decoration:none}

/* Layout */
.container{max-width:1100px;margin:0 auto;padding:24px 20px}
header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:28px;padding-bottom:16px;border-bottom:1px solid var(--border)}
header h1{font-size:28px;font-weight:700;letter-spacing:4px;color:var(--accent)}
header .meta{color:var(--text2);font-size:13px;text-align:right}
header select{background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;cursor:pointer}

/* Cards */
.grid{display:grid;gap:20px;margin-bottom:24px}
.grid-2{grid-template-columns:1fr 1fr}
.grid-3{grid-template-columns:1fr 1fr 1fr}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;overflow:hidden}
.card h2{font-size:15px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:1px;margin-bottom:14px}

/* Score gauge */
.score-wrap{display:flex;align-items:center;gap:28px;justify-content:center}
.gauge{position:relative;width:140px;height:140px}
.gauge svg{transform:rotate(-90deg)}
.gauge-bg{fill:none;stroke:var(--border);stroke-width:10}
.gauge-fill{fill:none;stroke-width:10;stroke-linecap:round;transition:stroke-dashoffset .8s ease}
.gauge-text{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge-text .score{font-size:42px;font-weight:700}
.gauge-text .label{font-size:12px;color:var(--text2)}
.grade-box{text-align:center}
.grade-box .grade{font-size:56px;font-weight:800}
.grade-box .trend{font-size:14px;margin-top:4px}

/* Severity badges */
.severity-bar{display:flex;gap:12px;flex-wrap:wrap}
.badge{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:20px;font-size:13px;font-weight:600}
.badge .count{font-size:18px;font-weight:700}
.badge-ok{background:rgba(63,185,80,.15);color:var(--ok)}
.badge-info{background:rgba(88,166,255,.15);color:var(--info)}
.badge-warn{background:rgba(210,153,34,.15);color:var(--warn)}
.badge-crit{background:rgba(248,81,73,.15);color:var(--crit)}

/* Chart */
.chart-container{width:100%;overflow-x:auto}
.chart-container svg{width:100%;height:200px}
.chart-line{fill:none;stroke:var(--accent);stroke-width:2}
.chart-area{fill:url(#chartGrad);opacity:.3}
.chart-dot{fill:var(--accent);r:3}
.chart-grid{stroke:var(--border);stroke-width:.5}
.chart-label{fill:var(--text2);font-size:10px}

/* Accordion */
.accordion{border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:2px}
.accordion+.accordion{margin-top:-1px}
.acc-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;background:var(--surface);transition:background .15s;user-select:none}
.acc-header:hover{background:var(--surface2)}
.acc-header .cat{font-weight:600;flex:1}
.acc-header .arrow{transition:transform .2s;color:var(--text2)}
.acc-header.open .arrow{transform:rotate(90deg)}
.acc-body{display:none;padding:0 16px 12px;background:var(--surface)}
.acc-body.open{display:block}
.finding{padding:10px 0;border-bottom:1px solid var(--border)}
.finding:last-child{border-bottom:none}
.finding .title{font-weight:500}
.finding .detail{color:var(--text2);font-size:13px;margin-top:4px;white-space:pre-wrap}
.finding .fix{color:var(--warn);font-size:13px;margin-top:4px}
.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase}
.sev-ok{background:rgba(63,185,80,.15);color:var(--ok)}
.sev-info{background:rgba(88,166,255,.15);color:var(--info)}
.sev-warning{background:rgba(210,153,34,.15);color:var(--warn)}
.sev-critical{background:rgba(248,81,73,.15);color:var(--crit)}

/* Action items */
.action-item{background:var(--surface2);border-left:3px solid var(--crit);border-radius:0 8px 8px 0;padding:14px 16px;margin-bottom:10px}
.action-item.warn-item{border-left-color:var(--warn)}
.action-item .ai-title{font-weight:600;margin-bottom:4px}
.action-item .ai-fix{color:var(--text2);font-size:13px;white-space:pre-wrap}

/* Suggestions */
.suggestion{background:var(--surface2);border-radius:8px;padding:16px;margin-bottom:10px;cursor:pointer}
.suggestion .s-header{display:flex;align-items:center;gap:10px}
.suggestion .s-title{font-weight:600;flex:1}
.suggestion .s-detail{display:none;color:var(--text2);font-size:13px;margin-top:10px;white-space:pre-wrap}
.suggestion.open .s-detail{display:block}
.pri{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.pri-high{background:rgba(248,81,73,.15);color:var(--high)}
.pri-medium{background:rgba(210,153,34,.15);color:var(--medium)}
.pri-low{background:rgba(88,166,255,.15);color:var(--low)}

/* Loading / Error */
.loading{text-align:center;padding:60px;color:var(--text2);font-size:15px}
.error{text-align:center;padding:60px;color:var(--crit);font-size:15px}
.empty{text-align:center;padding:30px;color:var(--text2);font-size:14px}

@media(max-width:700px){
  .grid-2,.grid-3{grid-template-columns:1fr}
  .score-wrap{flex-direction:column}
  header{flex-direction:column;align-items:flex-start}
}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>GUARDIAN</h1>
    <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
      <select id="reportSelect" title="Select report"></select>
      <div class="meta" id="metaInfo">Loading...</div>
    </div>
  </header>

  <div id="dashboard">
    <div class="loading">Loading dashboard...</div>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);
const esc = s => {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
};

let reports = [];
let currentReport = null;

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(r.statusText);
  return r.json();
}

function gradeColor(grade) {
  if (grade === 'A') return 'var(--ok)';
  if (grade === 'B') return 'var(--info)';
  if (grade === 'C') return 'var(--warn)';
  return 'var(--crit)';
}

function gaugeColor(score) {
  if (score >= 90) return 'var(--ok)';
  if (score >= 75) return 'var(--info)';
  if (score >= 50) return 'var(--warn)';
  return 'var(--crit)';
}

function fmtDate(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', {month:'short',day:'numeric',year:'numeric'}) +
      ' ' + d.toLocaleTimeString('en-US', {hour:'numeric',minute:'2-digit'});
  } catch { return iso; }
}

function renderGauge(score) {
  const r = 60, c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const offset = c * (1 - pct);
  const color = gaugeColor(score);
  return `<div class="gauge">
    <svg viewBox="0 0 140 140">
      <circle cx="70" cy="70" r="${r}" class="gauge-bg"/>
      <circle cx="70" cy="70" r="${r}" class="gauge-fill"
        stroke="${color}" stroke-dasharray="${c}" stroke-dashoffset="${offset}"/>
    </svg>
    <div class="gauge-text">
      <span class="score" style="color:${color}">${score}</span>
      <span class="label">/ 100</span>
    </div>
  </div>`;
}

function renderChart(history) {
  if (!history || history.length < 2) return '<div class="empty">Not enough data for chart</div>';
  const pts = history.slice(-20);
  const w = 800, h = 180, pad = 40, padR = 20, padB = 30;
  const cw = w - pad - padR, ch = h - 20 - padB;
  const minS = Math.max(0, Math.min(...pts.map(p => p.score)) - 10);
  const maxS = Math.min(100, Math.max(...pts.map(p => p.score)) + 10);
  const range = maxS - minS || 1;

  const coords = pts.map((p, i) => {
    const x = pad + (i / (pts.length - 1)) * cw;
    const y = 20 + ch - ((p.score - minS) / range) * ch;
    return [x, y];
  });

  const polyline = coords.map(c => c.join(',')).join(' ');
  const area = `${pad},${20 + ch} ${polyline} ${coords[coords.length-1][0]},${20 + ch}`;

  // Grid lines
  let grid = '';
  for (let v = minS; v <= maxS; v += Math.ceil(range / 4)) {
    const y = 20 + ch - ((v - minS) / range) * ch;
    grid += `<line x1="${pad}" y1="${y}" x2="${w - padR}" y2="${y}" class="chart-grid"/>`;
    grid += `<text x="${pad - 6}" y="${y + 4}" class="chart-label" text-anchor="end">${v}</text>`;
  }

  // Date labels (first, middle, last)
  const labelIdxs = [0, Math.floor(pts.length / 2), pts.length - 1];
  let labels = '';
  labelIdxs.forEach(i => {
    const d = new Date(pts[i].date);
    const lbl = (d.getMonth()+1) + '/' + d.getDate();
    labels += `<text x="${coords[i][0]}" y="${h - 4}" class="chart-label" text-anchor="middle">${lbl}</text>`;
  });

  const dots = coords.map(c => `<circle cx="${c[0]}" cy="${c[1]}" class="chart-dot"/>`).join('');

  return `<div class="chart-container">
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet">
      <defs><linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--accent)"/>
        <stop offset="100%" stop-color="transparent"/>
      </linearGradient></defs>
      ${grid}
      <polygon points="${area}" class="chart-area"/>
      <polyline points="${polyline}" class="chart-line"/>
      ${dots}
      ${labels}
    </svg>
  </div>`;
}

function severityCounts(findings) {
  const c = {OK:0,INFO:0,WARNING:0,CRITICAL:0};
  findings.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });
  return c;
}

function renderSeverityBar(counts) {
  return `<div class="severity-bar">
    <span class="badge badge-ok"><span class="count">${counts.OK}</span> OK</span>
    <span class="badge badge-info"><span class="count">${counts.INFO}</span> INFO</span>
    <span class="badge badge-warn"><span class="count">${counts.WARNING}</span> WARNING</span>
    <span class="badge badge-crit"><span class="count">${counts.CRITICAL}</span> CRITICAL</span>
  </div>`;
}

function renderFindings(findings) {
  const cats = {};
  findings.forEach(f => {
    if (!cats[f.category]) cats[f.category] = [];
    cats[f.category].push(f);
  });

  // Sort categories: those with critical/warning first
  const sorted = Object.keys(cats).sort((a, b) => {
    const sevOrder = s => s === 'CRITICAL' ? 0 : s === 'WARNING' ? 1 : s === 'INFO' ? 2 : 3;
    const worstA = Math.min(...cats[a].map(f => sevOrder(f.severity)));
    const worstB = Math.min(...cats[b].map(f => sevOrder(f.severity)));
    return worstA - worstB;
  });

  return sorted.map(cat => {
    const items = cats[cat];
    const worst = items.reduce((w, f) => {
      const o = {CRITICAL:0,WARNING:1,INFO:2,OK:3};
      return (o[f.severity] ?? 3) < (o[w] ?? 3) ? f.severity : w;
    }, 'OK');
    const sevClass = 'sev-' + worst.toLowerCase();
    const badge = `<span class="sev ${sevClass}">${worst}</span>`;
    const countLabel = `<span style="color:var(--text2);font-size:12px">${items.length}</span>`;

    const findingsHtml = items.map(f => {
      const fBadge = `<span class="sev sev-${f.severity.toLowerCase()}">${f.severity}</span>`;
      const detail = f.detail ? `<div class="detail">${esc(f.detail)}</div>` : '';
      const fix = f.fix ? `<div class="fix">${esc(f.fix)}</div>` : '';
      return `<div class="finding">${fBadge} <span class="title">${esc(f.title)}</span>${detail}${fix}</div>`;
    }).join('');

    return `<div class="accordion">
      <div class="acc-header" onclick="toggleAcc(this)">
        ${badge} <span class="cat">${esc(cat)}</span> ${countLabel}
        <span class="arrow">&#9654;</span>
      </div>
      <div class="acc-body">${findingsHtml}</div>
    </div>`;
  }).join('');
}

function renderActions(findings) {
  const actionable = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'WARNING');
  if (!actionable.length) return '<div class="empty">No action items — looking good!</div>';
  // Critical first, then warning
  actionable.sort((a, b) => (a.severity === 'CRITICAL' ? 0 : 1) - (b.severity === 'CRITICAL' ? 0 : 1));
  return actionable.map(f => {
    const cls = f.severity === 'CRITICAL' ? '' : ' warn-item';
    const badge = `<span class="sev sev-${f.severity.toLowerCase()}">${f.severity}</span>`;
    const fix = f.fix ? `<div class="ai-fix">${esc(f.fix)}</div>` : '';
    return `<div class="action-item${cls}">
      <div class="ai-title">${badge} ${esc(f.title)}</div>
      ${fix}
    </div>`;
  }).join('');
}

function renderSuggestions(suggestions) {
  if (!suggestions || !suggestions.length) return '<div class="empty">No suggestions</div>';
  const order = {HIGH:0,MEDIUM:1,LOW:2};
  suggestions.sort((a, b) => (order[a.priority] ?? 2) - (order[b.priority] ?? 2));
  return suggestions.map(s => {
    const pri = `<span class="pri pri-${s.priority.toLowerCase()}">${s.priority}</span>`;
    return `<div class="suggestion" onclick="this.classList.toggle('open')">
      <div class="s-header">${pri} <span class="s-title">${esc(s.title)}</span>
        <span class="arrow" style="color:var(--text2)">&#9654;</span></div>
      <div class="s-detail">${esc(s.detail)}</div>
    </div>`;
  }).join('');
}

function toggleAcc(el) {
  el.classList.toggle('open');
  el.nextElementSibling.classList.toggle('open');
}

function renderDashboard(report, history) {
  const counts = severityCounts(report.findings || []);
  const trend = computeTrend(history);

  return `
    <div class="grid grid-2">
      <div class="card">
        <h2>Security Score</h2>
        <div class="score-wrap">
          ${renderGauge(report.score)}
          <div class="grade-box">
            <div class="grade" style="color:${gradeColor(report.grade)}">${esc(report.grade)}</div>
            <div class="trend">${trend}</div>
          </div>
        </div>
      </div>
      <div class="card">
        <h2>Score History</h2>
        ${renderChart(history)}
      </div>
    </div>

    <div class="card">
      <h2>Severity Summary</h2>
      ${renderSeverityBar(counts)}
    </div>

    <div class="grid grid-2" style="margin-top:20px">
      <div class="card">
        <h2>Action Items</h2>
        ${renderActions(report.findings || [])}
      </div>
      <div class="card">
        <h2>Suggestions</h2>
        ${renderSuggestions(report.suggestions || [])}
      </div>
    </div>

    <div class="card" style="margin-top:20px">
      <h2>Findings by Category</h2>
      ${renderFindings(report.findings || [])}
    </div>
  `;
}

function computeTrend(history) {
  if (!history || history.length < 2) return '';
  const cur = history[history.length - 1].score;
  const prev = history[history.length - 2].score;
  const diff = cur - prev;
  if (diff > 0) return `<span style="color:var(--ok)">&#9650; +${diff} from last</span>`;
  if (diff < 0) return `<span style="color:var(--crit)">&#9660; ${diff} from last</span>`;
  return `<span style="color:var(--text2)">&#9644; No change</span>`;
}

async function loadReportList() {
  try {
    reports = await api('/api/reports');
    const sel = $('#reportSelect');
    sel.innerHTML = reports.map((ts, i) => {
      const d = ts.replace(/_/g, ' ').replace(/-/g, (m, off) => off > 4 && off < 10 ? '-' : off > 10 ? ':' : '-');
      return `<option value="${ts}"${i === 0 ? ' selected' : ''}>${d}${i === 0 ? ' (latest)' : ''}</option>`;
    }).join('');
    sel.addEventListener('change', () => loadReport(sel.value));
  } catch {
    reports = [];
  }
}

async function loadReport(timestamp) {
  const dash = $('#dashboard');
  try {
    const url = timestamp ? `/api/report/${timestamp}` : '/api/latest';
    const [report, history] = await Promise.all([api(url), api('/api/history')]);
    currentReport = report;
    $('#metaInfo').textContent = 'Last scan: ' + fmtDate(report.date);
    dash.innerHTML = renderDashboard(report, history);
  } catch (e) {
    dash.innerHTML = `<div class="error">Failed to load report: ${esc(e.message)}<br><br>
      <span style="color:var(--text2)">Run <code>python3 ~/guardian/guardian.py</code> to generate a scan first.</span></div>`;
  }
}

(async () => {
  await loadReportList();
  await loadReport(reports[0] || null);
})();
</script>
</body>
</html>
"""


# ─── HTTP Server ──────────────────────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):
    """Handle dashboard routes. Read-only, no subprocess calls."""

    def log_message(self, fmt, *args):
        # Quieter logging — just method + path
        sys.stderr.write(f"  {args[0]}\n")

    def _send(self, body, content_type="application/json", status=200):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status, msg):
        self._send(json.dumps({"error": msg}), status=status)

    def do_GET(self):
        path = self.path.split("?")[0]  # strip query params

        if path == "/":
            self._send(DASHBOARD_HTML, content_type="text/html")

        elif path == "/api/latest":
            self._serve_latest()

        elif path == "/api/history":
            self._serve_history()

        elif path == "/api/reports":
            self._serve_report_list()

        elif path.startswith("/api/report/"):
            ts = path[len("/api/report/"):]
            self._serve_report(ts)

        else:
            self._error(404, "Not found")

    def _serve_latest(self):
        try:
            files = sorted(REPORTS_DIR.glob("*.json"), reverse=True)
            if not files:
                self._error(404, "No reports found. Run guardian.py first.")
                return
            data = files[0].read_text(encoding="utf-8")
            self._send(data)
        except Exception as e:
            self._error(500, str(e))

    def _serve_history(self):
        try:
            if SCORES_FILE.exists():
                data = SCORES_FILE.read_text(encoding="utf-8")
                self._send(data)
            else:
                self._send("[]")
        except Exception as e:
            self._error(500, str(e))

    def _serve_report_list(self):
        try:
            if not REPORTS_DIR.exists():
                self._send("[]")
                return
            files = sorted(REPORTS_DIR.glob("*.json"), reverse=True)
            timestamps = [f.stem for f in files]
            self._send(json.dumps(timestamps))
        except Exception as e:
            self._error(500, str(e))

    def _serve_report(self, timestamp):
        # Strict validation — only allow YYYY-MM-DD_HH-MM-SS
        if not TIMESTAMP_RE.match(timestamp):
            self._error(400, "Invalid timestamp format")
            return
        report_file = REPORTS_DIR / f"{timestamp}.json"
        if not report_file.exists():
            self._error(404, "Report not found")
            return
        try:
            data = report_file.read_text(encoding="utf-8")
            self._send(data)
        except Exception as e:
            self._error(500, str(e))


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Guardian Web Dashboard")
    parser.add_argument("--port", type=int, default=8845, help="Port (default: 8845)")
    args = parser.parse_args()

    server = HTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"\n  Guardian Dashboard running at http://127.0.0.1:{args.port}")
    print(f"  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
