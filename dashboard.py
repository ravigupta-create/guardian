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
import re
import socket
import sys
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
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--surface3:#21262d;
  --border:#30363d;--border2:#3d444d;
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;--accent:#58a6ff;--accent2:#1f6feb;
  --ok:#3fb950;--ok-bg:rgba(63,185,80,.12);
  --info:#58a6ff;--info-bg:rgba(88,166,255,.12);
  --warn:#d29922;--warn-bg:rgba(210,153,34,.12);
  --crit:#f85149;--crit-bg:rgba(248,81,73,.12);
  --high:#f85149;--medium:#d29922;--low:#58a6ff;
  --purple:#bc8cff;--purple-bg:rgba(188,140,255,.12);
}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:"SF Mono",SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;font-size:12px}

/* Scrollbar */
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:var(--border2)}

/* Layout */
.container{max-width:1200px;margin:0 auto;padding:24px 20px 60px}
header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:28px;padding-bottom:16px;border-bottom:1px solid var(--border)}
.header-left{display:flex;align-items:center;gap:14px}
.shield{width:36px;height:36px;position:relative}
.shield svg{width:36px;height:36px}
header h1{font-size:26px;font-weight:700;letter-spacing:4px;color:var(--accent)}
.header-right{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
header .meta{color:var(--text2);font-size:13px;text-align:right}
header select{background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:13px;cursor:pointer;max-width:220px}
header select:focus{outline:1px solid var(--accent);border-color:var(--accent)}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:4px}
.status-active{background:var(--ok);box-shadow:0 0 6px var(--ok)}
.status-stale{background:var(--warn);box-shadow:0 0 6px var(--warn)}
.status-old{background:var(--crit);box-shadow:0 0 6px var(--crit)}
.refresh-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text2);border-radius:6px;padding:5px 10px;cursor:pointer;font-size:12px;display:flex;align-items:center;gap:4px;transition:all .15s}
.refresh-btn:hover{border-color:var(--accent);color:var(--accent)}
.refresh-btn.spinning svg{animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* Cards */
.grid{display:grid;gap:20px;margin-bottom:24px}
.grid-2{grid-template-columns:1fr 1fr}
.grid-3{grid-template-columns:1fr 1fr 1fr}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;overflow:hidden;transition:border-color .2s}
.card:hover{border-color:var(--border2)}
.card h2{font-size:14px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:1.2px;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card h2 .h2-count{background:var(--surface2);color:var(--text3);padding:2px 8px;border-radius:10px;font-size:11px;letter-spacing:0}

/* Score gauge */
.score-section{display:flex;align-items:center;gap:28px;justify-content:center;flex-wrap:wrap}
.gauge{position:relative;width:150px;height:150px}
.gauge svg{transform:rotate(-90deg)}
.gauge-bg{fill:none;stroke:var(--border);stroke-width:10}
.gauge-fill{fill:none;stroke-width:10;stroke-linecap:round;transition:stroke-dashoffset 1s ease}
.gauge-text{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge-text .score-num{font-size:44px;font-weight:700;transition:color .3s}
.gauge-text .score-label{font-size:12px;color:var(--text2)}
.grade-wrap{text-align:center}
.grade-letter{font-size:60px;font-weight:800;line-height:1;transition:color .3s}
.grade-sub{font-size:13px;color:var(--text2);margin-top:6px}
.trend-badge{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600;margin-top:8px}
.trend-up{background:var(--ok-bg);color:var(--ok)}
.trend-down{background:var(--crit-bg);color:var(--crit)}
.trend-flat{background:rgba(139,148,158,.12);color:var(--text2)}
.next-grade{font-size:12px;color:var(--text3);margin-top:6px}

/* Stats bar */
.stats-bar{display:flex;gap:20px;flex-wrap:wrap;align-items:center}
.stat-item{display:flex;flex-direction:column;align-items:center;gap:2px;min-width:60px}
.stat-value{font-size:22px;font-weight:700}
.stat-label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px}

/* Severity badges */
.severity-bar{display:flex;gap:10px;flex-wrap:wrap}
.badge{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s;border:1px solid transparent}
.badge:hover{transform:translateY(-1px)}
.badge .count{font-size:20px;font-weight:700}
.badge-ok{background:var(--ok-bg);color:var(--ok)}
.badge-ok:hover,.badge-ok.active{border-color:var(--ok)}
.badge-info{background:var(--info-bg);color:var(--info)}
.badge-info:hover,.badge-info.active{border-color:var(--info)}
.badge-warn{background:var(--warn-bg);color:var(--warn)}
.badge-warn:hover,.badge-warn.active{border-color:var(--warn)}
.badge-crit{background:var(--crit-bg);color:var(--crit)}
.badge-crit:hover,.badge-crit.active{border-color:var(--crit)}

/* Category chart */
.cat-chart{margin-top:14px}
.cat-bar-row{display:flex;align-items:center;gap:10px;margin-bottom:6px;font-size:12px}
.cat-bar-label{width:100px;text-align:right;color:var(--text2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cat-bar-track{flex:1;height:18px;background:var(--surface2);border-radius:4px;overflow:hidden;display:flex}
.cat-bar-seg{height:100%;transition:width .5s ease}
.cat-bar-count{width:30px;font-weight:600;font-size:11px;color:var(--text3)}

/* Chart */
.chart-container{width:100%;overflow-x:auto;position:relative}
.chart-container svg{width:100%;height:200px}
.chart-line{fill:none;stroke:var(--accent);stroke-width:2;filter:drop-shadow(0 0 3px rgba(88,166,255,.3))}
.chart-area{fill:url(#chartGrad);opacity:.25}
.chart-dot{fill:var(--accent);r:3.5;cursor:pointer;transition:r .15s}
.chart-dot:hover{r:6}
.chart-grid{stroke:var(--border);stroke-width:.5}
.chart-label{fill:var(--text2);font-size:10px;font-family:inherit}
.chart-tooltip{position:absolute;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;font-size:12px;pointer-events:none;opacity:0;transition:opacity .15s;z-index:10;white-space:nowrap}
.chart-tooltip.visible{opacity:1}

/* Section dividers */
.section{margin-bottom:28px}
.section-title{font-size:20px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:10px}
.section-title .icon{width:24px;height:24px;display:flex;align-items:center;justify-content:center}

/* Search & Filter */
.toolbar{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center}
.search-box{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;color:var(--text);font-size:13px;flex:1;min-width:180px;transition:border-color .15s}
.search-box:focus{outline:none;border-color:var(--accent)}
.filter-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text2);border-radius:6px;padding:6px 12px;cursor:pointer;font-size:12px;font-weight:500;transition:all .15s}
.filter-btn:hover{border-color:var(--accent);color:var(--accent)}
.filter-btn.active{background:var(--accent2);border-color:var(--accent);color:#fff}
.expand-btn{background:none;border:none;color:var(--accent);cursor:pointer;font-size:12px;padding:6px 10px}
.expand-btn:hover{text-decoration:underline}

/* Accordion */
.accordion{border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:4px;transition:border-color .15s}
.accordion:hover{border-color:var(--border2)}
.acc-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;background:var(--surface);transition:background .15s;user-select:none}
.acc-header:hover{background:var(--surface2)}
.acc-header .cat{font-weight:600;flex:1}
.acc-header .cat-count{color:var(--text3);font-size:12px}
.acc-header .arrow{transition:transform .2s;color:var(--text3);font-size:10px}
.acc-header.open .arrow{transform:rotate(90deg)}
.acc-body{max-height:0;overflow:hidden;transition:max-height .3s ease;background:var(--surface)}
.acc-body.open{max-height:5000px}
.acc-body-inner{padding:0 16px 12px}
.finding{padding:10px 0;border-bottom:1px solid var(--border)}
.finding:last-child{border-bottom:none}
.finding-header{display:flex;align-items:flex-start;gap:8px}
.finding .title{font-weight:500;flex:1}
.finding .detail{color:var(--text2);font-size:13px;margin-top:6px;white-space:pre-wrap;line-height:1.5}
.finding .fix-line{margin-top:6px;font-size:13px;display:flex;align-items:flex-start;gap:6px}
.finding .fix-label{color:var(--warn);font-weight:600;white-space:nowrap}
.finding .fix-text{color:var(--text2)}
.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;white-space:nowrap}
.sev-ok{background:var(--ok-bg);color:var(--ok)}
.sev-info{background:var(--info-bg);color:var(--info)}
.sev-warning{background:var(--warn-bg);color:var(--warn)}
.sev-critical{background:var(--crit-bg);color:var(--crit)}

/* Action items */
.action-item{background:var(--surface2);border-left:3px solid var(--crit);border-radius:0 8px 8px 0;padding:16px 18px;margin-bottom:10px;transition:background .15s}
.action-item:hover{background:var(--surface3)}
.action-item.warn-item{border-left-color:var(--warn)}
.action-item .ai-header{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.action-item .ai-title{font-weight:600;flex:1}
.action-item .ai-category{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px}
.action-item .ai-fix{color:var(--text2);font-size:13px}

/* Install Guide / Suggestions */
.guide-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:12px;overflow:hidden;transition:border-color .2s}
.guide-card:hover{border-color:var(--border2)}
.guide-header{display:flex;align-items:center;gap:10px;padding:16px 18px;cursor:pointer;user-select:none;transition:background .15s}
.guide-header:hover{background:var(--surface2)}
.guide-header .arrow{transition:transform .2s;color:var(--text3);font-size:10px}
.guide-header.open .arrow{transform:rotate(90deg)}
.guide-title{font-weight:600;flex:1;font-size:14px}
.guide-body{max-height:0;overflow:hidden;transition:max-height .4s ease}
.guide-body.open{max-height:3000px}
.guide-content{padding:0 18px 18px}
.guide-why{color:var(--text2);font-size:13px;margin-bottom:14px;line-height:1.6;padding:10px 14px;background:var(--surface2);border-radius:6px;border-left:3px solid var(--accent)}

/* Steps */
.steps{counter-reset:step}
.step{display:flex;gap:14px;padding:10px 0;position:relative}
.step:not(:last-child)::before{content:'';position:absolute;left:15px;top:36px;bottom:0;width:1px;background:var(--border)}
.step-num{width:30px;height:30px;border-radius:50%;background:var(--accent2);color:#fff;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0;position:relative;z-index:1}
.step-text{flex:1;padding-top:4px;font-size:13px;color:var(--text);line-height:1.6}
.step-text .step-done{color:var(--ok);font-weight:600}

/* Command blocks */
.cmd-block{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px 14px;margin:8px 0;display:flex;align-items:center;gap:10px;font-family:"SF Mono",SFMono-Regular,Consolas,"Liberation Mono",Menlo,monospace;font-size:12px;position:relative}
.cmd-block code{flex:1;color:var(--accent);word-break:break-all;white-space:pre-wrap}
.cmd-block .copy-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text2);border-radius:4px;padding:4px 10px;cursor:pointer;font-size:11px;white-space:nowrap;transition:all .15s;font-family:inherit}
.cmd-block .copy-btn:hover{border-color:var(--accent);color:var(--accent)}
.cmd-block .copy-btn.copied{background:var(--ok-bg);border-color:var(--ok);color:var(--ok)}
.cmd-prefix{color:var(--text3);user-select:none}

/* Priority badges */
.pri{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;white-space:nowrap}
.pri-high{background:var(--crit-bg);color:var(--high)}
.pri-medium{background:var(--warn-bg);color:var(--medium)}
.pri-low{background:var(--info-bg);color:var(--low)}

/* Optional tools */
.tool-card{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin-bottom:8px;display:flex;align-items:center;gap:12px}
.tool-card .tool-icon{width:32px;height:32px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.tool-installed{background:var(--ok-bg);color:var(--ok)}
.tool-missing{background:var(--warn-bg);color:var(--warn)}
.tool-info{flex:1}
.tool-name{font-weight:600;font-size:14px}
.tool-desc{font-size:12px;color:var(--text2)}
.tool-status{font-size:11px;font-weight:600;padding:3px 10px;border-radius:4px}

/* Nav tabs */
.nav-tabs{display:flex;gap:2px;margin-bottom:20px;border-bottom:1px solid var(--border);overflow-x:auto}
.nav-tab{padding:10px 18px;cursor:pointer;font-size:13px;font-weight:500;color:var(--text2);border-bottom:2px solid transparent;transition:all .15s;white-space:nowrap;user-select:none}
.nav-tab:hover{color:var(--text)}
.nav-tab.active{color:var(--accent);border-bottom-color:var(--accent)}

/* Loading / Error / Empty */
.loading{text-align:center;padding:60px;color:var(--text2);font-size:15px}
.error{text-align:center;padding:60px;color:var(--crit);font-size:15px}
.empty{text-align:center;padding:30px;color:var(--text2);font-size:14px}
.empty-icon{font-size:28px;margin-bottom:8px;opacity:.5}

/* Animations */
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.fade-in{animation:fadeIn .3s ease}

/* Print */
@media print{
  body{background:#fff;color:#000}
  .card{border:1px solid #ddd;break-inside:avoid}
  header select,.refresh-btn,.search-box,.filter-btn,.expand-btn,.copy-btn,.nav-tabs{display:none!important}
  .acc-body{max-height:none!important;display:block!important}
  .guide-body{max-height:none!important}
  .container{max-width:100%;padding:10px}
}

/* Responsive */
@media(max-width:768px){
  .grid-2,.grid-3{grid-template-columns:1fr}
  .score-section{flex-direction:column}
  header{flex-direction:column;align-items:flex-start}
  .header-right{width:100%}
  .cat-bar-label{width:70px;font-size:11px}
  .nav-tabs{gap:0}
  .nav-tab{padding:8px 12px;font-size:12px}
}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="header-left">
      <div class="shield">
        <svg viewBox="0 0 36 36" fill="none">
          <path d="M18 2L4 8v10c0 9.05 5.97 17.52 14 20 8.03-2.48 14-10.95 14-20V8L18 2z" fill="rgba(88,166,255,.15)" stroke="var(--accent)" stroke-width="1.5"/>
          <path d="M15 18l3 3 5-6" stroke="var(--ok)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
        </svg>
      </div>
      <h1>GUARDIAN</h1>
    </div>
    <div class="header-right">
      <button class="refresh-btn" onclick="refreshDashboard()" title="Refresh data">
        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 3a5 5 0 0 0-4.546 2.914.5.5 0 1 1-.908-.418A6 6 0 1 1 2.25 9.665a.5.5 0 1 1 .958.286A5 5 0 1 0 8 3z"/><path d="M8 4.466V.534a.25.25 0 0 1 .41-.192l2.36 1.966c.12.1.12.284 0 .384L8.41 4.658A.25.25 0 0 1 8 4.466z"/></svg>
        Refresh
      </button>
      <select id="reportSelect" title="Select report"></select>
      <div class="meta" id="metaInfo">
        <span id="statusDot"></span>
        <span id="metaText">Loading...</span>
      </div>
    </div>
  </header>

  <div class="nav-tabs" id="navTabs">
    <div class="nav-tab active" data-tab="overview" onclick="switchTab('overview')">Overview</div>
    <div class="nav-tab" data-tab="guide" onclick="switchTab('guide')">Install Guide</div>
    <div class="nav-tab" data-tab="actions" onclick="switchTab('actions')">Action Items</div>
    <div class="nav-tab" data-tab="findings" onclick="switchTab('findings')">All Findings</div>
  </div>

  <div id="dashboard">
    <div class="loading">Loading dashboard...</div>
  </div>
</div>

<script>
/* ── Helpers ─────────────────────────────────────────────────── */
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const esc = s => { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; };

let reports = [], currentReport = null, currentHistory = [], activeTab = 'overview', activeSevFilter = null, searchText = '';

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(r.statusText);
  return r.json();
}

/* ── Colors & formatting ─────────────────────────────────────── */
function gradeColor(g) { return g==='A'?'var(--ok)':g==='B'?'var(--info)':g==='C'?'var(--warn)':'var(--crit)'; }
function gaugeColor(s) { return s>=90?'var(--ok)':s>=75?'var(--info)':s>=50?'var(--warn)':'var(--crit)'; }
function sevColor(s) { return {OK:'var(--ok)',INFO:'var(--info)',WARNING:'var(--warn)',CRITICAL:'var(--crit)'}[s]||'var(--text2)'; }

function fmtDate(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'})+' '+d.toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit'});
  } catch { return iso; }
}

function relTime(iso) {
  try {
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff/60) + 'm ago';
    if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff/86400) + 'd ago';
    return fmtDate(iso);
  } catch { return ''; }
}

function nextGradeInfo(score) {
  if (score >= 90) return null;
  const thresholds = [{g:'A',t:90},{g:'B',t:80},{g:'C',t:65}];
  for (const {g,t} of thresholds) { if (score < t) return {grade:g, pts:t-score}; }
  return null;
}

/* ── Clipboard ───────────────────────────────────────────────── */
function copyCmd(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
  });
}

/* ── Step parser ─────────────────────────────────────────────── */
function parseGuideContent(detail) {
  if (!detail) return {why:'', steps:[]};
  const lines = detail.split('\n');
  let why = '', steps = [], currentStep = null;

  for (let line of lines) {
    const trimmed = line.trim();
    const stepMatch = trimmed.match(/^Step\s+(\d+)\s*:\s*(.*)$/i);
    if (stepMatch) {
      if (currentStep) steps.push(currentStep);
      currentStep = {num: parseInt(stepMatch[1]), text: stepMatch[2], extra: []};
    } else if (trimmed.toLowerCase() === 'done.' || trimmed.toLowerCase() === 'done!') {
      if (currentStep) { currentStep.done = true; steps.push(currentStep); currentStep = null; }
      else steps.push({num: steps.length+1, text: 'Done!', done: true, extra: []});
    } else if (currentStep) {
      if (trimmed) currentStep.extra.push(trimmed);
    } else if (trimmed && !steps.length) {
      why += (why ? '\n' : '') + trimmed;
    }
  }
  if (currentStep) steps.push(currentStep);
  return {why, steps};
}

function isCommand(text) {
  const cmdPatterns = /^(sudo |security |defaults |softwareupdate |networksetup |spctl |csrutil |fdesetup |launchctl |brew |open |python3 |curl |git |chmod |chown |mkdir |cp |mv |ln |export |source |\.\/|\/usr|\/bin|\/opt|tmutil )/;
  return cmdPatterns.test(text.trim());
}

function renderSteps(steps) {
  if (!steps.length) return '';
  return '<div class="steps">' + steps.map(s => {
    const combined = s.text + (s.extra.length ? '\n' + s.extra.join('\n') : '');
    const lines = combined.split('\n');
    let html = '';
    for (const ln of lines) {
      if (isCommand(ln.trim())) {
        html += renderCmdBlock(ln.trim());
      } else {
        html += '<div>' + (s.done && ln.trim().match(/^done/i) ? '<span class="step-done">' + esc(ln) + '</span>' : esc(ln)) + '</div>';
      }
    }
    return `<div class="step"><div class="step-num">${s.num}</div><div class="step-text">${html}</div></div>`;
  }).join('') + '</div>';
}

function renderCmdBlock(cmd) {
  const escaped = esc(cmd);
  const b64 = btoa(unescape(encodeURIComponent(cmd)));
  return `<div class="cmd-block"><span class="cmd-prefix">$</span> <code>${escaped}</code><button class="copy-btn" data-cmd="${b64}" onclick="event.stopPropagation();copyCmd(this,decodeURIComponent(escape(atob(this.dataset.cmd))))">Copy</button></div>`;
}

/* ── Gauge ───────────────────────────────────────────────────── */
function renderGauge(score) {
  const r = 62, c = 2*Math.PI*r, pct = Math.max(0,Math.min(100,score))/100;
  const offset = c*(1-pct), color = gaugeColor(score);
  return `<div class="gauge"><svg viewBox="0 0 150 150"><circle cx="75" cy="75" r="${r}" class="gauge-bg"/><circle cx="75" cy="75" r="${r}" class="gauge-fill" stroke="${color}" stroke-dasharray="${c}" stroke-dashoffset="${offset}"/></svg><div class="gauge-text"><span class="score-num" style="color:${color}">${score}</span><span class="score-label">/ 100</span></div></div>`;
}

/* ── Chart ───────────────────────────────────────────────────── */
function renderChart(history) {
  if (!history || history.length < 2) return '<div class="empty"><div class="empty-icon">&#128200;</div>Not enough data for chart yet</div>';
  const pts = history.slice(-20);
  const w = 800, h = 180, pad = 40, padR = 20, padB = 30;
  const cw = w-pad-padR, ch = h-20-padB;
  const scores = pts.map(p=>p.score);
  const minS = Math.max(0, Math.min(...scores)-10);
  const maxS = Math.min(100, Math.max(...scores)+10);
  const range = maxS-minS||1;

  const coords = pts.map((p,i) => {
    const x = pad + (i/(pts.length-1))*cw;
    const y = 20 + ch - ((p.score-minS)/range)*ch;
    return [x, y];
  });

  const polyline = coords.map(c=>c.join(',')).join(' ');
  const area = `${pad},${20+ch} ${polyline} ${coords[coords.length-1][0]},${20+ch}`;

  let grid = '';
  const step = Math.max(1, Math.ceil(range/4));
  for (let v = Math.ceil(minS/step)*step; v <= maxS; v += step) {
    const y = 20 + ch - ((v-minS)/range)*ch;
    grid += `<line x1="${pad}" y1="${y}" x2="${w-padR}" y2="${y}" class="chart-grid"/>`;
    grid += `<text x="${pad-6}" y="${y+4}" class="chart-label" text-anchor="end">${v}</text>`;
  }

  const labelIdxs = [0, Math.floor(pts.length/2), pts.length-1];
  let labels = '';
  labelIdxs.forEach(i => {
    const d = new Date(pts[i].date);
    const lbl = d.toLocaleDateString('en-US',{month:'short',day:'numeric'});
    labels += `<text x="${coords[i][0]}" y="${h-4}" class="chart-label" text-anchor="middle">${lbl}</text>`;
  });

  const dots = coords.map((c,i) => `<circle cx="${c[0]}" cy="${c[1]}" class="chart-dot" data-idx="${i}" onmouseenter="showChartTip(event,${i})" onmouseleave="hideChartTip()"/>`).join('');

  return `<div class="chart-container"><svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet"><defs><linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="var(--accent)"/><stop offset="100%" stop-color="transparent"/></linearGradient></defs>${grid}<polygon points="${area}" class="chart-area"/><polyline points="${polyline}" class="chart-line"/>${dots}${labels}</svg><div class="chart-tooltip" id="chartTip"></div></div>`;
}

function showChartTip(evt, idx) {
  const tip = $('#chartTip');
  if (!tip || !currentHistory) return;
  const pts = currentHistory.slice(-20);
  const p = pts[idx];
  if (!p) return;
  tip.innerHTML = `<strong>${p.score}/100</strong><br>${fmtDate(p.date)}<br><span style="font-size:11px;color:var(--text3)">${p.critical} critical, ${p.warning} warning</span>`;
  const rect = evt.target.closest('.chart-container').getBoundingClientRect();
  const cx = evt.clientX - rect.left, cy = evt.clientY - rect.top;
  tip.style.left = (cx+12)+'px';
  tip.style.top = (cy-10)+'px';
  tip.classList.add('visible');
}
function hideChartTip() { const t=$('#chartTip'); if(t) t.classList.remove('visible'); }

/* ── Severity counts ─────────────────────────────────────────── */
function sevCounts(findings) {
  const c = {OK:0,INFO:0,WARNING:0,CRITICAL:0};
  findings.forEach(f => { if(c[f.severity]!==undefined) c[f.severity]++; });
  return c;
}

/* ── Category chart ──────────────────────────────────────────── */
function renderCatChart(findings) {
  const cats = {};
  findings.forEach(f => {
    if (!cats[f.category]) cats[f.category] = {OK:0,INFO:0,WARNING:0,CRITICAL:0,total:0};
    cats[f.category][f.severity]++;
    cats[f.category].total++;
  });
  const sorted = Object.entries(cats).sort((a,b) => {
    const wo = c => (c.CRITICAL*1000 + c.WARNING*100 + c.INFO*10);
    return wo(b[1]) - wo(a[1]);
  }).slice(0, 12);

  const max = Math.max(...sorted.map(([,c])=>c.total));
  return '<div class="cat-chart">' + sorted.map(([name, c]) => {
    const pct = t => (t/max*100).toFixed(1);
    return `<div class="cat-bar-row"><span class="cat-bar-label" title="${esc(name)}">${esc(name)}</span><div class="cat-bar-track">${c.CRITICAL?`<div class="cat-bar-seg" style="width:${pct(c.CRITICAL)}%;background:var(--crit)"></div>`:''}${c.WARNING?`<div class="cat-bar-seg" style="width:${pct(c.WARNING)}%;background:var(--warn)"></div>`:''}${c.INFO?`<div class="cat-bar-seg" style="width:${pct(c.INFO)}%;background:var(--info)"></div>`:''}${c.OK?`<div class="cat-bar-seg" style="width:${pct(c.OK)}%;background:var(--ok)"></div>`:''}</div><span class="cat-bar-count">${c.total}</span></div>`;
  }).join('') + '</div>';
}

/* ── Severity bar ────────────────────────────────────────────── */
function renderSeverityBar(counts) {
  const makeClick = sev => `onclick="toggleSevFilter('${sev}')"`;
  return `<div class="severity-bar">
    <span class="badge badge-crit" ${makeClick('CRITICAL')} id="badge-CRITICAL"><span class="count">${counts.CRITICAL}</span> CRITICAL</span>
    <span class="badge badge-warn" ${makeClick('WARNING')} id="badge-WARNING"><span class="count">${counts.WARNING}</span> WARNING</span>
    <span class="badge badge-info" ${makeClick('INFO')} id="badge-INFO"><span class="count">${counts.INFO}</span> INFO</span>
    <span class="badge badge-ok" ${makeClick('OK')} id="badge-OK"><span class="count">${counts.OK}</span> OK</span>
  </div>`;
}

function toggleSevFilter(sev) {
  if (activeSevFilter === sev) { activeSevFilter = null; } else { activeSevFilter = sev; }
  $$('.badge').forEach(b => b.classList.remove('active'));
  if (activeSevFilter) { const el = $(`#badge-${activeSevFilter}`); if(el) el.classList.add('active'); }
  renderFindingsSection();
}
function clearSevFilter() {
  activeSevFilter = null;
  $$('.filter-btn').forEach(b => b.classList.remove('active'));
  renderFindingsSection();
}

/* ── Findings ────────────────────────────────────────────────── */
function getFilteredFindings() {
  if (!currentReport) return [];
  let f = currentReport.findings || [];
  if (activeSevFilter) f = f.filter(x => x.severity === activeSevFilter);
  if (searchText) {
    const q = searchText.toLowerCase();
    f = f.filter(x => x.title.toLowerCase().includes(q) || x.category.toLowerCase().includes(q) || (x.detail||'').toLowerCase().includes(q) || (x.fix||'').toLowerCase().includes(q));
  }
  return f;
}

function renderFindingsAccordion(findings) {
  const cats = {};
  findings.forEach(f => { if(!cats[f.category]) cats[f.category]=[]; cats[f.category].push(f); });
  const sorted = Object.keys(cats).sort((a,b) => {
    const o = s => s==='CRITICAL'?0:s==='WARNING'?1:s==='INFO'?2:3;
    return Math.min(...cats[a].map(f=>o(f.severity))) - Math.min(...cats[b].map(f=>o(f.severity)));
  });
  if (!sorted.length) return '<div class="empty"><div class="empty-icon">&#128269;</div>No findings match your filter</div>';

  return sorted.map(cat => {
    const items = cats[cat];
    const worst = items.reduce((w,f) => {
      const o = {CRITICAL:0,WARNING:1,INFO:2,OK:3};
      return (o[f.severity]??3)<(o[w]??3)?f.severity:w;
    },'OK');

    const findingsHtml = items.map(f => {
      const badge = `<span class="sev sev-${f.severity.toLowerCase()}">${f.severity}</span>`;
      const detail = f.detail ? `<div class="detail">${esc(f.detail)}</div>` : '';
      let fixHtml = '';
      if (f.fix) {
        const fixText = f.fix;
        if (isCommand(fixText) || fixText.startsWith('Terminal:')) {
          const cmd = fixText.replace(/^Terminal:\s*/,'');
          fixHtml = `<div class="fix-line"><span class="fix-label">Fix:</span></div>${renderCmdBlock(cmd)}`;
        } else {
          fixHtml = `<div class="fix-line"><span class="fix-label">Fix:</span> <span class="fix-text">${esc(fixText)}</span></div>`;
        }
      }
      return `<div class="finding"><div class="finding-header">${badge} <span class="title">${esc(f.title)}</span></div>${detail}${fixHtml}</div>`;
    }).join('');

    return `<div class="accordion"><div class="acc-header" onclick="toggleAcc(this)"><span class="sev sev-${worst.toLowerCase()}">${worst}</span> <span class="cat">${esc(cat)}</span> <span class="cat-count">${items.length} check${items.length>1?'s':''}</span><span class="arrow">&#9654;</span></div><div class="acc-body"><div class="acc-body-inner">${findingsHtml}</div></div></div>`;
  }).join('');
}

function renderFindingsSection() {
  const el = $('#findingsContent');
  if (!el) return;
  el.innerHTML = renderFindingsAccordion(getFilteredFindings());
}

/* ── Action items ────────────────────────────────────────────── */
function renderActions(findings) {
  const actionable = findings.filter(f => f.severity==='CRITICAL'||f.severity==='WARNING');
  if (!actionable.length) return '<div class="empty"><div class="empty-icon">&#9989;</div>No action items — your Mac is looking good!</div>';
  actionable.sort((a,b) => (a.severity==='CRITICAL'?0:1)-(b.severity==='CRITICAL'?0:1));
  return actionable.map(f => {
    const cls = f.severity==='CRITICAL'?'':' warn-item';
    const badge = `<span class="sev sev-${f.severity.toLowerCase()}">${f.severity}</span>`;
    let fixHtml = '';
    if (f.fix) {
      if (isCommand(f.fix) || f.fix.startsWith('Terminal:')) {
        const cmd = f.fix.replace(/^Terminal:\s*/,'');
        fixHtml = renderCmdBlock(cmd);
      } else {
        fixHtml = `<div class="ai-fix">${esc(f.fix)}</div>`;
      }
    }
    return `<div class="action-item${cls}"><div class="ai-header">${badge}<span class="ai-title">${esc(f.title)}</span><span class="ai-category">${esc(f.category)}</span></div>${fixHtml}</div>`;
  }).join('');
}

/* ── Install Guide (suggestions) ─────────────────────────────── */
function renderInstallGuide(suggestions) {
  if (!suggestions || !suggestions.length) return '<div class="empty"><div class="empty-icon">&#127942;</div>No suggestions — your security is maxed out!</div>';
  const order = {HIGH:0,MEDIUM:1,LOW:2};
  const sorted = [...suggestions].sort((a,b) => (order[a.priority]??2)-(order[b.priority]??2));
  return sorted.map((s, idx) => {
    const pri = `<span class="pri pri-${s.priority.toLowerCase()}">${s.priority}</span>`;
    const parsed = parseGuideContent(s.detail);
    let whyHtml = parsed.why ? `<div class="guide-why">${esc(parsed.why)}</div>` : '';
    let stepsHtml = renderSteps(parsed.steps);
    if (!parsed.steps.length && s.detail) {
      stepsHtml = `<div style="color:var(--text2);font-size:13px;white-space:pre-wrap;line-height:1.6">${esc(s.detail)}</div>`;
    }
    return `<div class="guide-card fade-in" style="animation-delay:${idx*0.05}s"><div class="guide-header" onclick="toggleGuide(this)">${pri} <span class="guide-title">${esc(s.title)}</span><span class="arrow">&#9654;</span></div><div class="guide-body"><div class="guide-content">${whyHtml}${stepsHtml}</div></div></div>`;
  }).join('');
}

/* ── Optional tools section ──────────────────────────────────── */
function renderOptionalTools(report) {
  const installed = report.optional_tools || [];
  const allTools = [
    {ids:['osquery','osqueryi'], name:'osquery', desc:'Advanced system queries — 40+ extra security checks', installCmd:'brew install osquery'},
    {ids:['clamscan','freshclam','clamav'], name:'ClamAV', desc:'Open-source antivirus scanner for malware detection', installCmd:'brew install clamav && sudo freshclam'},
    {ids:['terminal-notifier'], name:'terminal-notifier', desc:'Native macOS notifications for scan alerts', installCmd:'brew install terminal-notifier'},
  ];
  return allTools.map(t => {
    const isInstalled = t.ids.some(id => installed.includes(id));
    const icon = isInstalled ? '&#10003;' : '&#9888;';
    const iconCls = isInstalled ? 'tool-installed' : 'tool-missing';
    const statusText = isInstalled ? 'Installed' : 'Not installed';
    const statusCls = isInstalled ? 'sev-ok' : 'sev-warning';
    let installHtml = '';
    if (!isInstalled) {
      installHtml = `<div style="margin-top:8px">${renderCmdBlock(t.installCmd)}</div>`;
    }
    return `<div class="tool-card"><div class="tool-icon ${iconCls}">${icon}</div><div class="tool-info"><div class="tool-name">${esc(t.name)}</div><div class="tool-desc">${esc(t.desc)}</div>${installHtml}</div><span class="sev ${statusCls}" style="flex-shrink:0">${statusText}</span></div>`;
  }).join('');
}

/* ── Toggles ─────────────────────────────────────────────────── */
function toggleAcc(el) { el.classList.toggle('open'); el.nextElementSibling.classList.toggle('open'); }
function toggleGuide(el) { el.classList.toggle('open'); el.nextElementSibling.classList.toggle('open'); }
function expandAllAcc() { $$('.acc-header').forEach(h=>{h.classList.add('open');h.nextElementSibling.classList.add('open')}); }
function collapseAllAcc() { $$('.acc-header').forEach(h=>{h.classList.remove('open');h.nextElementSibling.classList.remove('open')}); }
function expandAllGuides() { $$('.guide-header').forEach(h=>{h.classList.add('open');h.nextElementSibling.classList.add('open')}); }
function collapseAllGuides() { $$('.guide-header').forEach(h=>{h.classList.remove('open');h.nextElementSibling.classList.remove('open')}); }

/* ── Tabs ────────────────────────────────────────────────────── */
function switchTab(tab) {
  activeTab = tab;
  $$('.nav-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  renderCurrentTab();
}

/* ── Tab renderers ───────────────────────────────────────────── */
function renderOverviewTab(report, history) {
  const counts = sevCounts(report.findings||[]);
  const trend = computeTrend(history);
  const ng = nextGradeInfo(report.score);
  const totalChecks = (report.findings||[]).length;
  const categories = new Set((report.findings||[]).map(f=>f.category)).size;

  return `
    <div class="grid grid-2 section">
      <div class="card">
        <h2>Security Score</h2>
        <div class="score-section">
          ${renderGauge(report.score)}
          <div class="grade-wrap">
            <div class="grade-letter" style="color:${gradeColor(report.grade)}">${esc(report.grade)}</div>
            ${trend}
            ${ng ? `<div class="next-grade">${ng.pts} point${ng.pts>1?'s':''} to ${ng.grade}</div>` : '<div class="next-grade" style="color:var(--ok)">Top grade!</div>'}
          </div>
        </div>
        <div class="stats-bar" style="margin-top:18px;justify-content:center;gap:28px">
          <div class="stat-item"><span class="stat-value">${totalChecks}</span><span class="stat-label">Checks</span></div>
          <div class="stat-item"><span class="stat-value">${categories}</span><span class="stat-label">Categories</span></div>
          <div class="stat-item"><span class="stat-value" style="color:${counts.CRITICAL?'var(--crit)':'var(--ok)'}">${counts.CRITICAL}</span><span class="stat-label">Critical</span></div>
          <div class="stat-item"><span class="stat-value" style="color:${counts.WARNING?'var(--warn)':'var(--ok)'}">${counts.WARNING}</span><span class="stat-label">Warnings</span></div>
        </div>
      </div>
      <div class="card">
        <h2>Score History</h2>
        ${renderChart(history)}
      </div>
    </div>

    <div class="grid grid-2 section">
      <div class="card">
        <h2>Severity Summary</h2>
        ${renderSeverityBar(counts)}
      </div>
      <div class="card">
        <h2>Category Breakdown <span class="h2-count">Top ${Math.min(12, categories)}</span></h2>
        ${renderCatChart(report.findings||[])}
      </div>
    </div>

    <div class="grid grid-2 section">
      <div class="card">
        <h2>Action Items <span class="h2-count">${(report.findings||[]).filter(f=>f.severity==='CRITICAL'||f.severity==='WARNING').length}</span></h2>
        <div style="max-height:500px;overflow-y:auto">${renderActions(report.findings||[])}</div>
      </div>
      <div class="card">
        <h2>Top Suggestions <span class="h2-count">${(report.suggestions||[]).length}</span></h2>
        <div style="max-height:500px;overflow-y:auto">${renderInstallGuide((report.suggestions||[]).slice(0,5))}</div>
        ${(report.suggestions||[]).length > 5 ? '<div style="text-align:center;margin-top:10px"><button class="filter-btn" onclick="switchTab(\'guide\')">View all ' + (report.suggestions||[]).length + ' suggestions &#8594;</button></div>' : ''}
      </div>
    </div>

    <div class="card section">
      <h2>Optional Security Tools</h2>
      ${renderOptionalTools(report)}
    </div>
  `;
}

function renderGuideTab(report) {
  const suggestions = report.suggestions || [];
  const findings = report.findings || [];
  const actionable = findings.filter(f => f.severity==='CRITICAL'||f.severity==='WARNING');

  return `
    <div class="section">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
        <div style="font-size:14px;color:var(--text2)">${suggestions.length} recommendation${suggestions.length!==1?'s':''} to improve your security score</div>
        <div>
          <button class="expand-btn" onclick="expandAllGuides()">Expand all</button>
          <button class="expand-btn" onclick="collapseAllGuides()">Collapse all</button>
        </div>
      </div>
    </div>

    ${actionable.length ? `
    <div class="section">
      <div class="card">
        <h2>Fix These First <span class="h2-count">${actionable.length} issue${actionable.length>1?'s':''}</span></h2>
        <p style="color:var(--text2);font-size:13px;margin-bottom:14px">These findings are actively lowering your score. Each warning costs 5 points; each critical costs 15.</p>
        ${renderActions(findings)}
      </div>
    </div>` : ''}

    <div class="section">
      <div class="card">
        <h2>Complete Install &amp; Setup Guide <span class="h2-count">${suggestions.length}</span></h2>
        ${renderInstallGuide(suggestions)}
      </div>
    </div>

    <div class="section">
      <div class="card">
        <h2>Optional Security Tools</h2>
        <p style="color:var(--text2);font-size:13px;margin-bottom:14px">These free tools unlock extra Guardian checks. Install via Homebrew (if you don't have Homebrew, install it first).</p>
        ${renderCmdBlock('/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')}
        <div style="margin-top:14px">${renderOptionalTools(report)}</div>
      </div>
    </div>
  `;
}

function renderActionsTab(report) {
  const findings = report.findings || [];
  const crit = findings.filter(f=>f.severity==='CRITICAL');
  const warn = findings.filter(f=>f.severity==='WARNING');

  return `
    ${crit.length ? `<div class="section"><div class="card" style="border-color:var(--crit)">
      <h2 style="color:var(--crit)">Critical Issues <span class="h2-count" style="background:var(--crit-bg);color:var(--crit)">${crit.length}</span></h2>
      <p style="color:var(--text2);font-size:13px;margin-bottom:14px">These are serious security risks. Each one reduces your score by 15 points. Fix these immediately.</p>
      ${crit.map(f => {
        let fixHtml = '';
        if (f.fix) {
          if (isCommand(f.fix) || f.fix.startsWith('Terminal:')) {
            fixHtml = renderCmdBlock(f.fix.replace(/^Terminal:\s*/,''));
          } else {
            fixHtml = `<div class="ai-fix">${esc(f.fix)}</div>`;
          }
        }
        const detail = f.detail ? `<div style="color:var(--text2);font-size:13px;margin:6px 0;white-space:pre-wrap">${esc(f.detail)}</div>` : '';
        return `<div class="action-item"><div class="ai-header"><span class="sev sev-critical">CRITICAL</span><span class="ai-title">${esc(f.title)}</span><span class="ai-category">${esc(f.category)}</span></div>${detail}${fixHtml}</div>`;
      }).join('')}
    </div></div>` : ''}

    ${warn.length ? `<div class="section"><div class="card" style="border-color:var(--warn)">
      <h2 style="color:var(--warn)">Warnings <span class="h2-count" style="background:var(--warn-bg);color:var(--warn)">${warn.length}</span></h2>
      <p style="color:var(--text2);font-size:13px;margin-bottom:14px">Each warning reduces your score by 5 points. Fixing all of these would add ${warn.length * 5} points to your score.</p>
      ${warn.map(f => {
        let fixHtml = '';
        if (f.fix) {
          if (isCommand(f.fix) || f.fix.startsWith('Terminal:')) {
            fixHtml = renderCmdBlock(f.fix.replace(/^Terminal:\s*/,''));
          } else {
            fixHtml = `<div class="ai-fix">${esc(f.fix)}</div>`;
          }
        }
        const detail = f.detail ? `<div style="color:var(--text2);font-size:13px;margin:6px 0;white-space:pre-wrap">${esc(f.detail)}</div>` : '';
        return `<div class="action-item warn-item"><div class="ai-header"><span class="sev sev-warning">WARNING</span><span class="ai-title">${esc(f.title)}</span><span class="ai-category">${esc(f.category)}</span></div>${detail}${fixHtml}</div>`;
      }).join('')}
    </div></div>` : ''}

    ${!crit.length && !warn.length ? '<div class="card"><div class="empty"><div class="empty-icon">&#127881;</div>No action items — your Mac is fully secured!</div></div>' : ''}

    <div class="section">
      <div class="card">
        <h2>Score Impact Calculator</h2>
        <p style="color:var(--text2);font-size:13px;margin-bottom:10px">Your current score: <strong>${report.score}/100</strong></p>
        <p style="color:var(--text2);font-size:13px">If you fix everything above, your score would be: <strong style="color:var(--ok)">${Math.min(100, report.score + crit.length*15 + warn.length*5)}/100</strong></p>
      </div>
    </div>
  `;
}

function renderFindingsTab(report) {
  return `
    <div class="toolbar">
      <input class="search-box" type="text" placeholder="Search findings..." value="${esc(searchText)}" oninput="searchText=this.value;renderFindingsSection()">
      <button class="filter-btn ${activeSevFilter==='CRITICAL'?'active':''}" onclick="toggleSevFilter('CRITICAL')">Critical</button>
      <button class="filter-btn ${activeSevFilter==='WARNING'?'active':''}" onclick="toggleSevFilter('WARNING')">Warning</button>
      <button class="filter-btn ${activeSevFilter==='INFO'?'active':''}" onclick="toggleSevFilter('INFO')">Info</button>
      <button class="filter-btn ${activeSevFilter==='OK'?'active':''}" onclick="toggleSevFilter('OK')">OK</button>
      ${activeSevFilter?'<button class="filter-btn" onclick="clearSevFilter()">Clear</button>':''}
      <button class="expand-btn" onclick="expandAllAcc()">Expand all</button>
      <button class="expand-btn" onclick="collapseAllAcc()">Collapse all</button>
    </div>
    <div id="findingsContent">${renderFindingsAccordion(getFilteredFindings())}</div>
  `;
}

/* ── Main renderer ───────────────────────────────────────────── */
function renderCurrentTab() {
  const dash = $('#dashboard');
  if (!currentReport) return;
  switch(activeTab) {
    case 'overview': dash.innerHTML = renderOverviewTab(currentReport, currentHistory); break;
    case 'guide':    dash.innerHTML = renderGuideTab(currentReport); break;
    case 'actions':  dash.innerHTML = renderActionsTab(currentReport); break;
    case 'findings': dash.innerHTML = renderFindingsTab(currentReport); break;
  }
}

function computeTrend(history) {
  if (!history || history.length < 2) return '';
  const cur = history[history.length-1].score, prev = history[history.length-2].score;
  const diff = cur - prev;
  if (diff > 0) return `<div class="trend-badge trend-up">&#9650; +${diff}</div>`;
  if (diff < 0) return `<div class="trend-badge trend-down">&#9660; ${diff}</div>`;
  return `<div class="trend-badge trend-flat">&#9644; No change</div>`;
}

/* ── Data loading ────────────────────────────────────────────── */
async function loadReportList() {
  try {
    reports = await api('/api/reports');
    const sel = $('#reportSelect');
    sel.innerHTML = reports.map((ts, i) => {
      const d = ts.replace(/_/g,' ').replace(/-/g,(m,off)=>off>4&&off<10?'-':off>10?':':'-');
      return `<option value="${ts}"${i===0?' selected':''}>${d}${i===0?' (latest)':''}</option>`;
    }).join('');
    sel.onchange = () => loadReport(sel.value);
  } catch { reports = []; }
}

async function loadReport(timestamp) {
  const dash = $('#dashboard');
  try {
    const url = timestamp ? `/api/report/${timestamp}` : '/api/latest';
    const [report, history] = await Promise.all([api(url), api('/api/history')]);
    currentReport = report;
    currentHistory = history;

    // Status dot
    const age = (Date.now() - new Date(report.date).getTime()) / 1000;
    const dotEl = $('#statusDot');
    const metaEl = $('#metaText');
    if (age < 14400) { dotEl.innerHTML = '<span class="status-dot status-active"></span>'; }
    else if (age < 86400) { dotEl.innerHTML = '<span class="status-dot status-stale"></span>'; }
    else { dotEl.innerHTML = '<span class="status-dot status-old"></span>'; }
    metaEl.textContent = relTime(report.date) + ' — ' + fmtDate(report.date);

    // Update tab counts
    const actionCount = (report.findings||[]).filter(f=>f.severity==='CRITICAL'||f.severity==='WARNING').length;
    const guideCount = (report.suggestions||[]).length;
    const findCount = (report.findings||[]).length;
    const tabs = $$('.nav-tab');
    tabs.forEach(t => {
      const tab = t.dataset.tab;
      if (tab==='actions' && actionCount) t.textContent = `Action Items (${actionCount})`;
      if (tab==='guide') t.textContent = `Install Guide (${guideCount})`;
      if (tab==='findings') t.textContent = `All Findings (${findCount})`;
    });

    renderCurrentTab();
  } catch (e) {
    dash.innerHTML = `<div class="error">Failed to load report: ${esc(e.message)}<br><br><span style="color:var(--text2)">Run <code>python3 ~/guardian/guardian.py</code> to generate a scan first.</span></div>`;
  }
}

async function refreshDashboard() {
  const btn = $('.refresh-btn');
  btn.classList.add('spinning');
  try {
    await loadReport($('#reportSelect').value || reports[0] || null);
  } finally {
    setTimeout(() => btn.classList.remove('spinning'), 300);
  }
}

/* ── Auto-refresh every 60s ──────────────────────────────────── */
setInterval(() => {
  if (document.visibilityState === 'visible') {
    loadReportList().then(() => {
      const sel = $('#reportSelect');
      if (sel && sel.selectedIndex === 0 && reports.length) loadReport(reports[0]);
    });
  }
}, 60000);

/* ── Init ────────────────────────────────────────────────────── */
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
        path = self.path.split("?")[0]

        if path == "/":
            self._send(DASHBOARD_HTML, content_type="text/html")
        elif path == "/api/latest":
            self._serve_latest()
        elif path == "/api/history":
            self._serve_history()
        elif path == "/api/reports":
            self._serve_report_list()
        elif path.startswith("/api/report/"):
            self._serve_report(path[len("/api/report/"):])
        else:
            self._error(404, "Not found")

    def _serve_latest(self):
        try:
            files = sorted(REPORTS_DIR.glob("*.json"), reverse=True)
            if not files:
                self._error(404, "No reports found. Run guardian.py first.")
                return
            self._send(files[0].read_text(encoding="utf-8"))
        except Exception as e:
            self._error(500, str(e))

    def _serve_history(self):
        try:
            if SCORES_FILE.exists():
                self._send(SCORES_FILE.read_text(encoding="utf-8"))
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
            self._send(json.dumps([f.stem for f in files]))
        except Exception as e:
            self._error(500, str(e))

    def _serve_report(self, timestamp):
        if not TIMESTAMP_RE.match(timestamp):
            self._error(400, "Invalid timestamp format")
            return
        report_file = REPORTS_DIR / f"{timestamp}.json"
        if not report_file.exists():
            self._error(404, "Report not found")
            return
        try:
            self._send(report_file.read_text(encoding="utf-8"))
        except Exception as e:
            self._error(500, str(e))


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Guardian Web Dashboard")
    parser.add_argument("--port", type=int, default=8845, help="Port (default: 8845)")
    args = parser.parse_args()

    class ReuseHTTPServer(HTTPServer):
        allow_reuse_address = True
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            super().server_bind()

    server = ReuseHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"\n  Guardian Dashboard running at http://127.0.0.1:{args.port}")
    print(f"  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
