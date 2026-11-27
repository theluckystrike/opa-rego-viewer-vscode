/* global acquireVsCodeApi */
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const app = document.getElementById('app');

  let state = {
    name: '',
    summary: null,
    pageSize: 100,
    page: 0,
    total: 0,
    rows: [],
    selected: null,
    tab: 'rules',
    req: 0,
  };

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function post(msg) {
    state.req += 1;
    vscode.postMessage({ ...msg, req: state.req });
  }

  function fmtSize(n) {
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  }

  function renderShell() {
    const s = state.summary;
    const errChip = s.findingErrors > 0 ? `<span class="chip bad"><b>Errors:</b> ${s.findingErrors}</span>` : '<span class="chip"><b>Errors:</b> 0</span>';
    const warnChip = s.findingWarnings > 0 ? `<span class="chip warn"><b>Warnings:</b> ${s.findingWarnings}</span>` : '';

    app.innerHTML = `
      <div class="top">
        <div class="title">
          <span class="name">${esc(s.title || state.name)}</span>
          <span class="kind">package ${esc(s.packageName)} · ${s.hasRegoV1 ? 'rego.v1' : 'legacy rego'} · ${s.totalLines} lines · ${fmtSize(s.fileSize)} · 100% offline (no OPA binary or network calls)</span>
        </div>
        <div class="summary">
          <span class="chip"><b>Rules:</b> ${s.ruleCount} (${s.entrypointCount} entry / ${s.defaultCount} default / ${s.functionCount} fn)</span>
          <span class="chip"><b>Imports:</b> ${s.importCount}</span>
          <span class="chip"><b>input.*:</b> ${s.inputPathCount}</span>
          <span class="chip"><b>data.*:</b> ${s.dataPathCount}</span>
          ${errChip}${warnChip}
        </div>
        <div class="toolbar">
          <input id="q" type="search" placeholder="Filter by rule, kind, signature, input.*, data.*..." />
          <select id="kindFilter">
            <option value="">All rules &amp; functions</option>
            <option value="entrypoint">Entrypoints (allow/deny/violation)</option>
            <option value="default">Defaults</option>
            <option value="function">Functions</option>
            <option value="helper">Helper rules</option>
            <option value="findings">With Findings</option>
          </select>
          <button id="filterBtn" type="button">Filter</button>
          <span class="sep"></span>
          <div id="protools"></div>
        </div>
        <div class="tabs">
          <button class="tab on" data-tab="rules" type="button">Rules &amp; Functions (${s.ruleCount})</button>
          <button class="tab" data-tab="refs" type="button">Input / Data Refs (${(s.refs || []).length})</button>
          <button class="tab" data-tab="findings" type="button">Findings (${(s.findings || []).length})</button>
        </div>
        <div id="hint" class="hint"></div>
      </div>
      <div class="main">
        <div id="leftPane" class="tablewrap"></div>
        <div id="detail" class="detail"><p class="muted">Select a rule, reference or finding to inspect its Rego policy details.</p></div>
      </div>
      <div class="pager">
        <button id="prev" type="button">Prev</button>
        <span id="pageInfo"></span>
        <button id="next" type="button">Next</button>
      </div>
    `;

    const q = document.getElementById('q');
    const kSel = document.getElementById('kindFilter');
    const runFilter = () => {
      state.page = 0;
      post({ type: 'filter', filter: { text: q.value, kind: kSel.value } });
    };
    document.getElementById('filterBtn').addEventListener('click', runFilter);
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter') runFilter(); });
    kSel.addEventListener('change', runFilter);

    document.querySelectorAll('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach((b) => b.classList.remove('on'));
        btn.classList.add('on');
        state.tab = btn.dataset.tab;
        renderPane();
      });
    });

    document.getElementById('prev').addEventListener('click', () => {
      if (state.page > 0) { state.page -= 1; loadPage(); }
    });
    document.getElementById('next').addEventListener('click', () => {
      if ((state.page + 1) * state.pageSize < state.total) { state.page += 1; loadPage(); }
    });
  }

  function loadPage() {
    post({ type: 'page', from: state.page * state.pageSize, n: state.pageSize });
  }

  function bindRowClicks(left) {
    left.querySelectorAll('tbody tr[data-idx]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const idx = Number(tr.dataset.idx);
        state.selected = idx;
        left.querySelectorAll('tbody tr').forEach((row) => row.classList.toggle('sel', Number(row.dataset.idx) === idx));
        post({ type: 'detail', index: idx });
      });
    });
  }

  function renderPane() {
    const left = document.getElementById('leftPane');
    const pager = document.querySelector('.pager');
    const s = state.summary;

    if (state.tab === 'refs') {
      pager.style.display = 'none';
      const rRows = (s.refs || []).map((r) => `<tr data-idx="${r.index}"${state.selected === r.index ? ' class="sel"' : ''}>
        <td class="num">${r.line}</td>
        <td><code>${esc(r.rule)}</code></td>
        <td><strong>${esc(r.root)}</strong></td>
        <td><code>${esc(r.path)}</code></td>
      </tr>`).join('');
      left.innerHTML = `<table id="grid">
        <thead><tr><th class="num">Line</th><th>Rule</th><th>Root</th><th>Referenced Path</th></tr></thead>
        <tbody>${rRows || '<tr><td colspan="4" class="muted">No input.* or data.* references detected.</td></tr>'}</tbody>
      </table>`;
      bindRowClicks(left);
      return;
    }

    if (state.tab === 'findings') {
      pager.style.display = 'none';
      const fRows = (s.findings || []).map((f) => `<tr>
        <td class="${f.severity === 'error' ? 'bad' : 'warn-text'}"><strong>${esc(f.severity.toUpperCase())}</strong></td>
        <td>${esc(f.category)}</td>
        <td><code>${esc(f.rule)}</code></td>
        <td class="num">${f.line}</td>
        <td><code>${esc(f.ruleName)}</code></td>
        <td>${esc(f.message)}</td>
      </tr>`).join('');
      left.innerHTML = fRows
        ? `<table id="grid"><thead><tr><th>Severity</th><th>Category</th><th>Rule</th><th class="num">Line</th><th>Target</th><th>Finding</th></tr></thead><tbody>${fRows}</tbody></table>`
        : '<p class="muted" style="padding:12px;">No static Rego policy findings.</p>';
      return;
    }

    pager.style.display = 'flex';
    const body = state.rows.map((r) => {
      const sel = state.selected === r.index ? ' class="sel"' : '';
      const badge = r.badge ? `<span class="badge-muted">${esc(r.badge)}</span>` : '';
      const statusCls = r.errorCount > 0 ? 'bad' : (r.warningCount > 0 ? 'warn-text' : (r.kind === 'deny' || r.kind === 'violation' ? 'ok' : ''));
      return `<tr data-idx="${r.index}"${sel}>
        <td class="num">${r.line}</td>
        <td class="${statusCls}"><strong>${esc(r.kind)}</strong>${badge}</td>
        <td><code>${esc(r.name)}</code></td>
        <td><code>${esc(r.signature)}</code></td>
        <td><code>${esc(r.refsSummary)}</code></td>
        <td>${esc(r.risk)}</td>
      </tr>`;
    }).join('');
    left.innerHTML = `<table id="grid">
      <thead><tr><th class="num">Line</th><th>Kind</th><th>Name</th><th>Signature</th><th>Input / Data Refs</th><th>Risk</th></tr></thead>
      <tbody>${body || '<tr><td colspan="6" class="muted">No matching rules.</td></tr>'}</tbody>
    </table>`;
    bindRowClicks(left);

    const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
    document.getElementById('pageInfo').textContent = `Page ${state.page + 1} of ${pages} (${state.total} rules)`;
    document.getElementById('prev').disabled = state.page <= 0;
    document.getElementById('next').disabled = (state.page + 1) * state.pageSize >= state.total;
  }

  function renderDetail(d) {
    const el = document.getElementById('detail');
    if (!d) {
      el.innerHTML = '<p class="muted">No rule selected.</p>';
      return;
    }
    const attrRows = (d.attrs || []).map((a) => `<tr><td><strong>${esc(a.key)}</strong></td><td><code>${esc(a.value)}</code></td></tr>`).join('');
    const findHtml = (d.findings && d.findings.length)
      ? '<div class="attr-head"><strong>Findings</strong></div>' + d.findings.map((f) => `<div class="error" style="margin:4px 0;padding:6px 10px;"><strong>${esc(f.rule)}</strong>: ${esc(f.message)}</div>`).join('')
      : '';
    const rawHtml = d.raw ? `<div class="attr-head"><strong>Rego Source</strong></div><pre class="trace">${esc(d.raw)}</pre>` : '';

    el.innerHTML = `
      <div class="dhead"><strong>Line ${d.line}: ${esc(d.name)}</strong><span>${esc(d.badge || '')}</span></div>
      <table class="splits"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${attrRows}</tbody></table>
      ${findHtml}${rawHtml}
    `;
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (!m || typeof m !== 'object') return;
    switch (m.type) {
      case 'init':
        if (m.error) {
          app.innerHTML = `<div class="error"><strong>Could not open ${esc(m.name)}</strong><p>${esc(m.error)}</p></div>`;
          return;
        }
        state.name = m.name;
        state.summary = m.summary;
        state.pageSize = m.pageSize || 100;
        state.page = 0;
        renderShell();
        loadPage();
        return;
      case 'pageResult':
        state.total = m.total;
        state.rows = m.rows || [];
        renderPane();
        if (state.rows.length && state.selected == null) {
          state.selected = state.rows[0].index;
          post({ type: 'detail', index: state.selected });
        }
        return;
      case 'filterResult':
        state.total = m.count;
        document.getElementById('hint').textContent = m.count < m.total ? `Showing ${m.count} of ${m.total} rules.` : '';
        loadPage();
        return;
      case 'detailResult':
        renderDetail(m.detail);
        return;
      case 'zovoAlso': {
        const anchor = m.anchor && document.getElementById(m.anchor);
        if (anchor && m.html) {
          const old = document.querySelector('.zovo-also');
          if (old) old.remove();
          anchor.insertAdjacentHTML('afterend', m.html);
        }
        return;
      }
      case 'hint':
        if (document.getElementById('hint')) document.getElementById('hint').textContent = m.text || '';
        return;
      default:
    }
  });

  post({ type: 'ready' });
})();
