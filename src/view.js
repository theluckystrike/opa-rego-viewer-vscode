'use strict';
// View model for OPA Rego Policy Inspector: pagination and filtering by kind, findings and text.

class RegoViewModel {
  constructor(parsed, name, fileSize) {
    this.parsed = parsed;
    this.name = name;
    this.fileSize = fileSize;
    this.filter = { text: '', kind: '' };
    this.filtered = parsed.rows.slice();
  }

  summary() {
    const p = this.parsed;
    const s = p.stats;
    return {
      name: this.name,
      fileSize: this.fileSize,
      title: p.title,
      packageName: p.packageName,
      hasRegoV1: p.hasRegoV1,
      imports: p.imports,
      totalLines: p.totalLines,
      ruleCount: s.ruleCount,
      importCount: s.importCount,
      entrypointCount: s.entrypointCount,
      defaultCount: s.defaultCount,
      functionCount: s.functionCount,
      helperCount: s.helperCount,
      inputPathCount: s.inputPathCount,
      dataPathCount: s.dataPathCount,
      findingErrors: s.findingErrors,
      findingWarnings: s.findingWarnings,
      refs: p.refs,
      findings: p.findings,
    };
  }

  totalCount() {
    return this.parsed.rows.length;
  }

  count() {
    return this.filtered.length;
  }

  setFilter(f) {
    const text = f && typeof f.text === 'string' ? f.text.trim().toLowerCase() : '';
    const kind = f && typeof f.kind === 'string' ? f.kind.trim() : '';
    this.filter = { text, kind };
    this.filtered = this.parsed.rows.filter((r) => {
      if (kind === 'entrypoint' && !['allow', 'deny', 'violation', 'warn', 'entrypoint'].includes(r.kind)) return false;
      if (kind === 'default' && !r.isDefault) return false;
      if (kind === 'function' && !r.isFunction) return false;
      if (kind === 'helper' && r.kind !== 'helper') return false;
      if (kind === 'findings' && !r.errorCount && !r.warningCount) return false;
      if (text) {
        const hay = `${r.name} ${r.kind} ${r.signature} ${r.refsSummary} ${r.raw}`.toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });
    return this.filtered.length;
  }

  rows(from, limit) {
    const start = Math.max(0, Number(from) || 0);
    const n = Math.max(1, Math.min(500, Number(limit) || 100));
    return this.filtered.slice(start, start + n).map((r) => ({
      index: r.index,
      line: r.line,
      name: r.name,
      kind: r.kind,
      signature: r.signature,
      refsSummary: r.refsSummary,
      badge: r.badge,
      risk: r.risk,
      errorCount: r.errorCount,
      warningCount: r.warningCount,
    }));
  }

  detail(index) {
    const r = this.parsed.rows.find((x) => x.index === index) || this.parsed.rows[0] || null;
    if (!r) return null;
    return {
      index: r.index,
      line: r.line,
      name: r.name,
      kind: r.kind,
      badge: r.badge,
      risk: r.risk,
      raw: r.raw,
      findings: r.findings,
      attrs: r.attrs,
    };
  }
}

module.exports = { RegoViewModel };
