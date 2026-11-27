'use strict';
// Offline Open Policy Agent (OPA) / Conftest / Gatekeeper Rego parser and static policy analyzer.
// Pure JavaScript, zero OPA binary, zero shell or network calls.

const ENTRYPOINT_NAMES = new Set([
  'allow', 'deny', 'violation', 'warn', 'main', 'decision', 'authz', 'reason', 'errors', 'valid', 'match', 'response',
]);

function stripLineComment(line) {
  let inStr = false;
  let inRaw = false;
  let esc = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (esc) { esc = false; continue; }
    if (inStr && ch === '\\') { esc = true; continue; }
    if (!inRaw && ch === '"') { inStr = !inStr; continue; }
    if (!inStr && ch === '`') { inRaw = !inRaw; continue; }
    if (!inStr && !inRaw && ch === '#') return line.slice(0, i);
  }
  return line;
}

function braceDelta(code) {
  let delta = 0;
  let inStr = false;
  let inRaw = false;
  let esc = false;
  for (let i = 0; i < code.length; i += 1) {
    const ch = code[i];
    if (esc) { esc = false; continue; }
    if (inStr && ch === '\\') { esc = true; continue; }
    if (!inRaw && ch === '"') { inStr = !inStr; continue; }
    if (!inStr && ch === '`') { inRaw = !inRaw; continue; }
    if (inStr || inRaw) continue;
    if (ch === '{') delta += 1;
    else if (ch === '}') delta -= 1;
  }
  return delta;
}

function classifyRuleKind(name, isDefault, isFunction) {
  if (isDefault) return 'default';
  if (isFunction) return 'function';
  const low = name.toLowerCase();
  if (low === 'allow' || low === 'deny' || low === 'violation' || low === 'warn') return low;
  if (ENTRYPOINT_NAMES.has(low)) return 'entrypoint';
  return 'helper';
}

function extractPaths(code) {
  const out = [];
  const re = /\b(input|data)((?:\.[a-zA-Z0-9_-]+|\[[^\]]*\])*)/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const root = m[1];
    const tail = m[2] || '';
    const full = `${root}${tail}`;
    if (full === root) continue;
    out.push({ root, path: full });
  }
  return out;
}

function parseRegoPolicy(bufOrText, fileName = 'policy.rego') {
  const text = Buffer.isBuffer(bufOrText) ? bufOrText.toString('utf8') : String(bufOrText || '');
  const rawLines = text.split(/\r?\n/);
  const totalLines = rawLines.length;
  if (!text.trim()) {
    throw new Error(`${fileName} is empty.`);
  }

  let pkg = '';
  let pkgLine = 0;
  const imports = [];
  const rules = [];
  const refs = [];
  const findings = [];

  let i = 0;
  while (i < rawLines.length) {
    const rawLine = rawLines[i];
    const code = stripLineComment(rawLine).trim();
    const lineNo = i + 1;
    if (!code) { i += 1; continue; }

    const pkgMatch = code.match(/^package\s+([a-zA-Z0-9_.\[\]"]+)/);
    if (pkgMatch) {
      pkg = pkgMatch[1];
      pkgLine = lineNo;
      i += 1;
      continue;
    }

    const impMatch = code.match(/^import\s+([a-zA-Z0-9_.\[\]"]+)(?:\s+as\s+([a-zA-Z0-9_]+))?/);
    if (impMatch) {
      imports.push({
        line: lineNo,
        path: impMatch[1],
        alias: impMatch[2] || '',
      });
      i += 1;
      continue;
    }

    const defMatch = code.match(/^default\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?::=|=)\s*(.+)$/);
    if (defMatch) {
      const name = defMatch[1];
      const value = defMatch[2].trim();
      rules.push({
        index: rules.length + 1,
        line: lineNo,
        endLine: lineNo,
        name,
        kind: 'default',
        isDefault: true,
        isFunction: false,
        signature: `default ${name} := ${value}`,
        defaultValue: value,
        args: '',
        raw: rawLine,
        bodyCode: code,
        refs: [],
        findings: [],
      });
      i += 1;
      continue;
    }

    // Rule or function header at top level
    const fnMatch = code.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*(?::=|=|if\b|\{|$)/);
    const ruleMatch = !fnMatch && code.match(/^([a-zA-Z_][a-zA-Z0-9_]*)(?:\s*\[([^\]]*)\]|\s+contains\s+([a-zA-Z_][a-zA-Z0-9_]*))?\s*(?::=|=|if\b|\{|$)/);
    if (fnMatch || ruleMatch) {
      const isFunction = Boolean(fnMatch);
      const name = isFunction ? fnMatch[1] : ruleMatch[1];
      const args = isFunction ? fnMatch[2].trim() : ((ruleMatch[2] || ruleMatch[3] || '').trim());
      const startLine = lineNo;
      const blockRaw = [rawLine];
      const blockCode = [code];
      let depth = braceDelta(code);
      let j = i + 1;
      while (j < rawLines.length && depth > 0) {
        const nextRaw = rawLines[j];
        const nextCode = stripLineComment(nextRaw);
        blockRaw.push(nextRaw);
        blockCode.push(nextCode);
        depth += braceDelta(nextCode);
        j += 1;
      }
      // Handle single-line header followed by indented block starting on next line
      if (blockRaw.length === 1 && !code.includes('{') && j < rawLines.length && stripLineComment(rawLines[j]).trim().startsWith('{')) {
        const nextRaw = rawLines[j];
        const nextCode = stripLineComment(nextRaw);
        blockRaw.push(nextRaw);
        blockCode.push(nextCode);
        depth += braceDelta(nextCode);
        j += 1;
        while (j < rawLines.length && depth > 0) {
          const r2 = rawLines[j];
          const c2 = stripLineComment(r2);
          blockRaw.push(r2);
          blockCode.push(c2);
          depth += braceDelta(c2);
          j += 1;
        }
      }
      const kind = classifyRuleKind(name, false, isFunction);
      const sig = code.replace(/\{.*$/, '').trim();
      rules.push({
        index: rules.length + 1,
        line: startLine,
        endLine: startLine + blockRaw.length - 1,
        name,
        kind,
        isDefault: false,
        isFunction,
        signature: sig || name,
        defaultValue: '',
        args,
        raw: blockRaw.join('\n'),
        bodyCode: blockCode.join('\n'),
        refs: [],
        findings: [],
      });
      i = j;
      continue;
    }

    i += 1;
  }

  if (!pkg && !rules.length && !imports.length) {
    throw new Error(`${fileName} does not contain a Rego package, import or rule declaration.`);
  }

  // Extract input.* / data.* references per rule
  for (const r of rules) {
    const codeLines = r.bodyCode.split(/\r?\n/);
    const ruleSeen = new Set();
    codeLines.forEach((cl, offset) => {
      const found = extractPaths(cl);
      for (const item of found) {
        const refEntry = {
          index: r.index,
          line: r.line + offset,
          rule: r.name,
          root: item.root,
          path: item.path,
        };
        refs.push(refEntry);
        if (!ruleSeen.has(item.path)) {
          ruleSeen.add(item.path);
          r.refs.push(item.path);
        }
      }
    });
  }

  // Static policy findings
  const addFileFinding = (severity, category, rule, line, ruleName, message, ruleObj = null) => {
    const f = { severity, category, rule, line, ruleName, message };
    findings.push(f);
    if (ruleObj) ruleObj.findings.push(f);
  };

  // 1. Missing import rego.v1
  const hasRegoV1 = imports.some((im) => im.path === 'rego.v1');
  if (!hasRegoV1) {
    addFileFinding(
      'warning',
      'Rego Compatibility',
      'missing-rego-v1',
      pkgLine || 1,
      '(file)',
      'Missing "import rego.v1". OPA v1.0+ requires rego.v1 keywords ("if", "contains") for forward compatibility.',
    );
  }

  // 2. Per-rule checks: fail-open default allow := true, unbounded wildcard loops, hardcoded secrets
  const allBodiesByRule = rules.map((r) => ({ name: r.name, body: r.bodyCode }));
  const secretTokenRe = /"(?:sk_live_[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._-]{12,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"/;
  const secretAssignRe = /\b(?:password|passwd|secret|api_?key|access_?token|auth_?token|client_?secret)\b[^#\n]{0,20}(?:==|:=|=)\s*"([^"]{6,})"/i;

  for (const r of rules) {
    if (r.isDefault && /^allow$/i.test(r.name) && /^true\b/i.test(r.defaultValue)) {
      addFileFinding(
        'error',
        'Fail-Open Hazard',
        'default-allow-true',
        r.line,
        r.name,
        `Rule "default ${r.name} := true" fails open: requests are allowed whenever no explicit deny or override matches.`,
        r,
      );
    }

    // Wildcard / unbounded iteration checks
    const bodyLines = r.bodyCode.split(/\r?\n/);
    bodyLines.forEach((bl, offset) => {
      if (/\b(?:input|data)(?:\.[a-zA-Z0-9_-]+)*\[_\]/.test(bl) || (/\[_\]/.test(bl) && (bl.match(/\[_\]/g) || []).length >= 2)) {
        addFileFinding(
          'warning',
          'Unbounded Iteration',
          'unbounded-wildcard-loop',
          r.line + offset,
          r.name,
          `Rule "${r.name}" uses an unbounded wildcard loop ("[_]"). Prefer explicit "some x in ..." iteration to avoid accidental Cartesian products.`,
          r,
        );
      }

      if (secretTokenRe.test(bl) || secretAssignRe.test(bl)) {
        addFileFinding(
          'error',
          'Secret Hygiene',
          'hardcoded-secret',
          r.line + offset,
          r.name,
          `Rule "${r.name}" contains a hardcoded token or credential string literal. Inject secrets or expected claims via OPA data or external verification.`,
          r,
        );
      }
    });
  }

  // 3. Unused helper rules (helper or function never referenced in any other rule body)
  const helperNames = new Set(rules.filter((r) => r.kind === 'helper' || r.kind === 'function').map((r) => r.name));
  for (const r of rules) {
    if (!helperNames.has(r.name)) continue;
    const refRe = new RegExp(`\\b${r.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
    const usedElsewhere = allBodiesByRule.some((other) => other.name !== r.name && refRe.test(other.body));
    if (!usedElsewhere) {
      addFileFinding(
        'warning',
        'Dead Policy Code',
        'unused-helper-rule',
        r.line,
        r.name,
        `Helper ${r.isFunction ? 'function' : 'rule'} "${r.name}" is never referenced by another rule in this file.`,
        r,
      );
    }
  }

  // Build rows with display summaries
  const rows = rules.map((r) => {
    const errorCount = r.findings.filter((f) => f.severity === 'error').length;
    const warningCount = r.findings.filter((f) => f.severity === 'warning').length;
    const risk = errorCount > 0 ? 'High' : (warningCount > 0 ? 'Medium' : 'Low');
    const badge = errorCount > 0 ? 'HIGH' : (warningCount > 0 ? 'WARN' : r.kind.toUpperCase());
    const refsSummary = r.refs.length ? r.refs.slice(0, 4).join(', ') + (r.refs.length > 4 ? ` (+${r.refs.length - 4})` : '') : 'None';
    const attrs = [
      { key: 'Rule / Function', value: r.name },
      { key: 'Kind', value: r.kind },
      { key: 'Lines', value: r.endLine > r.line ? `${r.line}-${r.endLine}` : String(r.line) },
      { key: 'Signature', value: r.signature },
      { key: 'Arguments', value: r.args || 'None' },
      { key: 'Input / Data Refs', value: r.refs.length ? r.refs.join(', ') : 'None' },
      { key: 'Risk', value: risk },
    ];
    return {
      ...r,
      risk,
      badge,
      errorCount,
      warningCount,
      refsSummary,
      attrs,
    };
  });

  const uniqueInputPaths = [...new Set(refs.filter((x) => x.root === 'input').map((x) => x.path))].sort();
  const uniqueDataPaths = [...new Set(refs.filter((x) => x.root === 'data').map((x) => x.path))].sort();
  const entrypointCount = rows.filter((r) => ['allow', 'deny', 'violation', 'warn', 'entrypoint'].includes(r.kind)).length;
  const defaultCount = rows.filter((r) => r.isDefault).length;
  const functionCount = rows.filter((r) => r.isFunction).length;
  const helperCount = rows.filter((r) => r.kind === 'helper').length;
  const findingErrors = findings.filter((f) => f.severity === 'error').length;
  const findingWarnings = findings.filter((f) => f.severity === 'warning').length;

  return {
    title: pkg ? `${fileName} (package ${pkg})` : fileName,
    packageName: pkg || '(none)',
    hasRegoV1,
    imports,
    totalLines,
    rules: rows,
    rows,
    refs,
    uniqueInputPaths,
    uniqueDataPaths,
    findings,
    stats: {
      ruleCount: rows.length,
      importCount: imports.length,
      entrypointCount,
      defaultCount,
      functionCount,
      helperCount,
      inputPathCount: uniqueInputPaths.length,
      dataPathCount: uniqueDataPaths.length,
      refCount: refs.length,
      findingErrors,
      findingWarnings,
    },
  };
}

function mdEsc(s) {
  return String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function csvEsc(s) {
  const v = String(s == null ? '' : s);
  return /[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

function buildAuditMarkdown(entries) {
  const lines = [
    '# OPA Rego Fail-Open & Policy Security Audit',
    '',
    `Generated offline across **${entries.length}** Rego policy file(s). No OPA binary or network calls were made.`,
    '',
    '## Policy Overview',
    '',
    '| File | Package | Rego v1 | Rules | Input Paths | Data Paths | Errors | Warnings |',
    '|---|---|---|---:|---:|---:|---:|---:|',
  ];
  let totalErrors = 0;
  let totalWarnings = 0;
  for (const { fileName, parsed } of entries) {
    const s = parsed.stats;
    totalErrors += s.findingErrors;
    totalWarnings += s.findingWarnings;
    lines.push(`| \`${mdEsc(fileName)}\` | \`${mdEsc(parsed.packageName)}\` | ${parsed.hasRegoV1 ? 'Yes' : 'No'} | ${s.ruleCount} | ${s.inputPathCount} | ${s.dataPathCount} | ${s.findingErrors} | ${s.findingWarnings} |`);
  }
  lines.push('', `Total findings: **${totalErrors} error(s)**, **${totalWarnings} warning(s)**.`, '');

  for (const { fileName, parsed } of entries) {
    lines.push(`## ${fileName}`, '');
    if (!parsed.findings.length) {
      lines.push('No static Rego policy findings detected.', '');
    } else {
      lines.push('| Severity | Category | Rule | Line | Target | Finding |', '|---|---|---|---:|---|---|');
      for (const f of parsed.findings) {
        lines.push(`| **${f.severity.toUpperCase()}** | ${mdEsc(f.category)} | \`${mdEsc(f.rule)}\` | ${f.line} | \`${mdEsc(f.ruleName)}\` | ${mdEsc(f.message)} |`);
      }
      lines.push('');
    }
  }
  return lines.join('\n');
}

function buildDiffMarkdown(leftName, left, rightName, right) {
  const lines = [
    `# OPA Rego Policy Comparison: \`${leftName}\` vs \`${rightName}\``,
    '',
    '| Metric | Baseline | Target | Delta |',
    '|---|---:|---:|---:|',
  ];
  const metrics = [
    ['Rules & Functions', left.stats.ruleCount, right.stats.ruleCount],
    ['Imports', left.stats.importCount, right.stats.importCount],
    ['Input Paths', left.stats.inputPathCount, right.stats.inputPathCount],
    ['Data Paths', left.stats.dataPathCount, right.stats.dataPathCount],
    ['Security Errors', left.stats.findingErrors, right.stats.findingErrors],
    ['Security Warnings', left.stats.findingWarnings, right.stats.findingWarnings],
  ];
  for (const [label, a, b] of metrics) {
    const d = b - a;
    lines.push(`| ${label} | ${a} | ${b} | ${d > 0 ? `+${d}` : d} |`);
  }

  const ruleKey = (r) => `${r.kind}:${r.name}`;
  const leftMap = new Map(left.rules.map((r) => [ruleKey(r), r]));
  const rightMap = new Map(right.rules.map((r) => [ruleKey(r), r]));
  const allKeys = [...new Set([...leftMap.keys(), ...rightMap.keys()])];

  lines.push('', '## Rule Changes', '');
  let changes = 0;
  for (const k of allKeys) {
    const a = leftMap.get(k);
    const b = rightMap.get(k);
    if (!a && b) {
      changes += 1;
      lines.push(`- **Added** \`${b.name}\` (${b.kind}) at line ${b.line}`);
    } else if (a && !b) {
      changes += 1;
      lines.push(`- **Removed** \`${a.name}\` (${a.kind})`);
    } else if (a && b && a.bodyCode.trim() !== b.bodyCode.trim()) {
      changes += 1;
      lines.push(`- **Modified** \`${b.name}\` (${b.kind}): refs \`${a.refsSummary}\` -> \`${b.refsSummary}\``);
    }
  }
  if (!changes) lines.push('- No rule differences detected.');

  const keyOf = (f) => `${f.severity}|${f.rule}|${f.ruleName}|${f.message}`;
  const leftF = new Set(left.findings.map(keyOf));
  const rightF = new Set(right.findings.map(keyOf));
  const addedF = right.findings.filter((f) => !leftF.has(keyOf(f)));
  const resolvedF = left.findings.filter((f) => !rightF.has(keyOf(f)));

  lines.push('', '## Security Finding Changes', '');
  if (!addedF.length && !resolvedF.length) {
    lines.push('- No security finding changes.');
  } else {
    for (const f of addedF) lines.push(`- **New ${f.severity.toUpperCase()}** \`${f.rule}\` (${f.ruleName}): ${f.message}`);
    for (const f of resolvedF) lines.push(`- **Resolved ${f.severity.toUpperCase()}** \`${f.rule}\` (${f.ruleName}): ${f.message}`);
  }
  lines.push('');
  return lines.join('\n');
}

function buildRuleCatalogCsv(parsed) {
  const rows = ['name,kind,line,end_line,signature,refs,risk'];
  for (const r of parsed.rules) {
    rows.push([r.name, r.kind, r.line, r.endLine, r.signature, r.refs.join('; '), r.risk].map(csvEsc).join(','));
  }
  return rows.join('\n') + '\n';
}

function buildRuleCatalogMarkdown(parsed, fileName) {
  const lines = [
    `# OPA Rego Rule & Input Catalog: ${fileName}`,
    '',
    `Package: \`${parsed.packageName}\` · Rego v1: **${parsed.hasRegoV1 ? 'Yes' : 'No'}** · Rules: **${parsed.stats.ruleCount}** · Input paths: **${parsed.stats.inputPathCount}** · Data paths: **${parsed.stats.dataPathCount}**`,
    '',
    '## Rules & Functions',
    '',
    '| Line | Kind | Name | Signature | Input / Data Refs | Risk |',
    '|---:|---|---|---|---|---|',
  ];
  for (const r of parsed.rules) {
    lines.push(`| ${r.line} | **${mdEsc(r.kind)}** | \`${mdEsc(r.name)}\` | \`${mdEsc(r.signature)}\` | \`${mdEsc(r.refsSummary)}\` | ${mdEsc(r.risk)} |`);
  }
  lines.push('', '## Referenced `input.*` and `data.*` Paths', '', '| Line | Rule | Root | Path |', '|---:|---|---|---|');
  if (!parsed.refs.length) {
    lines.push('| - | - | - | None |');
  } else {
    for (const ref of parsed.refs) {
      lines.push(`| ${ref.line} | \`${mdEsc(ref.rule)}\` | \`${mdEsc(ref.root)}\` | \`${mdEsc(ref.path)}\` |`);
    }
  }
  lines.push('');
  return lines.join('\n');
}

module.exports = {
  parseRegoPolicy,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildRuleCatalogCsv,
  buildRuleCatalogMarkdown,
};
