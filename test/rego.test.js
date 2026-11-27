'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const {
  parseRegoPolicy,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildRuleCatalogCsv,
  buildRuleCatalogMarkdown,
} = require('../src/rego');
const { RegoViewModel } = require('../src/view');
const { editorHtml, csp } = require('../src/html');

test('parses gatekeeper-authz.rego and flags fail-open default, missing rego.v1, unbounded wildcard, hardcoded secret and unused helper', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'gatekeeper-authz.rego'));
  const parsed = parseRegoPolicy(buf, 'gatekeeper-authz.rego');
  assert.equal(parsed.packageName, 'k8s.admission.authz');
  assert.equal(parsed.hasRegoV1, false);
  assert.ok(parsed.stats.ruleCount >= 5);
  assert.ok(parsed.stats.inputPathCount >= 3);
  assert.ok(parsed.stats.dataPathCount >= 1);
  const rules = new Set(parsed.findings.map((f) => f.rule));
  assert.ok(rules.has('default-allow-true'));
  assert.ok(rules.has('missing-rego-v1'));
  assert.ok(rules.has('unbounded-wildcard-loop'));
  assert.ok(rules.has('hardcoded-secret'));
  assert.ok(rules.has('unused-helper-rule'));
});

test('parses strict-rbac.rego with rego.v1 and zero findings', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'strict-rbac.rego'));
  const parsed = parseRegoPolicy(buf, 'strict-rbac.rego');
  assert.equal(parsed.packageName, 'platform.rbac.strict');
  assert.equal(parsed.hasRegoV1, true);
  assert.equal(parsed.findings.length, 0);
});

test('RegoViewModel filters by kind, findings and text', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'gatekeeper-authz.rego'));
  const parsed = parseRegoPolicy(buf, 'gatekeeper-authz.rego');
  const vm = new RegoViewModel(parsed, 'gatekeeper-authz.rego', buf.length);
  assert.equal(vm.setFilter({ text: '', kind: 'default' }), 1);
  assert.ok(vm.setFilter({ text: '', kind: 'entrypoint' }) >= 3);
  assert.ok(vm.setFilter({ text: '', kind: 'findings' }) >= 3);
  assert.equal(vm.setFilter({ text: 'unused_legacy_check', kind: '' }), 1);
  const det = vm.detail(1);
  assert.ok(det && det.name === 'allow');
});

test('Pro report builders produce audit Markdown, diff Markdown, CSV and Markdown rule catalog', () => {
  const left = parseRegoPolicy(fs.readFileSync(path.join(__dirname, '..', 'samples', 'gatekeeper-authz.rego')), 'gatekeeper-authz.rego');
  const right = parseRegoPolicy(fs.readFileSync(path.join(__dirname, '..', 'samples', 'strict-rbac.rego')), 'strict-rbac.rego');
  const audit = buildAuditMarkdown([{ fileName: 'gatekeeper-authz.rego', parsed: left }]);
  assert.match(audit, /OPA Rego Fail-Open & Policy Security Audit/);
  assert.match(audit, /default-allow-true/);
  const diff = buildDiffMarkdown('gatekeeper-authz.rego', left, 'strict-rbac.rego', right);
  assert.match(diff, /Rule Changes/);
  assert.match(diff, /Security Finding Changes/);
  const csv = buildRuleCatalogCsv(left);
  assert.match(csv, /^name,kind,line,end_line,signature,refs,risk/);
  const md = buildRuleCatalogMarkdown(left, 'gatekeeper-authz.rego');
  assert.match(md, /OPA Rego Rule & Input Catalog/);
});

test('editorHtml enforces strict CSP with nonce and no unsafe-inline', () => {
  const html = editorHtml({ cspSource: 'vscode-webview://test', script: 'v.js', styleUri: 'v.css', title: 'gatekeeper-authz.rego', nonce: 'opa123' });
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'nonce-opa123'/);
  assert.doesNotMatch(csp('vscode-webview://test', 'opa123'), /unsafe-inline/);
});
