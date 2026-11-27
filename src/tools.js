'use strict';
// Pro tools for OPA Rego Policy Inspector:
//   1. auditPolicy: Offline Markdown Rego fail-open and best-practice security audit.
//   2. diffPolicies: Compare two Rego policy files in Markdown.
//   3. exportRuleDocs: Non-destructive Markdown and CSV rule and input-path catalog export.
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const {
  parseRegoPolicy,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildRuleCatalogCsv,
  buildRuleCatalogMarkdown,
} = require('./rego');

const REGO_RE = /^.*\.rego$/i;

function uniquePath(targetPath) {
  if (!fs.existsSync(targetPath)) return targetPath;
  const dir = path.dirname(targetPath);
  const ext = path.extname(targetPath);
  const base = path.basename(targetPath, ext);
  for (let i = 1; i < 10000; i += 1) {
    const cand = path.join(dir, `${base}-${i}${ext}`);
    if (!fs.existsSync(cand)) return cand;
  }
  return path.join(dir, `${base}-${Date.now()}${ext}`);
}

async function resolveTargetUri(uri, provider, openLabel = 'Select Rego policy file') {
  if (uri && uri.scheme) return uri;
  if (provider && provider.active && provider.active.uri) return provider.active.uri;
  const ed = vscode.window.activeTextEditor;
  if (ed && ed.document && REGO_RE.test(path.basename(ed.document.uri.fsPath || ed.document.uri.path))) {
    return ed.document.uri;
  }
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel,
  });
  return picked && picked[0] ? picked[0] : null;
}

function listRegoFilesInDir(dirPath, maxDepth = 4) {
  const out = [];
  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      const full = path.join(dir, e.name);
      if (e.isFile() && REGO_RE.test(e.name)) out.push(full);
      else if (e.isDirectory() && depth < maxDepth) walk(full, depth + 1);
    }
  }
  walk(dirPath, 0);
  return out.sort();
}

function createTools({ provider, pro, reach }) {
  async function auditPolicy(uri, opts = {}) {
    if (!(await pro.allowed('auditPolicy', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const isDir = target.scheme === 'file' && fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory();
    const files = isDir ? listRegoFilesInDir(targetPath) : [targetPath];
    if (!files.length) {
      vscode.window.showInformationMessage('No *.rego policy files were found in this folder.');
      return undefined;
    }

    const entries = [];
    for (const f of files) {
      const buf = f === targetPath && target.scheme !== 'file'
        ? Buffer.from(await vscode.workspace.fs.readFile(target))
        : fs.readFileSync(f);
      const label = isDir ? path.relative(targetPath, f) : path.basename(f);
      entries.push({ fileName: label, parsed: parseRegoPolicy(buf, label) });
    }
    const md = buildAuditMarkdown(entries);
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('auditPolicy');
    if (reach) reach.refresh();
    return { files: files.length, markdown: md };
  }

  async function diffPolicies(uri, opts = {}) {
    if (!(await pro.allowed('diffPolicies', opts))) return undefined;
    const left = await resolveTargetUri(uri, provider, 'Select baseline Rego policy file');
    if (!left) return undefined;

    let right = opts.compareUri || null;
    if (!right) {
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Select second Rego policy file to compare',
      });
      right = picked && picked[0] ? picked[0] : null;
    }
    if (!right) return undefined;

    const leftBuf = Buffer.from(await vscode.workspace.fs.readFile(left));
    const rightBuf = Buffer.from(await vscode.workspace.fs.readFile(right));
    const leftName = path.basename(left.fsPath || left.path);
    const rightName = path.basename(right.fsPath || right.path);
    const md = buildDiffMarkdown(
      leftName,
      parseRegoPolicy(leftBuf, leftName),
      rightName,
      parseRegoPolicy(rightBuf, rightName),
    );
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('diffPolicies');
    if (reach) reach.refresh();
    return { markdown: md };
  }

  async function exportRuleDocs(uri, opts = {}) {
    if (!(await pro.allowed('exportRuleDocs', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const bytes = await vscode.workspace.fs.readFile(target);
    const baseName = path.basename(targetPath);
    const parsed = parseRegoPolicy(Buffer.from(bytes), baseName);
    const stemRaw = baseName.replace(/[^a-zA-Z0-9._-]+/g, '_') || 'policy';
    const defaultOut = uniquePath(path.join(path.dirname(targetPath), `${stemRaw}.rules.csv`));
    const saveUri = opts.outPath
      ? vscode.Uri.file(uniquePath(opts.outPath))
      : await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(defaultOut),
        filters: { 'CSV Rule Catalog': ['csv'] },
        saveLabel: 'Save Rego rule and input-path catalog CSV and Markdown',
      });
    if (!saveUri) return undefined;

    const csvPath = uniquePath(saveUri.fsPath);
    const dir = path.dirname(csvPath);
    const stem = path.basename(csvPath, '.csv').replace(/\.rules$/i, '');
    const mdPath = uniquePath(path.join(dir, `${stem}.rules.md`));

    fs.writeFileSync(csvPath, buildRuleCatalogCsv(parsed), 'utf8');
    fs.writeFileSync(mdPath, buildRuleCatalogMarkdown(parsed, baseName), 'utf8');

    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(mdPath));
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('exportRuleDocs');
    if (reach) reach.refresh();
    return { files: [csvPath, mdPath], rules: parsed.stats.ruleCount };
  }

  return { auditPolicy, diffPolicies, exportRuleDocs };
}

module.exports = { createTools, uniquePath, listRegoFilesInDir };
