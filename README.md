# OPA Rego Policy Inspector for VS Code

Inspect `*.rego` Open Policy Agent, Conftest and Gatekeeper policy files in VS Code without installing the `opa` binary or making any network calls. Large authorization and admission-control policies can hide `default allow := true` fail-open defaults, missing `import rego.v1` directives, unused helper rules, unbounded `[_]` wildcard loops and hardcoded tokens inside hundreds of lines of Rego. This extension parses Rego locally in plain JavaScript with zero CLI or cloud calls.

![OPA Rego Policy Inspector showing package metadata, rules, functions, input/data references and static policy findings](images/screenshot.png)

## What it opens

- Any `*.rego` policy file for Open Policy Agent (OPA), Conftest or Gatekeeper.
- Any open Rego file via the Command Palette or Explorer context menu (Open in OPA Rego Policy Inspector).
- Nothing to install, no `opa` binary required, no network or cloud calls.

## The free part

- Package, import, rule and function explorer: lists `package`, `import`, `default`, `allow`, `deny`, `violation`, `warn`, functions and helper rules in one searchable table with line numbers.
- Input and data reference table: extracts every `input.*` and `data.*` path referenced across rules so you can see what request fields and external data documents a policy expects.
- Rule detail inspector: shows each rule's kind, arguments, referenced `input.*`/`data.*` paths, helper calls, findings and raw Rego source block in the side pane.
- Static policy findings: flags `default allow := true` fail-open hazards, missing `import rego.v1`, unused helper rules, unbounded `[_]` wildcard loops and hardcoded tokens or passwords.

## The Pro tools, with 1 free try

Pro adds the audit, diff and catalog export steps: generate a Markdown Rego fail-open and best-practice audit for one file or a folder, compare two `.rego` files in Markdown for rule, import, input-path and finding changes, or export a Markdown and CSV catalog of rules and `input.*`/`data.*` paths locally. Your first try of each Pro tool is free. Zovo Pro is USD 19 once, and the team licence is USD 59.

## Why not plain text

Reading a 400-line OPA or Gatekeeper `.rego` file in plain text makes it easy to miss a `default allow := true` line near the top, a stale helper rule nobody calls, or an undocumented `input.request.object.spec` field buried in a nested block. A local inspector puts the rule table, input/data reference map and static findings on one screen.

## More tools by Zovo

See full docs and install options at [vscode.zovo.one/extensions/zovo-opa-rego-viewer/](https://vscode.zovo.one/extensions/zovo-opa-rego-viewer/), browse all Zovo VS Code extensions at [vscode.zovo.one](https://vscode.zovo.one/), or explore [Zovo Pro](https://vscode.zovo.one/pro/).
