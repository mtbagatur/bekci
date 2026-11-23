# Additional Bekci rules

Built-in rules are always active. This file can add restrictions, but cannot
weaken built-in decisions.

Each rule starts with `### <id>` and contains:

- `olay`: `bash`, `file` (read/edit/write), `yaz` (edit/write), `mcp`, or `all`
- `karar`: `deny`, `ask`, or `warn`
- `desen`: a Python regular expression, optionally wrapped in backticks
- `mesaj`: the explanation shown to the user
- `kapalı`: optional; disables the rule

Malformed rules are skipped and logged. Set `BEKCI_KURALLAR` to select a
different rules file.

### ask-sudo
- olay: bash
- karar: ask
- desen: `(^|[;&|'"]\s*)sudo\s+`
- mesaj: System-level commands require explicit approval.

### ask-crontab-remove
- olay: bash
- karar: ask
- desen: `\bcrontab\s+-r\b`
- mesaj: Removing all scheduled jobs requires explicit approval.

### ask-download-and-run
- olay: bash
- karar: ask
- desen: `\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b`
- mesaj: Review downloaded scripts before executing them.

### ask-global-settings
- olay: yaz
- karar: ask
- desen: `/\.claude/settings(\.local)?\.json|/\.codex/(config\.toml|hooks\.json)`
- mesaj: Changing agent-wide settings requires explicit approval.

### ask-global-settings-shell
- olay: bash
- karar: ask
- desen: `(\bsed\s+-i|\btee\b|>\s*|\b(cp|mv)\b)[^;&|]*(\.claude/settings(\.local)?\.json|\.codex/(config\.toml|hooks\.json))`
- mesaj: Changing agent-wide settings requires explicit approval.

### warn-world-writable
- olay: bash
- karar: warn
- desen: `\bchmod\s+(-R\s+)?777\b`
- mesaj: World-writable permissions are unsafe; use narrower permissions.

### warn-local-policy-file
- olay: yaz
- karar: warn
- desen: `/policy\.md`
- mesaj: This local policy file is managed by its owner.
