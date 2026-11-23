# Bekci

Bekci is a small Python `PreToolUse` safety hook for Claude Code and Codex. It
checks shell commands, file access, and supported MCP actions before a tool
runs. Built-in protections cover credential files, AI attribution trailers,
external actions, and destructive commands. Optional Markdown rules can add
`deny`, `ask`, or `warn` decisions; they cannot weaken built-in protections.
An active malformed rule fails closed: it produces an `ask` decision for its
event type (or all event types when `olay` is invalid). Codex converts that
`ask` to `deny`, like other approval requests.

## Requirements

- Python 3.8 or newer
- Claude Code or Codex with support for `PreToolUse` hooks

## Install

Clone or copy this directory to a stable location. Configure `BEKCI_LOG` and
`BEKCI_KURALLAR` if you want the log and rules stored elsewhere. By default,
the hook uses `bekci.log` and `bekci-kurallar.md` beside `bekci.py`.

### Claude Code

Add a `PreToolUse` command hook to your Claude Code settings. Replace
`/path/to/bekci` with the directory where you installed the files:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -I /path/to/bekci/bekci.py"
          }
        ]
      }
    ]
  }
}
```

### Codex

Add a `PreToolUse` command hook to `~/.codex/hooks.json` (or the hooks file
selected by your Codex setup). Replace `/path/to/bekci` with the install path:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -I /path/to/bekci/bekci.py"
          }
        ]
      }
    ]
  }
}
```

The hook reads event JSON from standard input and writes a decision JSON to
standard output. Codex has no approval prompt for this hook, so `ask` decisions
are converted to `deny`.

## Additional rule format

Edit `bekci-kurallar.md` or set `BEKCI_KURALLAR` to another Markdown file.
Each rule uses a heading and four fields:

```markdown
### block-dangerous-command
- olay: bash
- karar: deny
- desen: `\bexample-command\b`
- mesaj: This command is disabled by local policy.
```

`olay` accepts `bash`, `file`, `yaz`, `mcp`, or `all`. `karar` accepts
`deny`, `ask`, or `warn`. Add `- kapalı` to disable a rule. Malformed active
rules are reported as `ask` decisions and logged as `kural-hata:<id>`; disabled
rules remain inactive. Validate the file before installing changes:

```sh
python3 -I bekci.py --check [path]
```

The command prints each malformed rule and exits 1 if any are found, otherwise
exits 0.

## Run tests

```sh
python3 -I test_bekci.py
```

## Configuration

- `BEKCI_KURALLAR`: path to the additional Markdown rules file
- `BEKCI_LOG`: path for decision logs; logs contain tool and rule identifiers,
  not command content

## License

MIT; see [LICENSE](LICENSE).
