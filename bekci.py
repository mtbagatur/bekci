#!/usr/bin/env python3
"""Bekci: a PreToolUse safety guard for coding agents.

Ideas adapted from ECC (safety-guard, gateguard, governance-capture) and
ai-job-search (.claude/settings.json deny list), rewritten for our rules:
  1. GitHub'da AI izi yok  -> deny commits/PRs carrying Claude trailers.
  2. Şifre/token hiçbir araca -> deny reading .env, SSH keys, cloud creds.
  3. Dışarı giden iş son onayla -> ask before push, PR, mail send, publish.
  4. Geri alınamaz iş onaylı -> ask before broad rm -rf, force push, reset --hard.

Extra rules live in a Markdown file selected with BEKCI_KURALLAR. Built-in
rules are the floor: Markdown rules can add deny/ask/warn but cannot loosen
them. A broken rule is skipped and logged. Codex hook events are supported.

Reads the hook JSON on stdin, prints a decision JSON only when it acts.
Fails open (exit 0, no output) on bad input so a bug never bricks a session.
Logs decisions (tool + rule id, never content) to BEKCI_LOG, if configured.
"""
import json
import os
import re
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.expanduser(os.environ.get("BEKCI_LOG", os.path.join(BASE_DIR, "bekci.log")))
RULES_MD = os.path.expanduser(os.environ.get("BEKCI_KURALLAR", os.path.join(BASE_DIR, "bekci-kurallar.md")))
SHELL_TOOLS = {"Bash", "shell", "local_shell", "exec_command", "container.exec", "unified_exec"}
RANK = {"warn": 1, "ask": 2, "deny": 3}

AI_TRAILER = re.compile(
    r"co-authored-by:\s*claude|claude-session:|generated with \[?claude|"
    r"🤖 generated with",
    re.I,
)
SECRET_PATH = re.compile(
    r"(^|[\s/'\"=])(\.env(\.[\w-]+)?|id_(rsa|ed25519|ecdsa)(?!\.pub)\b|"
    r"\.aws/credentials|\.netrc|\.pgpass|\.docker/config\.json|"
    r"((access|auth|api|refresh|oauth|bearer|secret|session|github|gh|id|service)[-_.])*tokens?\.(json|txt)|\.ssh/(?!config\b|known_hosts\b|[\w.-]+\.pub\b)[\w.-]+)",
    re.I,
)
SECRET_READERS = re.compile(r"\b(cat|less|more|head|tail|grep|rg|sed|awk|cp|scp|base64|xxd|strings|bat|nl)\b")
ENV_EXAMPLE = re.compile(r"\.env\.(example|sample|template)\b", re.I)

BASH_ASK = [
    ("push", re.compile(r"\bgit\s+push\b")),
    ("pr", re.compile(r"\bgh\s+(pr\s+(create|merge|comment|review)|issue\s+(create|comment)|release\s+create|repo\s+create)\b")),
    ("publish", re.compile(r"\b(npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b")),
    ("reset-hard", re.compile(r"\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f|checkout\s+--?\s*\.)")),
    ("rm-broad", re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b[^;&|]*\s(/|~|\$HOME|/home/[^/]+)(?:/.*)?\s*(?:$|[;&|])")),
    ("dd-mkfs", re.compile(r"\b(mkfs(\.\w+)?|dd\s+if=)")),
]
FORCE_PUSH = re.compile(r"\bgit\s+push\b.*(--force\b|-f\b|--force-with-lease)")

MCP_ASK = re.compile(
    r"^mcp__.*(Gmail__(send_message|reply|forward)|Calendar__(create_event|delete_event|respond_to_event)|"
    r"Drive__share_file|Notion__notion-(create-comment|send-message))",
)


def shell_command(tool, inp):
    """Return the command string for Claude Bash or Codex shell events, else None."""
    if tool not in SHELL_TOOLS:
        return None
    cmd = inp.get("command", inp.get("cmd", ""))
    if isinstance(cmd, list):
        cmd = " ".join(str(c) for c in cmd)
    return str(cmd)


def decide_builtin(event):
    tool = event.get("tool_name", "")
    inp = event.get("tool_input") or {}

    cmd = shell_command(tool, inp)
    if cmd is not None:
        if re.search(r"\b(git\s+commit|gh\s+(pr|issue|release))\b", cmd) and AI_TRAILER.search(cmd):
            return "deny", "ai-izi", "AI attribution trailer detected. Remove it before committing."
        if SECRET_READERS.search(cmd) and SECRET_PATH.search(cmd) and not ENV_EXAMPLE.search(cmd):
            return "deny", "sir", "A credential file cannot be read by the hook caller."
        if FORCE_PUSH.search(cmd):
            return "ask", "force-push", "Force push requires explicit approval."
        for rid, rx in BASH_ASK:
            if rx.search(cmd):
                return "ask", rid, f"External or irreversible action ({rid}) requires explicit approval."
        return None

    if tool in ("Read", "Edit", "Write", "NotebookEdit"):
        path = inp.get("file_path", "") or inp.get("notebook_path", "")
        if SECRET_PATH.search(" " + path) and not ENV_EXAMPLE.search(path):
            return "deny", "sir", "A credential file cannot be accessed by the hook caller."
        if tool in ("Write", "Edit"):
            text = inp.get("content", "") + inp.get("new_string", "")
            if "/.git/" not in path and os.path.basename(path).upper() == "COMMIT_EDITMSG" and AI_TRAILER.search(text):
                return "deny", "ai-izi", "AI attribution trailer detected."
        return None

    if MCP_ASK.search(tool):
        return "ask", "dis-is", "This external action requires explicit approval."
    return None


def load_rules(path=None):
    """Parse bekci-kurallar.md. Block format:
    ### <id>
    - olay: bash | file | yaz (Edit/Write only) | mcp | all
    - karar: deny | ask | warn
    - desen: `<python regex>`
    - mesaj: <text>
    - kapalı            (optional: disables the rule)
    """
    rules, cur = [], None
    try:
        lines = open(path or RULES_MD, encoding="utf-8").read().splitlines()
    except OSError:
        return rules

    def close(r):
        if not r or r.get("kapali"):
            return
        try:
            assert r.get("olay") in ("bash", "file", "yaz", "mcp", "all")
            assert r.get("karar") in RANK
            r["rx"] = re.compile(r["desen"], re.I)
            rules.append(r)
        except (AssertionError, KeyError, re.error):
            log("-", "kural-hata:" + r.get("id", "?"), "skip")

    for line in lines:
        m = re.match(r"^###\s+(\S+)", line)
        if m:
            close(cur)
            cur = {"id": m.group(1)}
            continue
        if cur is None:
            continue
        m = re.match(r"^-\s*(olay|karar|desen|mesaj)\s*:\s*(.*)$", line.strip())
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key == "desen" and len(val) >= 2 and val[0] == val[-1] == "`":
                val = val[1:-1]
            cur[key] = val.lower() if key in ("olay", "karar") else val
        elif re.match(r"^-\s*kapal[ıi]\b", line.strip()):
            cur["kapali"] = True
    close(cur)
    return rules


def decide_rules(event, rules):
    tool = event.get("tool_name", "")
    inp = event.get("tool_input") or {}
    cmd = shell_command(tool, inp)
    if cmd is not None:
        kind, text = "bash", cmd
    elif tool in ("Read", "Edit", "Write", "NotebookEdit", "MultiEdit"):
        kind = "file"
        text = " ".join(str(inp.get(k, "")) for k in ("file_path", "notebook_path", "content", "new_string"))
    elif tool.startswith("mcp__"):
        kind, text = "mcp", tool
    else:
        return None
    best = None
    for r in rules:
        kinds = (kind, "all", "yaz") if kind == "file" and tool != "Read" else (kind, "all")
        if r["olay"] not in kinds:
            continue
        if r["rx"].search(text) and (best is None or RANK[r["karar"]] > RANK[best["karar"]]):
            best = r
    if best:
        return best["karar"], best["id"], best.get("mesaj") or "bekçi kuralı"
    return None


def decide(event, rules=None):
    """Built-in floor first; md rules can only add stricter outcomes."""
    base = decide_builtin(event)
    if rules is None:
        rules = load_rules()
    extra = decide_rules(event, rules)
    if base and (not extra or RANK[base[0]] >= RANK[extra[0]]):
        return base
    return extra or base


def is_codex(event):
    return "turn_id" in event


def log(tool, rule, decision):
    try:
        with open(LOG, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{decision}\t{rule}\t{tool}\n")
    except OSError:
        pass


def main():
    try:
        event = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    result = decide(event)
    if not result:
        return 0
    decision, rule, reason = result
    if decision == "ask" and is_codex(event):
        # Codex hooks have no "ask"; convert it to deny so the command cannot
        # run without an approval mechanism.
        decision = "deny"
        reason += " (Codex has no approval prompt: blocked.)"
    log(("codex:" if is_codex(event) else "") + event.get("tool_name", ""), rule, decision)
    if decision == "warn":
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": f"[bekçi:{rule}] {reason}",
            }
        }, ensure_ascii=False))
        return 0
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": f"[bekçi:{rule}] {reason}",
        }
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
