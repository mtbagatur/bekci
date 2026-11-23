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
them. Broken rules fail closed with an ask decision. Codex hook events are supported.

Reads the hook JSON on stdin, prints a decision JSON only when it acts.
Fails open (exit 0, no output) on bad input so a bug never bricks a session.
Use --check [path] to validate the Markdown rules file.
Logs decisions (tool + rule id, never content) to BEKCI_LOG, if configured.
"""
import json
import os
import re
import shlex
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
    ("pr", re.compile(r"\bgh\s+(pr\s+(create|merge|comment|review)|issue\s+(create|comment)|release\s+create|repo\s+create)\b")),
    ("publish", re.compile(r"\b(npm|pnpm|yarn)\s+publish\b|\btwine\s+upload\b")),
    ("rm-broad", re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b[^;&|]*\s(/|~|\$HOME|/home/[^/]+)(?:/.*)?\s*(?:$|[;&|])")),
    ("dd-mkfs", re.compile(r"\b(mkfs(\.\w+)?|dd\s+if=)")),
]
GIT_GLOBAL_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
GIT_GLOBAL_FLAGS = {"--no-pager"}


def git_actions(command):
    """Yield git subcommands from shell syntax, including common wrappers."""
    try:
        tokens = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        tokens.whitespace_split = True
        tokens.commenters = "#"
        words = list(tokens)
    except ValueError:
        return

    # Split shell command lists so quoted strings remain a single inert token.
    chunks, chunk = [], []
    for word in words:
        if word in (";", "&&", "||", "|", "&"):
            if chunk:
                chunks.append(chunk)
                chunk = []
        else:
            chunk.append(word)
    if chunk:
        chunks.append(chunk)

    for argv in chunks:
        i = 0
        while i < len(argv):
            word = argv[i]
            if os.path.basename(word) in ("env", "command", "builtin", "exec"):
                i += 1
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", word):
                i += 1
                continue
            if os.path.basename(word) == "git":
                i += 1
                while i < len(argv):
                    opt = argv[i]
                    if opt in GIT_GLOBAL_FLAGS:
                        i += 1
                    elif opt in GIT_GLOBAL_VALUE_OPTIONS:
                        i += 2
                    elif any(opt.startswith(name + "=") for name in ("--git-dir", "--work-tree", "--namespace")):
                        i += 1
                    elif opt.startswith("-") and opt != "-":
                        i += 1
                    else:
                        break
                if i < len(argv):
                    action = argv[i]
                    yield action, argv[i + 1:]
                break
            if os.path.basename(word) in {"sh", "bash", "dash", "zsh"}:
                try:
                    c_index = argv.index("-c", i + 1)
                    if c_index + 1 < len(argv):
                        yield from git_actions(argv[c_index + 1])
                except ValueError:
                    pass
                break
            # Skip leading command options such as /usr/bin/env -i.
            if word.startswith("-"):
                i += 1
                continue
            break


def git_rule(command):
    for action, args in git_actions(command):
        if action == "push":
            return "force-push" if any(a in ("--force", "-f", "--force-with-lease") for a in args) else "push"
        if action == "reset" and "--hard" in args:
            return "reset-hard"
        if action == "clean" and any(re.fullmatch(r"-[a-zA-Z]*f[a-zA-Z]*", a) for a in args):
            return "reset-hard"
        if action == "checkout" and "--" in args and any(a in (".", ".\\") for a in args[args.index("--") + 1:]):
            return "reset-hard"
    return None

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
        wrapped_commit = any(action == "commit" for action, _ in git_actions(cmd))
        if (wrapped_commit or re.search(r"\bgh\s+(pr|issue|release)\b", cmd)) and AI_TRAILER.search(cmd):
            return "deny", "ai-izi", "AI attribution trailer detected. Remove it before committing."
        if SECRET_READERS.search(cmd) and SECRET_PATH.search(cmd) and not ENV_EXAMPLE.search(cmd):
            return "deny", "sir", "A credential file cannot be read by the hook caller."
        git_rule_id = git_rule(cmd)
        if git_rule_id == "force-push":
            return "ask", "force-push", "Force push requires explicit approval."
        if git_rule_id:
            return "ask", git_rule_id, f"External or irreversible action ({git_rule_id}) requires explicit approval."
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


def load_rules(path=None, broken=None):
    """Parse rules; append malformed active rules to *broken* with reasons."""
    rules, cur = [], None
    broken = broken if broken is not None else []
    try:
        with open(path or RULES_MD, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as exc:
        broken.append({"id": "?", "olay": "all", "reason": f"cannot read rules file: {exc}"})
        return rules

    def close(r):
        if not r or r.get("kapali"):
            return
        reason = None
        if r.get("olay") not in ("bash", "file", "yaz", "mcp", "all"):
            reason = f"invalid or missing olay: {r.get('olay', '<missing>')}"
        elif r.get("karar") not in RANK:
            reason = f"invalid or missing karar: {r.get('karar', '<missing>')}"
        elif not r.get("desen"):
            reason = "missing desen"
        else:
            try:
                r["rx"] = re.compile(r["desen"], re.I)
            except re.error as exc:
                reason = f"invalid regex: {exc}"
        if reason:
            broken.append({"id": r.get("id", "?"), "olay": r.get("olay"), "reason": reason})
        else:
            rules.append(r)

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


def decide(event, rules=None, broken=None):
    """Built-in floor first; md rules can only add stricter outcomes."""
    base = decide_builtin(event)
    if rules is None:
        if broken is None:
            broken = []
        rules = load_rules(broken=broken)
    if broken is None:
        broken = []
    extra = decide_rules(event, rules)
    tool = event.get("tool_name", "")
    cmd = shell_command(tool, event.get("tool_input") or {})
    if cmd is not None:
        kind = "bash"
    elif tool in ("Read", "Edit", "Write", "NotebookEdit", "MultiEdit"):
        kind = "file"
    elif tool.startswith("mcp__"):
        kind = "mcp"
    else:
        kind = "other"
    broken_result = None
    if kind:
        for item in broken:
            bad_kind = item.get("olay")
            if bad_kind not in ("bash", "file", "yaz", "mcp", "all") or bad_kind == "all" or bad_kind == kind or (bad_kind == "yaz" and kind == "file" and tool != "Read"):
                broken_result = ("ask", "kural-hata:" + item["id"], f"Bekci: broken rule {item['id']}: {item['reason']}; fix bekci-kurallar.md")
                break
    strict_extra = extra
    if broken_result and (not strict_extra or RANK["ask"] > RANK[strict_extra[0]]):
        strict_extra = broken_result
    if base and (not strict_extra or RANK[base[0]] > RANK[strict_extra[0]]):
        return base
    return strict_extra or base


def is_codex(event):
    return "turn_id" in event


def log(tool, rule, decision):
    try:
        with open(LOG, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{decision}\t{rule}\t{tool}\n")
    except OSError:
        pass


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--check":
        path = sys.argv[2] if len(sys.argv) > 2 else RULES_MD
        broken = []
        load_rules(path, broken)
        for item in broken:
            print(f"{item['id']}: {item['reason']}")
        return 1 if broken else 0
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
    logged_decision = "ask" if rule.startswith("kural-hata:") else decision
    log(("codex:" if is_codex(event) else "") + event.get("tool_name", ""), rule, logged_decision)
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
