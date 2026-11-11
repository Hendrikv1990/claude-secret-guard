#!/usr/bin/env python3
"""Claude Code hook entry point.

  guard.py pre     PreToolUse   (Bash, Read, Grep, Edit, Write, NotebookEdit)
  guard.py post    PostToolUse  (Bash)
  guard.py prompt  UserPromptSubmit
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))

import guard  # noqa: E402
import secret_guard as sg  # noqa: E402

REDACT_ARGV = [sys.executable, os.path.join(ROOT, "bin", "redact")]


def emit(obj):
    sys.stdout.write(json.dumps(obj))


def deny(reason):
    emit({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": f"secret-guard: {reason}",
    }})


def pre(data):
    tool = data.get("tool_name")
    ti = data.get("tool_input") or {}
    if tool == "Bash":
        cmd = ti.get("command", "")
        reason = guard.bash_block_reason(cmd)
        if reason:
            return deny(reason)
        if ti.get("run_in_background"):
            cwd = data.get("cwd") or os.getcwd()
            new = dict(ti, command=guard.wrap_background(cmd, REDACT_ARGV, [cwd] + sg.cd_targets(cmd, cwd)))
            emit({"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": new}})
    elif tool == "Read":
        if guard.is_secret_file(ti.get("file_path")):
            deny(f"{os.path.basename(ti['file_path'])} holds secrets. {guard.ENV_HINT}")
    elif tool == "Grep":
        if guard.is_secret_file(ti.get("path")) or ".env" in (ti.get("glob") or ""):
            deny(f"searching secret files would print their values. {guard.ENV_HINT}")
    elif tool in ("Edit", "Write", "NotebookEdit"):
        if guard.is_protected_path(ti.get("file_path") or ti.get("notebook_path")):
            deny("Only the user can change secret-guard's off switch or settings.")


def post(data):
    resp = data.get("tool_response")
    if data.get("tool_name") != "Bash" or not isinstance(resp, dict):
        return
    cwd = data.get("cwd") or os.getcwd()
    cmd = (data.get("tool_input") or {}).get("command", "")
    r = sg.Redactor.for_cwd([cwd] + sg.cd_targets(cmd, cwd))
    new, changed = dict(resp), False
    for key in ("stdout", "stderr"):
        if isinstance(resp.get(key), str):
            new[key] = r.redact(resp[key])
            changed |= new[key] != resp[key]
    if changed:
        emit({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": new}})


def prompt(data):
    text = data.get("prompt") or ""
    redacted = sg.Redactor.for_cwd(data.get("cwd") or os.getcwd()).redact(text)
    if redacted != text:
        labels = ", ".join(guard.found_labels(text, redacted)) or "a secret"
        emit({
            "decision": "block",
            "reason": (f"secret-guard: your message contains {labels}. It was not sent. "
                       "Refer to it by its variable name, or store it with `! envset NAME --clipboard`."),
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
        })


def main():
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    if os.path.exists(sg.OFF_SWITCH):
        return
    try:
        data = json.load(sys.stdin)
        {"pre": pre, "post": post, "prompt": prompt}[event](data)
    except Exception as e:  # fail closed
        msg = f"secret-guard hook error ({type(e).__name__}: {e})"
        if event == "pre":
            deny(msg + ". Fix the hook, or the user can create ~/.claude/secret-guard-off.")
        elif event == "post":
            emit({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": {
                "stdout": f"[{msg}; output hidden]", "stderr": "", "interrupted": False, "isImage": False}}})
        else:
            emit({"decision": "block", "reason": msg})


if __name__ == "__main__":
    main()
