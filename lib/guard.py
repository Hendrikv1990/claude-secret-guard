"""Rules for the Claude Code hooks: what to block, what to wrap, what to mask."""

import os
import re
import shlex

import secret_guard as sg

ENV_HINT = (
    "Refer to secrets by name instead. Use `envnames` to list variable names, "
    "`secret-fp NAME` to compare values by fingerprint, and `set -a; source .env; set +a` "
    "to load them into a command without printing them."
)
DISPLAY_COMMANDS = {
    "cat", "less", "more", "head", "tail", "bat", "nl", "strings", "xxd", "od", "hexdump",
    "tac", "view", "vim", "vi", "nano", "open", "code", "pbcopy",
}
SECRET_BASENAMES = {
    "master.key", "credentials.key", "secrets.yml", "secrets.yaml", ".netrc", ".pgpass",
    ".npmrc", ".pypirc", ".git-credentials", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
}
SECRET_EXTENSIONS = (".pem", ".p12", ".pfx", ".key")
WRITE_HINTS = re.compile(r"(>|\btouch\b|\brm\b|\bmv\b|\bcp\b|\btee\b|\bln\b|\bmkdir\b|\bsed\s+-i|\bchmod\b|\bpython|\bruby\b|\bnode\b|\bperl\b|\bdd\b)")
SEPARATORS = {";", "&&", "||", "|", "&", "\n", "|&", "(", ")"}


def is_secret_file(path):
    if not path:
        return False
    base = os.path.basename(path.rstrip("/"))
    if sg._is_env_file(base) or base in SECRET_BASENAMES:
        return True
    if base == "credentials" and os.path.basename(os.path.dirname(path)) == ".aws":
        return True
    return base.endswith(SECRET_EXTENSIONS) and not base.endswith(".pub")


def is_protected_path(path):
    path = os.path.abspath(os.path.expanduser(path or ""))
    return path == sg.OFF_SWITCH or path == sg.CONFIG_DIR or path.startswith(sg.CONFIG_DIR + os.sep)


def _segments(cmd):
    """Split a shell command into simple-command word lists. Best effort."""
    try:
        lexer = shlex.shlex(cmd.replace("\n", " ; "), posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        tokens = re.split(r"\s+", cmd)
    segments, current = [], []
    for tok in tokens:
        if tok in SEPARATORS or set(tok) <= set(";&|()"):
            if current:
                segments.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    cleaned = []
    for seg in segments:
        while seg and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[0]):
            seg = seg[1:]
        while seg and seg[0] in ("sudo", "command", "exec", "time", "nohup", "then", "do", "else", "{", "}"):
            seg = seg[1:]
        if seg:
            cleaned.append(seg)
    return cleaned


def bash_block_reason(cmd):
    """Return why a command must not run, or None."""
    if ("secret-guard-off" in cmd or ".config/secret-guard" in cmd) and WRITE_HINTS.search(cmd):
        return "Only the user can change secret-guard's off switch or settings."

    for seg in _segments(cmd):
        name, args = seg[0], seg[1:]
        base = os.path.basename(name)
        if base in DISPLAY_COMMANDS and any(is_secret_file(a) for a in args if not a.startswith("-")):
            return f"`{base}` would print a secret file into the chat. {ENV_HINT}"
        if base in ("env", "printenv") and not args:
            return f"`{base}` prints every environment variable. Use `envnames --process` for names only."
        if base == "export" and (not args or args == ["-p"]):
            return "`export` without arguments prints every value. Use `envnames --process` for names only."
        if base in ("set", "declare", "typeset") and (not args or args in (["-p"], ["-x"], ["-px"])):
            return f"`{base}` without arguments prints shell variables. Use `envnames --process` for names only."
        if base in ("echo", "printf", "print"):
            for arg in args:
                for var in re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", arg):
                    if sg.SECRET_NAME_RE.search(var):
                        return f"`{base} ${var}` would print a secret. Use `secret-fp {var}` or `echo ${{#{var}}}` for its length."

    for m in re.finditer(r"\bheroku\s+config(?=\s|$)", cmd):
        rest = re.split(r"[;&\n]", cmd[m.end():], maxsplit=1)[0]
        if not re.search(r"\|\s*jq\b.*\bkeys", rest):
            return "`heroku config` prints every value. Use `heroku config -a APP --json | jq -r 'keys[]'` for names."
    for m in re.finditer(r"\bheroku\s+config:get\b", cmd):
        before = cmd[: m.start()].rstrip()
        rest = re.split(r"[;&\n]", cmd[m.end():], maxsplit=1)[0]
        if not (before.endswith("$(") or before.endswith("`") or re.search(r"\|\s*secret-fp\b", rest)):
            return ("`heroku config:get` prints the value. Capture it instead: "
                    "`X=$(heroku config:get NAME -a APP) cmd`, or compare with `heroku config:get NAME -a APP | secret-fp -`.")
    return None


def wrap_background(cmd, redact_argv, dirs=()):
    argv = list(redact_argv)
    for d in dirs:
        argv += ["--cwd", d]
    redact = " ".join(shlex.quote(a) for a in argv)
    return f"set -o pipefail 2>/dev/null; {{\n{cmd}\n}} 2>&1 | {redact} --stream"


def found_labels(before, after):
    return sorted(set(re.findall(r"«([A-Z0-9_]+)»", after)) - set(re.findall(r"«([A-Z0-9_]+)»", before)))
