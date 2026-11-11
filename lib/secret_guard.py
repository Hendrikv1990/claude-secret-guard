"""Find secret values and mask them in text.

Standard library only, Python 3.8+. Values come from .env files near the
working directory and from secret-looking environment variables. Known
formats (AWS keys, JWTs, GitHub tokens, private keys, passwords in URLs)
are masked even when their value is unknown.
"""

import hashlib
import math
import os
import re

CONFIG_DIR = os.path.expanduser(os.environ.get("SECRET_GUARD_CONFIG", "~/.config/secret-guard"))
OFF_SWITCH = os.path.expanduser("~/.claude/secret-guard-off")

SECRET_NAME_RE = re.compile(
    r"(KEY|TOKEN|SECRET|PASSW|(?<!OLD)(?<!^)PWD|AUTH|CREDENTIAL|PRIVATE|SIGNATURE|SALT|DSN|WEBHOOK)",
    re.I,
)
EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".schema")
SKIP_DIRS = {".git", "node_modules", "vendor", "tmp", "log", ".next", "dist", "build", ".venv", "venv", "__pycache__"}
DUMMY_VALUES = {
    "password", "postgres", "changeme", "secret", "example", "development", "production",
    "staging", "test", "localhost", "root", "admin", "redis", "mysql", "guest", "default",
    "true", "false", "yes", "no", "null", "none", "undefined", "xxxxxxxx", "your-key-here",
}
MIN_LEN = 8
PATH_RE = re.compile(
    r"^(~|/(Users|home|private|tmp|var|opt|usr|etc|Library|Applications|System|Volumes|nix|srv|mnt|root|run|dev|bin|app|workspace))(/[^\s]*)?$"
)

# (label, regex). A regex with a group named "secret" masks only that group.
PATTERNS = [
    ("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("API_KEY", re.compile(r"\bsk-(?:ant-|proj-|or-v1-)?[A-Za-z0-9_-]{20,}")),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("WEBHOOK_SECRET", re.compile(r"\bwhsec_[A-Za-z0-9+/=]{16,}")),
    ("SLACK_TOKEN", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("SENDGRID_KEY", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}")),
    ("NPM_TOKEN", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("HEROKU_TOKEN", re.compile(r"\bHRKU-[A-Za-z0-9_-]{20,}")),
    ("MAILCHIMP_KEY", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}")),
    ("AUTH_HEADER", re.compile(r"(?i)(?:authorization|x-api-key|x-webhook-secret|api-key)\s*[:=]\s*(?:(?:bearer|basic|token)\s+)?[\"']?(?P<secret>[A-Za-z0-9._~+/=-]{12,})")),
    ("TOKEN", re.compile(r"(?i)\bbearer\s+(?P<secret>[A-Za-z0-9._~+/=-]{20,})")),
    ("URL_PASSWORD", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:(?P<secret>[^@\s/]+)@")),
]
BEGIN_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
END_KEY = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")


def parse_env_file(path):
    """Parse a dotenv file into a dict. Never raises on bad lines."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return {}
    env, i = {}, 0
    line_re = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$")
    while i < len(lines):
        m = line_re.match(lines[i])
        i += 1
        if not m:
            continue
        name, raw = m.group(1), m.group(2)
        if raw[:1] in ("'", '"'):
            quote = raw[0]
            body = raw[1:]
            while quote not in body and i < len(lines):
                body += "\n" + lines[i]
                i += 1
            value = body.split(quote, 1)[0]
            if quote == '"':
                value = value.replace("\\n", "\n")
        else:
            value = re.split(r"\s+#", raw, maxsplit=1)[0].strip()
        env[name] = value
    return env


def _is_env_file(name):
    return (name == ".env" or name.startswith(".env.") or name == ".envrc") and not name.endswith(EXAMPLE_SUFFIXES)


def project_root(cwd):
    d = os.path.abspath(cwd)
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            return os.path.abspath(cwd)
        d = parent


def find_env_files(cwd, max_depth=3):
    """Env files in the project root and up to max_depth folders below it, plus configured extras."""
    root = project_root(cwd)
    if root == os.path.expanduser("~") or root == os.sep:
        max_depth = 0
    found = []
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath.count(os.sep) - base_depth
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and depth < max_depth]
        found += [os.path.join(dirpath, f) for f in sorted(filenames) if _is_env_file(f)]
    extra = os.path.join(CONFIG_DIR, "env-files")
    if os.path.exists(extra):
        with open(extra) as f:
            found += [os.path.expanduser(l.strip()) for l in f if l.strip() and not l.startswith("#")]
    seen, result = set(), []
    for p in found:
        if p not in seen and os.path.isfile(p):
            seen.add(p)
            result.append(p)
    return result


def _entropy(s):
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _looks_random(value):
    """High-entropy token under a neutral name. UUIDs are IDs unless their name says otherwise."""
    if UUID_RE.match(value):
        return False
    if len(value) < 20 or re.search(r"\s", value) or value.startswith(("/", "~", "./", "http://", "https://")):
        return False
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    return classes >= 2 and _entropy(value) >= 3.5


def _url_has_password(value):
    m = re.search(r"://[^/\s:@]+:([^@\s/]+)@", value)
    return bool(m) and m.group(1).lower() not in DUMMY_VALUES


def is_secret(name, value):
    value = (value or "").strip()
    if len(value) < MIN_LEN or value.lower() in DUMMY_VALUES or re.fullmatch(r"[0-9.:-]+", value):
        return False
    if "://" in value:
        return _url_has_password(value)
    if PATH_RE.match(value):
        return False  # a filesystem path, e.g. SSH_AUTH_SOCK
    if SECRET_NAME_RE.search(name):
        return True
    return _looks_random(value)


def load_allowlist():
    path = os.path.join(CONFIG_DIR, "allow")
    allow = set()
    if os.path.exists(path):
        with open(path) as f:
            allow = {l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")}
    return allow


def collect_known(cwd, environ=None):
    """Map NAME -> value for every secret found near cwd (a folder or a list) and in the environment."""
    environ = os.environ if environ is None else environ
    dirs = [cwd] if isinstance(cwd, str) else list(cwd)
    files = []
    for d in dirs:
        if os.path.isdir(d):
            files += [f for f in find_env_files(d) if f not in files]
    known = {}
    for path in files:
        for name, value in parse_env_file(path).items():
            if is_secret(name, value) and name not in known:
                known[name] = value
    for name, value in environ.items():
        if name not in known and is_secret(name, value):
            known[name] = value
    return known


def cd_targets(cmd, cwd):
    """Folders a shell command changes into, resolved from cwd (best effort)."""
    dirs, here = [], cwd
    for m in re.finditer(r"(?:^|[;&|(\n]|\s)cd\s+(\"[^\"]+\"|'[^']+'|[^\s;&|)]+)", cmd):
        target = os.path.expanduser(m.group(1).strip("\"'"))
        here = os.path.normpath(os.path.join(here, target))
        dirs.append(here)
    return dirs


def fingerprint(value):
    digest = hashlib.sha256(value.encode()).hexdigest()[:12]
    return f"sha256:{digest} len={len(value)}"


class Redactor:
    def __init__(self, known=None, allow=None):
        self.allow = set(allow or ())
        pairs = {}
        for name, value in (known or {}).items():
            parts = [value] + (value.splitlines() if "\n" in value else [])
            for part in parts:
                part = part.strip()
                if len(part) >= MIN_LEN and part not in self.allow and part not in pairs:
                    pairs[part] = name
        self.values = sorted(pairs.items(), key=lambda kv: -len(kv[0]))
        self.values_re = (
            re.compile("|".join(re.escape(v) for v, _ in self.values)) if self.values else None
        )
        self.labels = dict(self.values)

    @classmethod
    def for_cwd(cls, cwd, environ=None):
        return cls(collect_known(cwd, environ), load_allowlist())

    def _mask_patterns(self, text):
        for label, rx in PATTERNS:
            def sub(m, label=label):
                if "secret" in rx.groupindex:
                    s = m.group("secret")
                    if s in self.allow or s.lower() in DUMMY_VALUES or s.startswith("«"):
                        return m.group(0)
                    start, end = m.span("secret")
                    whole = m.group(0)
                    return whole[: start - m.start()] + f"«{label}»" + whole[end - m.start():]
                if m.group(0) in self.allow:
                    return m.group(0)
                return f"«{label}»"
            text = rx.sub(sub, text)
        return text

    def redact_line(self, line):
        if self.values_re:
            line = self.values_re.sub(lambda m: f"«{self.labels[m.group(0)]}»", line)
        return self._mask_patterns(line)

    def redact_lines(self, lines):
        """Redact an iterable of lines (keeping line endings). Suitable for streaming."""
        in_key = False
        for line in lines:
            if in_key:
                if END_KEY.search(line):
                    in_key = False
                    yield END_KEY.split(line, 1)[1] if END_KEY.split(line, 1)[1].strip() else ""
                continue
            m = BEGIN_KEY.search(line)
            if m:
                before = line[: m.start()]
                rest = line[m.end():]
                if END_KEY.search(rest):
                    after = END_KEY.split(rest, 1)[1]
                    yield self.redact_line(before) + "«PRIVATE_KEY»" + self.redact_line(after)
                else:
                    in_key = True
                    yield self.redact_line(before) + "«PRIVATE_KEY»\n"
                continue
            yield self.redact_line(line)

    def redact(self, text):
        return "".join(self.redact_lines(text.splitlines(True)))
