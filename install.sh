#!/bin/sh
# Install or remove secret-guard for Claude Code (user level).
#   ./install.sh              install hooks into ~/.claude/settings.json and helpers into ~/.local/bin
#   ./install.sh --uninstall  remove both
set -eu

REPO="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${SECRET_GUARD_BIN_DIR:-$HOME/.local/bin}"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
PY="$(command -v python3)"
HELPERS="redact envnames secret-fp envset sg-scan"
MODE="${1:-install}"

[ -n "$PY" ] || { echo "python3 is required" >&2; exit 1; }
mkdir -p "$BIN_DIR" "$(dirname "$SETTINGS")"
[ -f "$SETTINGS" ] || echo '{}' > "$SETTINGS"
cp "$SETTINGS" "$SETTINGS.bak-secret-guard"

"$PY" - "$SETTINGS" "$PY" "$REPO/hooks/guard.py" "$MODE" <<'EOF'
import json, sys
path, py, guard, mode = sys.argv[1:5]
with open(path) as f:
    settings = json.load(f)
hooks = settings.setdefault("hooks", {})

def strip(event):
    groups = []
    for g in hooks.get(event, []):
        kept = [h for h in g.get("hooks", []) if "hooks/guard.py" not in h.get("command", "")]
        if kept:
            groups.append(dict(g, hooks=kept))
    if groups:
        hooks[event] = groups
    else:
        hooks.pop(event, None)

for event in ("PreToolUse", "PostToolUse", "UserPromptSubmit"):
    strip(event)

if mode != "--uninstall":
    def hook(arg, **extra):
        return dict({"type": "command", "command": f'"{py}" "{guard}" {arg}', "timeout": 15}, **extra)
    hooks.setdefault("PreToolUse", []).append(
        {"matcher": "Bash|Read|Grep|Edit|Write|NotebookEdit", "hooks": [hook("pre", onFailure="block")]})
    hooks.setdefault("PostToolUse", []).append({"matcher": "Bash", "hooks": [hook("post")]})
    hooks.setdefault("UserPromptSubmit", []).append({"hooks": [hook("prompt", onFailure="block")]})
if not hooks:
    settings.pop("hooks")
with open(path, "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")
EOF

for h in $HELPERS; do
  if [ "$MODE" = "--uninstall" ]; then
    [ -L "$BIN_DIR/$h" ] && rm "$BIN_DIR/$h"
  else
    ln -sf "$REPO/bin/$h" "$BIN_DIR/$h"
  fi
done

if [ "$MODE" = "--uninstall" ]; then
  echo "secret-guard removed (settings backup: $SETTINGS.bak-secret-guard)"
else
  echo "secret-guard installed: hooks in $SETTINGS, helpers in $BIN_DIR"
  case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "note: add $BIN_DIR to your PATH" ;; esac
  echo "Open /hooks in Claude Code once (or restart it) to load the hooks."
fi
