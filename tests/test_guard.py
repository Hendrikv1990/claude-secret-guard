import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
import guard  # noqa: E402

GUARD = os.path.join(HERE, "..", "hooks", "guard.py")
FAKE_TOKEN = "tok_" + "9f8a7b6c5d4e3f2a1b0c9d8e"


def run_hook(event, payload, env=None):
    full_env = dict(os.environ, **(env or {}))
    p = subprocess.run(
        [sys.executable, GUARD, event], input=json.dumps(payload),
        capture_output=True, text=True, env=full_env,
    )
    return p.returncode, (json.loads(p.stdout) if p.stdout.strip() else None), p.stderr


class BashRulesTest(unittest.TestCase):
    def blocked(self, cmd):
        return guard.bash_block_reason(cmd) is not None

    def test_blocks_dumping_secret_files(self):
        for cmd in ["cat .env", "head -5 apps/web/.env.production", "less config/master.key",
                    "cat .env | grep TOKEN", "cd x && cat ~/.ssh/id_rsa"]:
            self.assertTrue(self.blocked(cmd), cmd)

    def test_allows_example_files_and_sourcing(self):
        for cmd in ["cat .env.example", "set -a; source .env; set +a; bin/rails db:migrate",
                    "grep -c '' .env", "cat README.md"]:
            self.assertFalse(self.blocked(cmd), cmd)

    def test_blocks_full_environment_dumps(self):
        for cmd in ["env", "printenv", "env | sort", "export -p", "set"]:
            self.assertTrue(self.blocked(cmd), cmd)

    def test_allows_env_with_arguments(self):
        for cmd in ["env RAILS_ENV=test bundle exec rspec", "printenv HOME", "set -e"]:
            self.assertFalse(self.blocked(cmd), cmd)

    def test_heroku_config(self):
        self.assertTrue(self.blocked("heroku config -a myapp"))
        self.assertTrue(self.blocked("heroku config:get API_KEY -a myapp"))
        self.assertFalse(self.blocked("heroku config -a myapp --json | jq -r 'keys[]'"))
        self.assertFalse(self.blocked('K=$(heroku config:get API_KEY -a myapp) ./run.sh'))
        self.assertFalse(self.blocked("heroku config:set FOO=bar -a myapp"))

    def test_echoing_secret_variables(self):
        self.assertTrue(self.blocked('echo "$SERVICE_API_TOKEN"'))
        self.assertTrue(self.blocked("printf '%s' ${DB_PASSWORD}"))
        self.assertFalse(self.blocked('echo "${#SERVICE_API_TOKEN}"'))
        self.assertFalse(self.blocked('echo "$HOME $RAILS_ENV"'))

    def test_protects_the_off_switch_and_config(self):
        self.assertTrue(self.blocked("touch ~/.claude/secret-guard-off"))
        self.assertTrue(self.blocked("echo x >> ~/.config/secret-guard/allow"))


class FileRulesTest(unittest.TestCase):
    def test_secret_files(self):
        for p in ["/a/.env", "/a/.env.local", "/a/config/master.key", "/a/key.pem",
                  "/home/u/.ssh/id_ed25519", "/home/u/.aws/credentials", "/a/config/secrets.yml"]:
            self.assertTrue(guard.is_secret_file(p), p)
        for p in ["/a/.env.example", "/a/app.rb", "/a/environment.rb", "/a/.envrc.sample"]:
            self.assertFalse(guard.is_secret_file(p), p)

    def test_protected_paths(self):
        self.assertTrue(guard.is_protected_path(os.path.expanduser("~/.claude/secret-guard-off")))
        self.assertTrue(guard.is_protected_path(os.path.expanduser("~/.config/secret-guard/allow")))
        self.assertFalse(guard.is_protected_path("/tmp/x"))


class HookProcessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        os.mkdir(os.path.join(self.dir, ".git"))
        with open(os.path.join(self.dir, ".env"), "w") as f:
            f.write(f"SERVICE_API_TOKEN={FAKE_TOKEN}\n")
        self.env = {"HOME": self.dir, "SECRET_GUARD_CONFIG": os.path.join(self.dir, "cfg")}

    def tearDown(self):
        self.tmp.cleanup()

    def test_post_bash_replaces_output(self):
        payload = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": self.dir,
                   "tool_input": {"command": "x"},
                   "tool_response": {"stdout": f"got {FAKE_TOKEN}\n", "stderr": "", "interrupted": False, "isImage": False}}
        code, out, _ = run_hook("post", payload, self.env)
        self.assertEqual(code, 0)
        new = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(new["stdout"], "got «SERVICE_API_TOKEN»\n")
        self.assertEqual(new["interrupted"], False)

    def test_post_bash_follows_cd_into_other_project(self):
        other = tempfile.mkdtemp(dir=self.dir)
        os.mkdir(os.path.join(other, ".git"))
        secret = "Zq81" + "xPv02LmNa7Rt5Ywq"
        with open(os.path.join(other, ".env"), "w") as f:
            f.write(f"OTHER_SECRET={secret}\n")
        payload = {"tool_name": "Bash", "cwd": self.dir, "tool_input": {"command": f"cd {other} && grep . .env"},
                   "tool_response": {"stdout": f"OTHER_SECRET={secret}\n", "stderr": "", "interrupted": False, "isImage": False}}
        _, out, _ = run_hook("post", payload, self.env)
        self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"]["stdout"], "OTHER_SECRET=«OTHER_SECRET»\n")

    def test_post_bash_silent_when_clean(self):
        payload = {"tool_name": "Bash", "cwd": self.dir, "tool_input": {"command": "x"},
                   "tool_response": {"stdout": "hello\n", "stderr": "", "interrupted": False, "isImage": False}}
        code, out, _ = run_hook("post", payload, self.env)
        self.assertEqual((code, out), (0, None))

    def test_pre_bash_denies_with_reason(self):
        payload = {"tool_name": "Bash", "cwd": self.dir, "tool_input": {"command": "cat .env"}}
        code, out, _ = run_hook("pre", payload, self.env)
        hso = out["hookSpecificOutput"]
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("envnames", hso["permissionDecisionReason"])

    def test_pre_bash_wraps_background_commands(self):
        payload = {"tool_name": "Bash", "cwd": self.dir,
                   "tool_input": {"command": "bin/dev", "run_in_background": True, "description": "d"}}
        code, out, _ = run_hook("pre", payload, self.env)
        new = out["hookSpecificOutput"]["updatedInput"]
        self.assertIn("bin/dev", new["command"])
        self.assertIn("redact", new["command"])
        self.assertTrue(new["run_in_background"])
        self.assertEqual(new["description"], "d")

    def test_pre_bash_leaves_foreground_alone(self):
        payload = {"tool_name": "Bash", "cwd": self.dir, "tool_input": {"command": "ls"}}
        self.assertEqual(run_hook("pre", payload, self.env)[:2], (0, None))

    def test_pre_read_denies_env(self):
        payload = {"tool_name": "Read", "cwd": self.dir, "tool_input": {"file_path": os.path.join(self.dir, ".env")}}
        _, out, _ = run_hook("pre", payload, self.env)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_off_switch_disables_everything(self):
        os.makedirs(os.path.join(self.dir, ".claude"))
        open(os.path.join(self.dir, ".claude", "secret-guard-off"), "w").close()
        payload = {"tool_name": "Bash", "cwd": self.dir, "tool_input": {"command": "cat .env"}}
        self.assertEqual(run_hook("pre", payload, self.env)[:2], (0, None))

    def test_prompt_with_secret_is_blocked(self):
        payload = {"hook_event_name": "UserPromptSubmit", "cwd": self.dir,
                   "prompt": f"use this token {FAKE_TOKEN} please"}
        _, out, _ = run_hook("prompt", payload, self.env)
        self.assertEqual(out["decision"], "block")
        self.assertNotIn(FAKE_TOKEN, out["reason"])
        self.assertIn("SERVICE_API_TOKEN", out["reason"])

    def test_clean_prompt_passes(self):
        payload = {"cwd": self.dir, "prompt": "use $SERVICE_API_TOKEN from .env"}
        self.assertEqual(run_hook("prompt", payload, self.env)[:2], (0, None))


class BackgroundWrapperTest(unittest.TestCase):
    """The wrapped background command must still stream, mask and keep the exit code."""

    def run_wrapped(self, shell, cmd, cwd):
        wrapped = guard.wrap_background(cmd, [sys.executable, os.path.join(HERE, "..", "bin", "redact")])
        return subprocess.run([shell, "-c", wrapped], capture_output=True, text=True, cwd=cwd)

    def test_masks_and_keeps_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, ".git"))
            with open(os.path.join(d, ".env"), "w") as f:
                f.write(f"SERVICE_API_TOKEN={FAKE_TOKEN}\n")
            for shell in ("/bin/zsh", "/bin/bash"):
                p = self.run_wrapped(shell, f"echo out {FAKE_TOKEN}; echo err >&2; exit 3", d)
                self.assertEqual(p.returncode, 3, shell)
                self.assertIn("out «SERVICE_API_TOKEN»", p.stdout, shell)
                self.assertIn("err", p.stdout, shell)
                self.assertNotIn(FAKE_TOKEN, p.stdout + p.stderr, shell)

    def test_follows_cd_inside_wrapped_command(self):
        with tempfile.TemporaryDirectory() as outer:
            inner = os.path.join(outer, "proj")
            os.makedirs(os.path.join(inner, ".git"))
            with open(os.path.join(inner, ".env"), "w") as f:
                f.write(f"SERVICE_API_TOKEN={FAKE_TOKEN}\n")
            cmd = f"cd {inner} && echo got {FAKE_TOKEN}"
            wrapped = guard.wrap_background(cmd, [sys.executable, os.path.join(HERE, "..", "bin", "redact")],
                                            dirs=[outer, inner])
            p = subprocess.run(["/bin/zsh", "-c", wrapped], capture_output=True, text=True, cwd=outer)
            self.assertIn("got «SERVICE_API_TOKEN»", p.stdout)

    def test_heredoc_and_trailing_comment(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.run_wrapped("/bin/zsh", "cat <<'EOF'\nhello\nEOF\n# trailing comment", d)
            self.assertEqual(p.stdout, "hello\n")


if __name__ == "__main__":
    unittest.main()
