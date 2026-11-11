import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import secret_guard as sg  # noqa: E402

# Fake values only. Built from pieces so this file never trips secret scanners.
FAKE_TOKEN = "tok_" + "9f8a7b6c5d4e3f2a1b0c9d8e"
FAKE_DB_PASS = "Xk29" + "vLq81mZp"
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJpZCI6MTIzfQ" + ".abcdefghijklmnopqrstuv"
FAKE_GH = "ghp_" + "A" * 36
FAKE_ANTHROPIC = "sk-ant-" + "api03-" + "x" * 30


def write_env(directory, name, body):
    path = os.path.join(directory, name)
    with open(path, "w") as f:
        f.write(textwrap.dedent(body))
    return path


class ParseEnvTest(unittest.TestCase):
    def test_parses_quotes_export_and_comments(self):
        with tempfile.TemporaryDirectory() as d:
            p = write_env(d, ".env", f"""
                # comment
                export API_TOKEN="{FAKE_TOKEN}"
                RAILS_ENV=development
                SINGLE='single quoted value'
                EMPTY=
                """)
            env = sg.parse_env_file(p)
        self.assertEqual(env["API_TOKEN"], FAKE_TOKEN)
        self.assertEqual(env["RAILS_ENV"], "development")
        self.assertEqual(env["SINGLE"], "single quoted value")
        self.assertEqual(env["EMPTY"], "")

    def test_multiline_double_quoted_value(self):
        with tempfile.TemporaryDirectory() as d:
            p = write_env(d, ".env", 'PRIVATE_KEY="line one\nline two"\nNEXT=1\n')
            env = sg.parse_env_file(p)
        self.assertEqual(env["PRIVATE_KEY"], "line one\nline two")
        self.assertEqual(env["NEXT"], "1")


class FindEnvFilesTest(unittest.TestCase):
    def test_finds_env_files_but_skips_examples_and_node_modules(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, ".git"))
            os.makedirs(os.path.join(d, "apps", "web"))
            os.makedirs(os.path.join(d, "node_modules", "pkg"))
            write_env(d, ".env", "A=1\n")
            write_env(d, ".env.local", "A=1\n")
            write_env(d, ".env.example", "A=1\n")
            write_env(os.path.join(d, "apps", "web"), ".env.production", "A=1\n")
            write_env(os.path.join(d, "node_modules", "pkg"), ".env", "A=1\n")
            found = {os.path.relpath(p, d) for p in sg.find_env_files(os.path.join(d, "apps"))}
        self.assertEqual(found, {".env", ".env.local", os.path.join("apps", "web", ".env.production")})


class IsSecretTest(unittest.TestCase):
    def test_secret_names_with_real_looking_values(self):
        self.assertTrue(sg.is_secret("SERVICE_API_TOKEN", FAKE_TOKEN))
        self.assertTrue(sg.is_secret("DB_PASSWORD", FAKE_DB_PASS))

    def test_skips_harmless_values(self):
        self.assertFalse(sg.is_secret("SESSION_TIMEOUT", "30"))
        self.assertFalse(sg.is_secret("AUTH_ENABLED", "true"))
        self.assertFalse(sg.is_secret("API_KEY", "short"))
        self.assertFalse(sg.is_secret("DB_PASSWORD", "postgres"))
        self.assertFalse(sg.is_secret("RAILS_ENV", "development"))
        self.assertFalse(sg.is_secret("APP_URL", "https://crm.example.com/path"))

    def test_paths_and_session_ids_are_not_secrets(self):
        self.assertFalse(sg.is_secret("PWD", "/Users/someone/Projects/app"))
        self.assertFalse(sg.is_secret("OLDPWD", "/Users/someone"))
        self.assertFalse(sg.is_secret("SSH_AUTH_SOCK", "/private/tmp/com.apple.launchd.x/Listeners"))
        self.assertFalse(sg.is_secret("CLAUDE_CODE_SESSION_ID", "1605be90-7bb2-4a56-b602-c133d0d94688"))
        self.assertTrue(sg.is_secret("DB_PWD", FAKE_DB_PASS))
        self.assertTrue(sg.is_secret("POSTMARK_API_TOKEN", "1605be90-7bb2-4a56-b602-c133d0d94688"))

    def test_high_entropy_value_under_neutral_name(self):
        self.assertTrue(sg.is_secret("SOMETHING", "aZ3kP9qL2mX8vB7nC4tR6wY1"))


class RedactTest(unittest.TestCase):
    def setUp(self):
        self.r = sg.Redactor(known={"SERVICE_API_TOKEN": FAKE_TOKEN})

    def test_known_value_becomes_name(self):
        out = self.r.redact(f"curl -H 'Authorization: Bearer {FAKE_TOKEN}' -> 401")
        self.assertNotIn(FAKE_TOKEN, out)
        self.assertIn("«SERVICE_API_TOKEN»", out)

    def test_url_password_is_masked_but_host_stays(self):
        out = self.r.redact(f"connecting to postgres://app:{FAKE_DB_PASS}@db.example.com:5432/prod")
        self.assertNotIn(FAKE_DB_PASS, out)
        self.assertIn("db.example.com:5432/prod", out)

    def test_local_dummy_url_password_stays(self):
        line = "postgres://postgres:postgres@localhost:5432/dev"
        self.assertEqual(self.r.redact(line), line)

    def test_known_formats(self):
        for value, label in [
            (FAKE_AWS, "AWS_ACCESS_KEY_ID"),
            (FAKE_JWT, "JWT"),
            (FAKE_GH, "GITHUB_TOKEN"),
            (FAKE_ANTHROPIC, "API_KEY"),
        ]:
            out = self.r.redact(f"value: {value} end")
            self.assertNotIn(value, out, label)
            self.assertIn(f"«{label}»", out)

    def test_bearer_header_with_unknown_token(self):
        unknown = "Zq81" + "xPv02LmNa7Rt5Yw"
        out = self.r.redact(f"> Authorization: Bearer {unknown}")
        self.assertNotIn(unknown, out)

    def test_private_key_block_across_lines(self):
        text = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\nabcdef\n-----END RSA PRIVATE KEY-----\nb\n"
        out = self.r.redact(text)
        self.assertNotIn("MIIBOgIBAAJBAK", out)
        self.assertTrue(out.startswith("a\n"))
        self.assertTrue(out.endswith("b\n"))

    def test_streaming_matches_whole_text(self):
        text = f"x {FAKE_TOKEN}\n-----BEGIN PRIVATE KEY-----\nSECRETBODY\n-----END PRIVATE KEY-----\ny\n"
        streamed = "".join(self.r.redact_lines(text.splitlines(True)))
        self.assertEqual(streamed, self.r.redact(text))

    def test_allowlist(self):
        r = sg.Redactor(known={"SERVICE_API_TOKEN": FAKE_TOKEN}, allow={FAKE_TOKEN})
        self.assertIn(FAKE_TOKEN, r.redact(FAKE_TOKEN))

    def test_longest_value_wins(self):
        r = sg.Redactor(known={"SHORT_TOKEN": FAKE_TOKEN, "LONG_TOKEN": FAKE_TOKEN + "EXTRA123"})
        self.assertEqual(r.redact(FAKE_TOKEN + "EXTRA123"), "«LONG_TOKEN»")

    def test_plain_text_untouched(self):
        line = "1396 examples, 146 failures, 333 pending"
        self.assertEqual(self.r.redact(line), line)


class CollectTest(unittest.TestCase):
    def test_collects_from_env_files_and_environment(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, ".git"))
            write_env(d, ".env", f"SERVICE_API_TOKEN={FAKE_TOKEN}\nRAILS_ENV=development\n")
            known = sg.collect_known(d, environ={"MY_SECRET": FAKE_DB_PASS, "HOME": "/Users/x"})
        self.assertEqual(known["SERVICE_API_TOKEN"], FAKE_TOKEN)
        self.assertEqual(known["MY_SECRET"], FAKE_DB_PASS)
        self.assertNotIn("RAILS_ENV", known)
        self.assertNotIn("HOME", known)


class CdTargetsTest(unittest.TestCase):
    def test_follows_cd_in_commands(self):
        self.assertEqual(sg.cd_targets("cd sub && ls; cd ../other", "/a"), ["/a/sub", "/a/other"])
        self.assertEqual(sg.cd_targets('(cd "/x y" && make)', "/a"), ["/x y"])
        self.assertEqual(sg.cd_targets("echo abcd efg", "/a"), [])


class FingerprintTest(unittest.TestCase):
    def test_fingerprint_is_stable_and_hides_value(self):
        fp = sg.fingerprint(FAKE_TOKEN)
        self.assertEqual(fp, sg.fingerprint(FAKE_TOKEN))
        self.assertNotIn(FAKE_TOKEN, fp)
        self.assertIn(f"len={len(FAKE_TOKEN)}", fp)


if __name__ == "__main__":
    unittest.main()
