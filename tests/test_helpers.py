import os
import subprocess
import sys
import tempfile
import unittest

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin")
FAKE_TOKEN = "tok_" + "9f8a7b6c5d4e3f2a1b0c9d8e"


def run(cmd, cwd, stdin=None, env=None):
    return subprocess.run([sys.executable, os.path.join(BIN, cmd[0])] + cmd[1:], cwd=cwd,
                          input=stdin, capture_output=True, text=True, env=dict(os.environ, **(env or {})))


class HelpersTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        os.mkdir(os.path.join(self.d, ".git"))
        with open(os.path.join(self.d, ".env"), "w") as f:
            f.write(f"# c\nSERVICE_API_TOKEN={FAKE_TOKEN}\nRAILS_ENV=development\n")

    def tearDown(self):
        self.tmp.cleanup()

    def read_env(self):
        with open(os.path.join(self.d, ".env")) as f:
            return f.read()

    def test_envnames_lists_names_without_values(self):
        p = run(["envnames"], self.d)
        self.assertIn("SERVICE_API_TOKEN", p.stdout)
        self.assertIn("RAILS_ENV", p.stdout)
        self.assertNotIn(FAKE_TOKEN, p.stdout)
        self.assertNotIn("development", p.stdout)

    def test_envnames_process(self):
        p = run(["envnames", "--process"], self.d, env={"MY_API_TOKEN": FAKE_TOKEN})
        self.assertIn("MY_API_TOKEN", p.stdout)
        self.assertNotIn(FAKE_TOKEN, p.stdout)

    def test_secret_fp_from_env_file_and_stdin_match(self):
        a = run(["secret-fp", "SERVICE_API_TOKEN"], self.d).stdout
        b = run(["secret-fp", "-"], self.d, stdin=FAKE_TOKEN + "\n").stdout
        self.assertNotIn(FAKE_TOKEN, a + b)
        self.assertEqual(a.split()[1], b.split()[1])

    def test_secret_fp_missing_name_fails(self):
        self.assertNotEqual(run(["secret-fp", "NOPE"], self.d).returncode, 0)

    def test_envset_replaces_value_from_stdin(self):
        p = run(["envset", "SERVICE_API_TOKEN", "--stdin"], self.d, stdin="new_value_123456789\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("new_value_123456789", p.stdout + p.stderr)
        self.assertIn("SERVICE_API_TOKEN=new_value_123456789\n", self.read_env())
        self.assertIn("RAILS_ENV=development", self.read_env())
        self.assertEqual(self.read_env().count("SERVICE_API_TOKEN"), 1)

    def test_envset_appends_generated_value(self):
        p = run(["envset", "NEW_SECRET", "--generate", "32"], self.d)
        self.assertEqual(p.returncode, 0, p.stderr)
        line = [l for l in self.read_env().splitlines() if l.startswith("NEW_SECRET=")][0]
        self.assertGreaterEqual(len(line.split("=", 1)[1]), 32)
        self.assertNotIn(line.split("=", 1)[1], p.stdout)

    def test_envset_quotes_values_with_spaces(self):
        run(["envset", "GREETING_SECRET", "--stdin"], self.d, stdin="has a space\n")
        self.assertIn('GREETING_SECRET="has a space"', self.read_env())


if __name__ == "__main__":
    unittest.main()
