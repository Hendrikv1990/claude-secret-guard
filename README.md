# claude-secret-guard

Keep API keys, tokens and database passwords out of your Claude Code chats, while Claude can still use them to run scripts, migrations and API calls.

The approach: Claude refers to secrets **by name** (`$SERVICE_API_TOKEN`), and the shell supplies the value when the command runs. Hooks make sure a value that slips into output is masked before Claude sees it:

```
$ grep TOKEN .env
SERVICE_API_TOKEN=«SERVICE_API_TOKEN»
```

It prevents accidents. It is not a security boundary against a hostile process (see [Limits](#limits)).

## What it does

| Layer | Hook | Effect |
|---|---|---|
| Mask output | `PostToolUse` on Bash | Every command's stdout and stderr is filtered before Claude sees it, using `updatedToolOutput`. Commands themselves are unchanged, so your permission rules, `cd`, exit codes and environment work as before. |
| Mask background output | `PreToolUse` on Bash | Commands run with `run_in_background` are piped through `redact --stream`, because their output arrives later through a file. |
| Block dumps | `PreToolUse` on Bash | `cat .env`, `printenv`, plain `env` or `export`, `heroku config`, `heroku config:get` printed to the screen, `echo $SOME_TOKEN`. Each refusal tells Claude the safe alternative. |
| Block secret files | `PreToolUse` on Read and Grep | `.env*` (not `.env.example`), `master.key`, `secrets.yml`, `*.pem`, `*.key`, SSH keys, `.netrc`, `.npmrc`, `~/.aws/credentials`. |
| Check your prompts | `UserPromptSubmit` | A message containing a known secret is stopped before it reaches Claude. |
| Off switch | | Only you can turn it off: `touch ~/.claude/secret-guard-off`. Hooks refuse attempts by Claude to create that file or edit the settings. |

### What counts as a secret

- **Values from `.env` files** in the project (root and up to three folders deep, skipping `node_modules` and similar), and in folders the command `cd`s into. The label is the variable name.
- **Environment variables** whose name contains `KEY`, `TOKEN`, `SECRET`, `PASSW`, `PWD`, `AUTH`, `CREDENTIAL`, `PRIVATE`, `SIGNATURE`, `SALT`, `DSN` or `WEBHOOK`, or whose value looks random (20+ characters, mixed, high entropy).
- **Known formats**, even with an unknown value: AWS access keys, GitHub, Anthropic, OpenAI and OpenRouter, Stripe, Slack, Google, SendGrid, npm, Heroku and Mailchimp keys, JWTs, private key blocks, `Authorization:` / `X-Api-Key:` header values, `Bearer` tokens, and passwords in URLs (`postgres://user:«URL_PASSWORD»@host/db`).

It skips values that aren't secrets: anything under 8 characters, numbers, `true`/`false`, local dummies like `postgres` or `password`, filesystem paths, and UUIDs that aren't under a secret-looking name.

## Install

Requires macOS or Linux, `python3` (3.8+, standard library only) and Claude Code.

```sh
git clone https://github.com/Hendrikv1990/claude-secret-guard.git
cd claude-secret-guard
./install.sh
```

The installer adds three hooks to `~/.claude/settings.json` (it keeps a backup next to it) and links the helpers into `~/.local/bin`. Open `/hooks` in Claude Code once, or restart it, to load them. Running it again is safe. `./install.sh --uninstall` removes everything it added.

Optionally add this to `~/.claude/CLAUDE.md` so Claude uses the safe pattern from the start:

```md
Refer to secrets by environment variable name and never print their values. Load them with `set -a; source .env; set +a`, compare them with `secret-fp NAME`, list them with `envnames`, and change them with `envset`.
```

## Helpers

| Command | Purpose |
|---|---|
| `envnames` | List variable names in the project's `.env` files, marking which look secret. `--process` lists the environment's names. |
| `secret-fp NAME` | Print a short sha256 and the length. Equal fingerprints mean equal values. `secret-fp --all` prints every secret in the project; `heroku config:get X -a app \| secret-fp -` compares a remote value. |
| `envset NAME --stdin \| --clipboard \| --generate [N]` | Add or replace a value in `.env` (or `--file`), printing only its fingerprint. `--clipboard` is meant for you to run yourself: `! envset STRIPE_KEY --clipboard`. |
| `redact` | The filter itself: `some-command \| redact`. |
| `sg-scan` | Scan past transcripts in `~/.claude/projects` for secrets that already reached a chat. Prints file, label and count, never the value. `--project DIR` adds that project's `.env` values to the search. |

## Working with it

```sh
# Use a secret without printing it
set -a; source .env; set +a
curl -s -H "Authorization: Bearer $SERVICE_API_TOKEN" https://api.example.com/leads
DATABASE_URL="$STAGING_DATABASE_URL" bin/rails db:migrate

# Fetch a remote secret straight into a command
X=$(heroku config:get WEBHOOK_SECRET_KEY -a my-app) ./scripts/test-webhook.sh

# Is the local value the same as production?
secret-fp SERVICE_API_TOKEN
heroku config:get SERVICE_API_TOKEN -a my-app | secret-fp -
```

## Configuration

`~/.config/secret-guard/` (or `$SECRET_GUARD_CONFIG`). Claude can't write here.

- `allow`: values never to mask, one per line. Use it for a test fixture that keeps getting masked.
- `env-files`: extra env files to read, one path per line, e.g. a shared `~/.secrets/api.env`.

## Limits

- **It stops accidents, not attacks.** A value that is base64-encoded, split up or reversed gets through.
- **What is checked:** Bash output, Read and Grep of secret files, and your prompts. Output from MCP tools and WebFetch isn't filtered, and neither are files with secrets in them that aren't on the list above (add them to the rules if you have such files).
- **`!` commands you run yourself** don't go through tool hooks, so their output reaches the chat unmasked.
- **The transcript on disk** may still hold the original output. Masking changes what Claude sees and what is sent to the API. A blocked prompt can also remain in your local prompt history.
- **Unexported shell variables** (`X=$(…)` without `export`) aren't visible to the filter. Their values are masked only when they match a known format or look random.
- **Background commands** are rewritten, so permission allow rules are matched against the wrapped command (`… | redact --stream`).

## Tests

```sh
python3 -m unittest discover -s tests
```

## License

MIT
