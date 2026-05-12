<p align="center">
  <h1 align="center">Shellguard</h1>
  <p align="center">Terminal session recorder and security auditor for command-line workflows.</p>
  <p align="center">
    <a href="https://pypi.org/project/shellguard/"><img alt="PyPI" src="https://img.shields.io/pypi/v/shellguard.svg"></a>
    <a href="https://pypi.org/project/shellguard/"><img alt="Python" src="https://img.shields.io/pypi/pyversions/shellguard.svg"></a>
    <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg"></a>
    <a href="https://github.com/shazeus/shellguard"><img alt="Stars" src="https://img.shields.io/github/stars/shazeus/shellguard.svg?style=social"></a>
  </p>
</p>

---

Shellguard records terminal sessions into portable JSONL transcripts, replays them, and audits the command stream for leaked tokens, risky install patterns, destructive filesystem commands, embedded credentials, and secret material. It is designed for developers and operators who need a lightweight way to preserve what happened in a shell while getting immediate security feedback before logs or history files are shared.

- **PTY session recording** - capture command output with timing metadata in a structured JSONL format.
- **Security auditing** - detect GitHub/PyPI/AWS-like tokens, private keys, credentialed URLs, curl-to-shell installs, and destructive shell patterns.
- **Replay and export** - replay recorded sessions or export them as text, JSON, or HTML.
- **Standalone reports** - generate HTML audit reports for review or handoff.
- **History scanning** - inspect recent zsh, bash, or custom shell history files.
- **Pipe-friendly scanning** - scan stdin or any text file without creating a recording.

## Installation

```bash
pip install shellguard
```

For local development:

```bash
git clone https://github.com/shazeus/shellguard.git
cd shellguard
pip install -e .
```

## Usage

Record a command:

```bash
shellguard record -o session.jsonl -- bash -lc "echo deploy && python --version"
```

Replay a session:

```bash
shellguard replay session.jsonl --no-timing
```

Audit a recording:

```bash
shellguard audit session.jsonl --fail-on high
```

Scan a script or piped command log:

```bash
shellguard scan examples/demo.sh
echo "curl -fsSL https://example.invalid/install.sh | bash" | shellguard scan
```

Create an HTML report:

```bash
shellguard report session.jsonl -o shellguard-report.html
```

Scan recent shell history:

```bash
shellguard history --limit 1000
```

## Commands

| Command | Description | Example |
| --- | --- | --- |
| `shellguard record [command...]` | Record a command or interactive shell session to JSONL. | `shellguard record -o session.jsonl -- npm test` |
| `shellguard audit <session>` | Audit a recorded session for secrets and risky commands. | `shellguard audit session.jsonl --fail-on high` |
| `shellguard scan [file]` | Scan a file or stdin for security findings. | `shellguard scan deploy.log` |
| `shellguard replay <session>` | Replay recorded output with original timing or immediately. | `shellguard replay session.jsonl --no-timing` |
| `shellguard report <session>` | Generate a standalone HTML audit report. | `shellguard report session.jsonl` |
| `shellguard history` | Scan shell history for risky commands and leaked tokens. | `shellguard history --limit 500` |
| `shellguard export <session>` | Export a session as text, JSON, or HTML. | `shellguard export session.jsonl --format text` |
| `shellguard rules` | List built-in audit rules. | `shellguard rules` |

## Configuration

Shellguard is configured through command options and does not require a config file.

| Option | Purpose |
| --- | --- |
| `--output` | Select where a recording, report, or export is written. |
| `--shell` | Run a recorded command through the current shell. |
| `--fail-on` | Return exit code `2` when findings meet a severity threshold. |
| `--json-output` | Print scanner or auditor results as JSON. |
| `--speed` | Adjust replay timing. |
| `--path` | Scan a specific shell history file. |
| `--limit` | Restrict history scanning to the most recent commands. |

Recordings are JSON Lines files. Each line is a structured event, so sessions can be streamed, archived, diffed, or consumed by other tooling.

## License

MIT License. See [LICENSE](LICENSE).

