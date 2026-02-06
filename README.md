# cryper

CLI tool to encrypt and decrypt files with random alphanumeric filenames.
Designed for large files with streaming I/O and parallel chunk processing.

Spec: `docs/cryper.spec.md`

## Install

Requirements: Python 3.12+.

From a local clone:

```bash
python -m pip install -e .
```

## Usage

```bash
cryper encrypt <input_path>
cryper decrypt <input_path>
```

Common options:

- `--out-dir <dir>`: output directory (default: input directory).
- `--threads <n>`: worker threads (default: min(8, cpu_count)).
- `--chunk-size <bytes>`: chunk size, multiple of 16 (default: 8MiB).
- `--passphrase`: prompt for passphrase (default).
- `--passphrase-env <VAR>`: read passphrase from env var.
- `--verbose`: extra logging.

Encrypt-only options:

- `--keep-name`: do not randomize filename; output as `<original>.enc`.

Decrypt-only options:

- `--output-name <name>`: override restored filename.

## Examples

Encrypt a file (prompts for passphrase):

```bash
cryper encrypt "C:\\data\\budget.xlsx"
```

Decrypt a file (prompts for passphrase):

```bash
cryper decrypt "C:\\data\\r19IjpjRZtc5jQTl.crp"
```

Use an environment variable for the passphrase:

```bash
set CRYPER_PASSPHRASE=correct-horse-battery-staple
cryper encrypt "C:\\data\\notes.txt" --passphrase-env CRYPER_PASSPHRASE
```

Encrypt to a specific output directory:

```bash
cryper encrypt "C:\\data\\notes.txt" --out-dir "C:\\vault"
```

Decrypt to a custom output name:

```bash
cryper decrypt "C:\\vault\\aB3xK7qP2mN8rT4l.crp" --output-name notes.txt
```

## Notes

- Output filenames are 16-character random alphanumeric strings with `.crp` extension.
- Existing output paths are never overwritten; collisions fail.
