# cryper

CLI tool to encrypt and decrypt files while using plausible document-like
filenames. Designed for large files with streaming I/O and parallel chunk
processing.

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

- `--ext {docx,pptx,xlsx}`: force output extension.
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
cryper decrypt "C:\\data\\2026_02_Texas_report_814233.docx"
```

Use an environment variable for the passphrase:

```bash
set CRYPER_PASSPHRASE=correct-horse-battery-staple
cryper encrypt "C:\\data\\notes.txt" --passphrase-env CRYPER_PASSPHRASE
```

Encrypt to a specific output directory and extension:

```bash
cryper encrypt "C:\\data\\notes.txt" --out-dir "C:\\vault" --ext xlsx
```

Decrypt to a custom output name:

```bash
cryper decrypt "C:\\vault\\2026_02_Ohio_review_552901.xlsx" --output-name notes.txt
```

## Notes

- Output filenames mimic common Office extensions but contain encrypted data.
- Existing output paths are never overwritten; collisions fail.
