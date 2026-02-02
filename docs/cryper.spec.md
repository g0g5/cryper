# cryper: Spec (v0.1)

This document specifies a CLI program that (1) renames a file to a plausible document-like name and (2) encrypts it with AES-256, and can later (3) decrypt it and restore the original filename.

Scope: single-file encrypt/decrypt. Large-file oriented (200MB to ~2GB) with streaming I/O and parallel chunk processing.

## Goals

- Encrypt a single input file to a new file with a generated “document-like” name.
- Decrypt an encrypted file back to plaintext and restore the original base filename.
- AES-256 encryption with authenticated integrity.
- Streaming operation (do not load whole file into RAM).
- Parallelizable encryption/decryption for throughput on large files.

## Non-goals

- Directory/folder recursion.
- Hiding file existence (this is not steganography).
- Compressing data.

## CLI

Executable name (Python entry point): `cryper`

Subcommands:

- `cryper encrypt <input_path>`
- `cryper decrypt <input_path>`

Common options:

- `--out-dir <dir>`: output directory (default: same directory as input).
- `--threads <n>`: number of worker threads (default: `min(8, os.cpu_count() or 4)`).
- `--chunk-size <bytes>`: chunk size (default: `8MiB`; must be a multiple of 16).
- `--verbose`: extra logging.

Passphrase options (encrypt + decrypt):

- `--passphrase`: read passphrase from stdin prompt (default behavior; uses `getpass`).
- `--passphrase-env <VAR>`: read passphrase from environment variable `VAR`.

Encrypt-only options:

- `--ext {docx,pptx,xlsx}`: force output extension; otherwise randomly choose from the set.
- `--keep-name`: do not randomize filename; encrypt to `<original>.enc` (mainly for testing).

Decrypt-only options:

- `--output-name <name>`: override restored filename (debug/recovery use).

Exit codes:

- `0`: success
- `2`: invalid arguments / usage
- `3`: input file not found / not a file
- `4`: output file exists (overwrite is not performed)
- `5`: decrypt failed (bad header / wrong passphrase / integrity failure)

## Filename Generation

Generated output base name format:

`<YYYY><MM>_<STATE>_<DOCTYPE>_<RANDOM>.<EXT>`

- `YYYY`: current year (4 digits)
- `MM`: current month (2 digits)
- `STATE`: token from US states list (sanitized: ASCII letters and underscores only)
- `DOCTYPE`: token from common document types list (sanitized)
- `RANDOM`: 6 digits from a cryptographically secure RNG (`secrets`)
- `EXT`: one of `docx`, `pptx`, `xlsx`

Collision handling:

- If the generated output path already exists, fail (no overwrite, no auto-rename).

US state tokens (example set; full list is the 50 states, space replaced with `_`):

- `Alabama`, `Alaska`, `Arizona`, ... `New_York`, ... `Wyoming`

Document type tokens (initial set; can be extended later):

- `report`, `summary`, `analysis`, `brief`, `notes`, `minutes`, `proposal`, `plan`, `review`, `update`

## Cryptography

Construction:

- Encryption: AES-256 in CTR mode (stream cipher) for confidentiality.
- Integrity: HMAC-SHA256 over `header || ciphertext`.

Rationale:

- AES-CTR allows independent chunk encryption/decryption (good for multi-threading).
- HMAC provides strong tamper detection and wrong-passphrase detection.

Library:

- Use `cryptography` (OpenSSL-backed) for AES + HMAC + KDF.

### Key Derivation (Passphrase)

Derive keys from a user passphrase with scrypt:

- KDF: scrypt
- Parameters (defaults; stored in header):
  - `N = 2**20`
  - `r = 8`
  - `p = 1`
  - `salt_len = 16`

Output key material: 64 bytes derived, split as:

- `enc_key`: first 32 bytes (AES-256)
- `mac_key`: last 32 bytes (HMAC-SHA256)

### AES-CTR IV / Initial Counter

- `iv`: 16 random bytes stored in header.
- Chunk `i` at offset `i * chunk_size` uses counter advanced by `offset // 16` blocks.
- Chunk boundaries must be multiples of 16 bytes (enforced by `--chunk-size`).

## File Format

Encrypted file layout:

`[START_MARK][FILENAME_LEN][FILENAME_UTF8][END_MARK][CRYPER_META][CIPHERTEXT][HMAC_TAG]`

Where:

- `START_MARK`: fixed 16 bytes: ASCII `CRYPER_START_v1!`
- `FILENAME_LEN`: uint32 little-endian, number of bytes in `FILENAME_UTF8`
- `FILENAME_UTF8`: original *base filename* (no directory), UTF-8 encoded
- `END_MARK`: fixed 16 bytes: ASCII `CRYPER_END___v1!`

`CRYPER_META` follows immediately after `END_MARK` and is a binary struct:

- `meta_version`: uint16 LE (initially `1`)
- `kdf_id`: uint8 (1 = scrypt)
- `salt_len`: uint8
- `salt`: `salt_len` bytes
- `scrypt_N_log2`: uint8 (e.g., 20 for 2**20)
- `scrypt_r`: uint32 LE
- `scrypt_p`: uint32 LE
- `aes_mode`: uint8 (1 = CTR)
- `iv_len`: uint8 (must be 16)
- `iv`: `iv_len` bytes
- `plaintext_size`: uint64 LE
- `chunk_size`: uint32 LE

`CIPHERTEXT` is the AES-CTR encryption of the plaintext bytes.

`HMAC_TAG` is 32 bytes, appended at EOF:

- `tag = HMAC-SHA256(mac_key, header_and_meta || ciphertext)`
- `header_and_meta` means everything from `START_MARK` through the end of `CRYPER_META`.

Notes:

- The required “mark head” (`START_MARK` + filename length + filename UTF-8 + `END_MARK`) is kept exactly at the very beginning of the file.
- The `CRYPER_META` block allows versioning, parameter storage, and robust parsing.

## Encryption Process

Inputs:

- `input_path`: path to an existing file
- `passphrase`: user-provided

Steps:

1. Read and validate `input_path` is a regular file.
2. Generate output name using the filename generation rules.
3. Generate `salt` (16 bytes) and `iv` (16 bytes).
4. Derive `enc_key` and `mac_key` with scrypt.
5. Write header marks + filename info + meta to the output file.
6. Encrypt the plaintext in chunks:
   - Use a bounded work queue + `ThreadPoolExecutor`.
   - For each chunk at offset `off`, compute the correct CTR initial counter for that offset.
   - Encrypt chunk and return `(index, ciphertext)`.
   - A single writer writes ciphertext in chunk index order.
7. While writing ciphertext, incrementally update HMAC with `header_and_meta` first, then each ciphertext chunk in order.
8. Append the final 32-byte HMAC tag.

Memory bounds:

- Peak memory approx `threads * chunk_size * 2` (plaintext + ciphertext buffers), plus overhead.

## Decryption Process

Inputs:

- `input_path`: path to an encrypted file
- `passphrase`: user-provided

Steps:

1. Parse and validate `START_MARK`, `END_MARK`, and decode original filename.
2. Parse `CRYPER_META` and validate supported versions/parameters.
3. Derive `enc_key` and `mac_key` from passphrase using stored KDF params.
4. Compute and verify HMAC:
   - Stream over `header_and_meta || ciphertext` and compare against trailing `HMAC_TAG`.
   - If verification fails, abort with exit code `5`.
5. Decrypt ciphertext in chunks (parallelizable like encryption) into a temporary output file in `--out-dir`.
6. After successful decryption, move/rename the temp file to the restored filename (or `--output-name` if set).
7. Fail if the final output path already exists.

Temp file naming:

- Use a deterministic safe name like `<restored>.tmp.cryper` in the output directory.
- If the temp path already exists, fail.

## Validation Rules

- Marks must match exactly; otherwise reject as not a cryper file.
- `FILENAME_LEN` must be reasonable (e.g., <= 4096 bytes).
- `chunk_size` must be a multiple of 16 and <= a max (e.g., 64MiB).
- `plaintext_size` must be consistent with ciphertext length.
- HMAC must verify before finalizing decrypted output.

## Logging / UX

- Print the generated output filename on encrypt.
- Print the restored output path on decrypt.
- For large files, optionally show progress (bytes processed / total). (Implementation detail; not required for v0.1.)

## Dependencies / Packaging (uv)

- Add runtime dependency: `cryptography`.
- Configure console script entry point in `pyproject.toml`:

  - `[project.scripts]`
  - `cryper = "cryper.cli:main"` (module layout to be created during implementation)

## Security Notes

- Using a fake Office extension is intentionally misleading; users should treat these files as encrypted blobs.
- Passphrases should be high-entropy; recommend a password manager.
- CTR + HMAC is secure when IV is unique per file and keys are derived safely (scrypt + random salt).

## Test Plan (v0.1)

- Round-trip: encrypt then decrypt returns identical bytes for small and large files.
- Wrong passphrase: decrypt fails with integrity error.
- Tamper: flipping a byte causes HMAC failure.
- Unicode filename: original filename restored correctly.
- Collision: output exists -> fails.
