# AGENTS.md
# Guidance for coding agents working in this repository.

## Project overview
- Purpose: CLI tool to encrypt/decrypt files with plausible document-like names.
- Language: Python 3.12+.
- Entry point: console script `cryper` -> `cryper.cli:main`.
- Spec: `docs/cryper.spec.md` is the authoritative format and behavior.

## Repo layout
- `cryper/cli.py`: main implementation and CLI parsing.
- `main.py`: simple placeholder script.
- `docs/cryper.spec.md`: file format, crypto details, CLI contract.
- `pyproject.toml`: package metadata and dependencies.

## Environment and dependencies
- Runtime dependency: `cryptography` (already in `pyproject.toml`).
- Always use `uv run main.py` to run the application.
- Do not use system python directly.
- Do not install dependencies yourself. If dependencies are missing, tell the user to install them using `uv`.

## Building Windows binary
- Run `uv run build_exe.py` to compile the project into a standalone Windows executable using Nuitka.
- Build output: middle files go to `./build/`, final exe goes to `./dist/cryper.exe`.
- Nuitka is configured in `build_exe.py` with `--onefile` mode for single-file distribution.

## Code style and conventions

### General style
- Follow PEP 8 conventions; 4-space indents, no tabs.
- Keep line length reasonable (aim for ~88-100 unless unavoidable).
- Prefer explicit, readable code over cleverness.

### Imports
- Order imports: standard library, third-party, local.
- Group with a blank line between sections.
- Avoid unused imports; keep top-of-file clean.

### Naming
- Module-level constants: UPPER_SNAKE_CASE.
- Functions and variables: snake_case.
- Classes: PascalCase.
- Internal helpers in `cryper/cli.py` start with `_`.

### Types
- Use type hints for public functions and non-trivial helpers.
- Favor built-in generics (`list[str]`, `dict[int, bytes]`).
- Use `Path` from `pathlib` for filesystem paths in new code.

### Error handling
- User-facing errors should raise `CryperError(message, exit_code)`.
- Exit codes are defined in `docs/cryper.spec.md`.
- Keep error messages short and actionable.
- Allow unexpected exceptions to propagate unless a specific user error
  needs handling (e.g., `InvalidSignature`).

### CLI behavior
- Keep CLI flags and semantics aligned with `docs/cryper.spec.md`.
- Avoid breaking changes to option names or defaults without updating the spec.

### File format and crypto
- Do not change `START_MARK`, `END_MARK`, or header format lightly.
- If format or crypto parameters change, update `docs/cryper.spec.md`.
- Maintain CTR chunk alignment and HMAC update order.

### Concurrency
- When using `ThreadPoolExecutor`, preserve chunk ordering on write.
- Keep memory bounded by limiting in-flight futures.

### Logging and output
- Only print user-relevant info (output path on success, errors on stderr).
- Do not add verbose output unless behind a `--verbose` flag.

## Safe defaults for changes
- Prefer additive changes that do not alter encrypted file format.
- Avoid auto-overwrite behavior; current design fails on collisions.
- Preserve temp-file cleanup on errors during decrypt.

## Spec alignment checklist
- CLI flags match spec.
- Exit codes match spec.
- Encryption/decryption stream behavior matches spec.
- Header layout and HMAC construction match spec.
