import argparse
import getpass
import os
import secrets
import struct
import sys
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

START_MARK = b"CRYPER_START_v1!"
END_MARK = b"CRYPER_END___v1!"

HMAC_SIZE = 32
MAX_FILENAME_LEN = 4096
MAX_CHUNK_SIZE = 64 * 1024 * 1024

DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024

KDF_ID_SCRYPT = 1
AES_MODE_CTR = 1

SCRYPT_N_LOG2 = 20
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_LEN = 16

DOC_TYPES = [
    "report",
    "summary",
    "analysis",
    "brief",
    "notes",
    "minutes",
    "proposal",
    "plan",
    "review",
    "update",
]

STATES = [
    "Alabama",
    "Alaska",
    "Arizona",
    "Arkansas",
    "California",
    "Colorado",
    "Connecticut",
    "Delaware",
    "Florida",
    "Georgia",
    "Hawaii",
    "Idaho",
    "Illinois",
    "Indiana",
    "Iowa",
    "Kansas",
    "Kentucky",
    "Louisiana",
    "Maine",
    "Maryland",
    "Massachusetts",
    "Michigan",
    "Minnesota",
    "Mississippi",
    "Missouri",
    "Montana",
    "Nebraska",
    "Nevada",
    "New_Hampshire",
    "New_Jersey",
    "New_Mexico",
    "New_York",
    "North_Carolina",
    "North_Dakota",
    "Ohio",
    "Oklahoma",
    "Oregon",
    "Pennsylvania",
    "Rhode_Island",
    "South_Carolina",
    "South_Dakota",
    "Tennessee",
    "Texas",
    "Utah",
    "Vermont",
    "Virginia",
    "Washington",
    "West_Virginia",
    "Wisconsin",
    "Wyoming",
]


class CryperError(Exception):
    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class MetaInfo:
    salt: bytes
    scrypt_n_log2: int
    scrypt_r: int
    scrypt_p: int
    iv: bytes
    plaintext_size: int
    chunk_size: int


def _default_threads() -> int:
    cpu_count = os.cpu_count() or 4
    return min(8, cpu_count)


def _require_file(path: Path) -> None:
    if not path.exists() or not path.is_file():
        raise CryperError(f"input file not found: {path}", 3)


def _validate_chunk_size(chunk_size: int) -> None:
    if chunk_size % 16 != 0:
        raise CryperError("chunk size must be a multiple of 16", 2)
    if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
        raise CryperError("chunk size out of allowed range", 2)


def _validate_threads(threads: int) -> None:
    if threads <= 0:
        raise CryperError("threads must be positive", 2)


def _get_passphrase(args: argparse.Namespace) -> str:
    if args.passphrase_env:
        value = os.environ.get(args.passphrase_env)
        if value is None:
            raise CryperError(
                f"passphrase environment variable not set: {args.passphrase_env}",
                2,
            )
        return value
    return getpass.getpass("Passphrase: ")


def _derive_keys(passphrase: str, meta: MetaInfo) -> tuple[bytes, bytes]:
    kdf = Scrypt(
        salt=meta.salt,
        length=64,
        n=1 << meta.scrypt_n_log2,
        r=meta.scrypt_r,
        p=meta.scrypt_p,
    )
    key_material = kdf.derive(passphrase.encode("utf-8"))
    return key_material[:32], key_material[32:]


def _ctr_iv_for_offset(iv: bytes, offset: int) -> bytes:
    blocks = offset // 16
    iv_int = int.from_bytes(iv, "big")
    return (iv_int + blocks).to_bytes(16, "big")


def _encrypt_chunk(enc_key: bytes, iv: bytes, offset: int, data: bytes) -> bytes:
    counter = _ctr_iv_for_offset(iv, offset)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(counter))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _decrypt_chunk(enc_key: bytes, iv: bytes, offset: int, data: bytes) -> bytes:
    counter = _ctr_iv_for_offset(iv, offset)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(counter))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _build_header(filename_bytes: bytes, meta: MetaInfo) -> bytes:
    header = bytearray()
    header += START_MARK
    header += struct.pack("<I", len(filename_bytes))
    header += filename_bytes
    header += END_MARK
    header += struct.pack("<HBB", 1, KDF_ID_SCRYPT, len(meta.salt))
    header += meta.salt
    header += struct.pack("<BII", meta.scrypt_n_log2, meta.scrypt_r, meta.scrypt_p)
    header += struct.pack("<BB", AES_MODE_CTR, len(meta.iv))
    header += meta.iv
    header += struct.pack("<QI", meta.plaintext_size, meta.chunk_size)
    return bytes(header)


def _parse_header(file_obj) -> tuple[str, MetaInfo, bytes]:
    header = bytearray()

    start = file_obj.read(len(START_MARK))
    if start != START_MARK:
        raise CryperError("invalid start mark", 5)
    header += start

    filename_len_bytes = file_obj.read(4)
    if len(filename_len_bytes) != 4:
        raise CryperError("invalid filename length", 5)
    header += filename_len_bytes
    (filename_len,) = struct.unpack("<I", filename_len_bytes)
    if filename_len > MAX_FILENAME_LEN:
        raise CryperError("filename length too large", 5)

    filename_bytes = file_obj.read(filename_len)
    if len(filename_bytes) != filename_len:
        raise CryperError("invalid filename bytes", 5)
    header += filename_bytes

    end = file_obj.read(len(END_MARK))
    if end != END_MARK:
        raise CryperError("invalid end mark", 5)
    header += end

    meta_prefix = file_obj.read(4)
    if len(meta_prefix) != 4:
        raise CryperError("invalid meta header", 5)
    header += meta_prefix
    meta_version, kdf_id, salt_len = struct.unpack("<HBB", meta_prefix)
    if meta_version != 1 or kdf_id != KDF_ID_SCRYPT:
        raise CryperError("unsupported meta version or kdf", 5)

    salt = file_obj.read(salt_len)
    if len(salt) != salt_len:
        raise CryperError("invalid salt", 5)
    header += salt

    scrypt_params = file_obj.read(9)
    if len(scrypt_params) != 9:
        raise CryperError("invalid scrypt params", 5)
    header += scrypt_params
    scrypt_n_log2, scrypt_r, scrypt_p = struct.unpack("<BII", scrypt_params)

    aes_meta = file_obj.read(2)
    if len(aes_meta) != 2:
        raise CryperError("invalid aes meta", 5)
    header += aes_meta
    aes_mode, iv_len = struct.unpack("<BB", aes_meta)
    if aes_mode != AES_MODE_CTR or iv_len != 16:
        raise CryperError("unsupported aes mode or iv length", 5)

    iv = file_obj.read(iv_len)
    if len(iv) != iv_len:
        raise CryperError("invalid iv", 5)
    header += iv

    sizes = file_obj.read(12)
    if len(sizes) != 12:
        raise CryperError("invalid size meta", 5)
    header += sizes
    plaintext_size, chunk_size = struct.unpack("<QI", sizes)

    if chunk_size % 16 != 0 or chunk_size > MAX_CHUNK_SIZE:
        raise CryperError("invalid chunk size", 5)

    try:
        filename = filename_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CryperError("invalid filename encoding", 5) from exc

    meta = MetaInfo(
        salt=salt,
        scrypt_n_log2=scrypt_n_log2,
        scrypt_r=scrypt_r,
        scrypt_p=scrypt_p,
        iv=iv,
        plaintext_size=plaintext_size,
        chunk_size=chunk_size,
    )

    return filename, meta, bytes(header)


def _generate_output_name(ext: str | None) -> str:
    now = datetime.now()
    year = f"{now.year:04d}"
    month = f"{now.month:02d}"
    state = secrets.choice(STATES)
    doc_type = secrets.choice(DOC_TYPES)
    rand = f"{secrets.randbelow(1_000_000):06d}"
    extension = ext or secrets.choice(["docx", "pptx", "xlsx"])
    return f"{year}{month}_{state}_{doc_type}_{rand}.{extension}"


def _encrypt_file(args: argparse.Namespace) -> None:
    input_path = Path(args.input_path)
    _require_file(input_path)
    _validate_chunk_size(args.chunk_size)
    _validate_threads(args.threads)

    passphrase = _get_passphrase(args)

    out_dir = Path(args.out_dir) if args.out_dir else input_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.keep_name:
        output_name = f"{input_path.name}.enc"
    else:
        output_name = _generate_output_name(args.ext)

    output_path = out_dir / output_name
    if output_path.exists():
        raise CryperError("output file already exists", 4)

    plaintext_size = input_path.stat().st_size
    salt = secrets.token_bytes(SCRYPT_SALT_LEN)
    iv = secrets.token_bytes(16)
    meta = MetaInfo(
        salt=salt,
        scrypt_n_log2=SCRYPT_N_LOG2,
        scrypt_r=SCRYPT_R,
        scrypt_p=SCRYPT_P,
        iv=iv,
        plaintext_size=plaintext_size,
        chunk_size=args.chunk_size,
    )
    enc_key, mac_key = _derive_keys(passphrase, meta)

    filename_bytes = input_path.name.encode("utf-8")
    if len(filename_bytes) > MAX_FILENAME_LEN:
        raise CryperError("filename too long", 2)
    header = _build_header(filename_bytes, meta)

    hmac_obj = hmac.HMAC(mac_key, hashes.SHA256())
    hmac_obj.update(header)

    max_inflight = max(1, args.threads * 2)
    next_index = 0
    index = 0
    offset = 0
    futures: dict[int, Future[bytes]] = {}

    try:
        with open(input_path, "rb") as source, open(output_path, "xb") as dest:
            dest.write(header)
            with ThreadPoolExecutor(max_workers=args.threads) as pool:
                while True:
                    if len(futures) >= max_inflight:
                        future = futures.pop(next_index)
                        ciphertext = future.result()
                        dest.write(ciphertext)
                        hmac_obj.update(ciphertext)
                        next_index += 1
                        continue

                    chunk = source.read(args.chunk_size)
                    if not chunk:
                        break
                    current_index = index
                    current_offset = offset
                    index += 1
                    offset += len(chunk)
                    futures[current_index] = pool.submit(
                        _encrypt_chunk, enc_key, iv, current_offset, chunk
                    )

                while next_index < index:
                    future = futures.pop(next_index)
                    ciphertext = future.result()
                    dest.write(ciphertext)
                    hmac_obj.update(ciphertext)
                    next_index += 1

            dest.write(hmac_obj.finalize())
    except FileExistsError as exc:
        raise CryperError("output file already exists", 4) from exc

    print(output_path)


def _decrypt_file(args: argparse.Namespace) -> None:
    input_path = Path(args.input_path)
    _require_file(input_path)
    _validate_threads(args.threads)

    passphrase = _get_passphrase(args)

    out_dir = Path(args.out_dir) if args.out_dir else input_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    total_size = input_path.stat().st_size
    if total_size <= HMAC_SIZE:
        raise CryperError("invalid file size", 5)

    with open(input_path, "rb") as source:
        filename, meta, header = _parse_header(source)
        header_len = len(header)
        if total_size < header_len + HMAC_SIZE:
            raise CryperError("invalid file size", 5)

        ciphertext_len = total_size - header_len - HMAC_SIZE
        if ciphertext_len != meta.plaintext_size:
            raise CryperError("ciphertext size mismatch", 5)

        output_name = args.output_name or filename
        output_name = Path(output_name).name
        output_path = out_dir / output_name
        if output_path.exists():
            raise CryperError("output file already exists", 4)

        temp_path = out_dir / f"{output_name}.tmp.cryper"
        if temp_path.exists():
            raise CryperError("temp file already exists", 4)

        source.seek(-HMAC_SIZE, os.SEEK_END)
        tag = source.read(HMAC_SIZE)
        if len(tag) != HMAC_SIZE:
            raise CryperError("invalid hmac tag", 5)

        source.seek(header_len)

        enc_key, mac_key = _derive_keys(passphrase, meta)
        hmac_obj = hmac.HMAC(mac_key, hashes.SHA256())
        hmac_obj.update(header)

        max_inflight = max(1, args.threads * 2)
        next_index = 0
        index = 0
        offset = 0
        futures: dict[int, Future[bytes]] = {}

        try:
            with open(temp_path, "xb") as dest:
                with ThreadPoolExecutor(max_workers=args.threads) as pool:
                    remaining = ciphertext_len
                    while remaining > 0:
                        if len(futures) >= max_inflight:
                            future = futures.pop(next_index)
                            plaintext = future.result()
                            dest.write(plaintext)
                            next_index += 1
                            continue

                        read_size = min(meta.chunk_size, remaining)
                        chunk = source.read(read_size)
                        if len(chunk) != read_size:
                            raise CryperError("unexpected eof", 5)
                        hmac_obj.update(chunk)

                        current_index = index
                        current_offset = offset
                        index += 1
                        offset += len(chunk)
                        remaining -= len(chunk)
                        futures[current_index] = pool.submit(
                            _decrypt_chunk, enc_key, meta.iv, current_offset, chunk
                        )

                    while next_index < index:
                        future = futures.pop(next_index)
                        plaintext = future.result()
                        dest.write(plaintext)
                        next_index += 1

                try:
                    hmac_obj.verify(tag)
                except InvalidSignature as exc:
                    raise CryperError("hmac verification failed", 5) from exc
        except Exception:
            if temp_path.exists():
                temp_path.unlink(missing_ok=True)
            raise

    os.rename(temp_path, output_path)
    print(output_path)


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-o",
        "--output",
        "--out-dir",
        dest="out_dir",
        help="output directory",
    )
    parser.add_argument("--threads", type=int, default=_default_threads())
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--verbose", action="store_true")
    passphrase_group = parser.add_mutually_exclusive_group()
    passphrase_group.add_argument("--passphrase", action="store_true")
    passphrase_group.add_argument("--passphrase-env", metavar="VAR")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="cryper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser("encrypt", help="encrypt a file")
    encrypt_parser.add_argument("input_path")
    encrypt_parser.add_argument("--ext", choices=["docx", "pptx", "xlsx"])
    encrypt_parser.add_argument("--keep-name", action="store_true")
    _add_common_args(encrypt_parser)
    encrypt_parser.set_defaults(handler=_encrypt_file)

    decrypt_parser = subparsers.add_parser("decrypt", help="decrypt a file")
    decrypt_parser.add_argument("input_path")
    decrypt_parser.add_argument("--output-name")
    _add_common_args(decrypt_parser)
    decrypt_parser.set_defaults(handler=_decrypt_file)

    args = parser.parse_args(argv)

    try:
        args.handler(args)
    except CryperError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(exc.exit_code)


if __name__ == "__main__":
    main()
