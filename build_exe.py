import shutil
import subprocess
import sys
from pathlib import Path


def build_exe() -> None:
    script_path = Path(__file__).parent / "main.py"
    build_dir = Path(__file__).parent / "build"
    dist_dir = Path(__file__).parent / "dist"

    build_dir.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        str(script_path),
        "--onefile",
        "--output-dir=" + str(build_dir),
        "--output-filename=cryper.exe",
    ]

    subprocess.run(cmd, check=True)

    exe_path = build_dir / "cryper.exe"
    if exe_path.exists():
        shutil.move(str(exe_path), str(dist_dir / "cryper.exe"))
    else:
        print(f"Warning: Expected executable not found at {exe_path}")


if __name__ == "__main__":
    build_exe()
