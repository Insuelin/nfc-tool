"""Wrappers around the existing mfoc / mfcuk / mfoc-hardnested binaries.

They are ordinary command-line programs; we only supply the device string and
stream their output. Nothing here links against libnfc.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path


class EngineError(RuntimeError):
    pass


class Engine:
    name = "engine"
    executable = ""

    def __init__(self, directory: Path, device: str):
        self.directory = Path(directory)
        self.device = device

    @property
    def path(self) -> Path:
        return self.directory / self.executable

    def available(self) -> bool:
        return self.path.is_file()

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["LIBNFC_DEVICE"] = self.device
        env["LIBNFC_AUTO_SCAN"] = "false"
        env["LIBNFC_INTRUSIVE_SCAN"] = "false"
        env.setdefault("PATH", "")
        env["PATH"] = f"{self.directory}{os.pathsep}{env['PATH']}"
        return env

    def run(self, args: list[str], timeout: float, on_line=None) -> tuple[int, str]:
        if not self.available():
            raise EngineError(f"{self.executable} not found in {self.directory}")
        proc = subprocess.Popen(
            [str(self.path), *args],
            cwd=str(self.directory),
            env=self._env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
        )
        lines: list[str] = []
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                lines.append(line.rstrip("\n"))
                if on_line:
                    on_line(line.rstrip("\n"))
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise EngineError(f"{self.name} timed out after {timeout:.0f}s")
        finally:
            if proc.stdout:
                proc.stdout.close()
        return proc.returncode, "\n".join(lines)


class Mfoc(Engine):
    name = "mfoc"
    executable = "mfoc.exe"

    def crack(self, out_path: Path, known_keys: list[bytes] | None = None,
              probes: int = 20, timeout: float = 300.0, on_line=None):
        args: list[str] = []
        for key in known_keys or []:
            args += ["-k", key.hex()]
        args += ["-P", str(probes), "-O", str(out_path)]
        return self.run(args, timeout, on_line)


class Mfcuk(Engine):
    name = "mfcuk"
    executable = "mfcuk.exe"

    def darkside(self, out_path: Path, sector: int = 0, timeout: float = 900.0,
                 on_line=None):
        # -C connects, -R recovers, -O writes the extended dump.
        args = ["-C", "-R", f"{sector}:A", "-s", "250", "-S", "250", "-O", str(out_path)]
        return self.run(args, timeout, on_line)


class Hardnested(Engine):
    name = "mfoc-hardnested"
    executable = "mfoc-hardnested.exe"

    def crack(self, out_path: Path, known_keys: list[bytes] | None = None,
              timeout: float = 3600.0, on_line=None):
        args: list[str] = []
        for key in known_keys or []:
            args += ["-k", key.hex()]
        args += ["-O", str(out_path)]
        return self.run(args, timeout, on_line)


KEY_LINE = re.compile(r"Found Key ([A-Fa-f0-9]{12})", re.I)


def found_keys(text: str) -> list[bytes]:
    return [bytes.fromhex(m) for m in KEY_LINE.findall(text)]


def parse_dump(path: Path) -> bytes:
    return path.read_bytes()


def scratch_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="nfc-tool-"))
