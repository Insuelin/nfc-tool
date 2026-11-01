# Copyright (C) 2026 Insuelin
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <https://www.gnu.org/licenses/>.

"""Wrappers around the existing mfoc / mfcuk / mfoc-hardnested binaries.

They are ordinary command-line programs; we only supply the device string and
stream their output. Nothing here links against libnfc.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import threading
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

        def reader() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                text = line.rstrip("\n")
                lines.append(text)
                if on_line:
                    on_line(text)

        pump = threading.Thread(target=reader, daemon=True)
        pump.start()
        try:
            # wait() is the real timeout: a silent child still gets killed.
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise EngineError(f"{self.name} timed out after {timeout:.0f}s")
        finally:
            pump.join(timeout=1.0)
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
        # -C connects, -R recovers, -O writes the extended dump. Leave the
        # field delays at their defaults (10/50 ms); the old 250/250 made the
        # verify phase take minutes per sector.
        args = ["-C", "-R", f"{sector}:A", "-O", str(out_path)]
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


# mfoc / mfoc-hardnested: "Found Key: A [a0a1a2a3a4a5]"
# mfcuk:                  "INFO: block 0 recovered KEY: a0a1a2a3a4a5"
#                         "    key: a0a1a2a3a4a5"
KEY_PATTERNS = (
    # mfoc: "[Key: ffffffffffff] -> [...]" is a *tried* key, so only the
    # explicit "Found Key: A [..]" line counts.
    re.compile(r"Found Key:\s*[AB]\s*\[([0-9A-Fa-f]{12})\]", re.I),
    # mfcuk: "INFO: block 0 recovered KEY: ..." and "    key: ..." at line start.
    re.compile(r"recovered KEY:\s*([0-9A-Fa-f]{12})", re.I),
    re.compile(r"^[ \t]+key:\s*([0-9A-Fa-f]{12})[ \t]*$", re.I | re.M),
    # mfoc with -O prints the key it authenticated with for every saved block:
    # "Block 03, type A, key 000000000000 :..."
    re.compile(r"^Block\s+\d+,\s*type\s+[AB],\s*key\s+([0-9A-Fa-f]{12})\b",
               re.I | re.M),
)


def found_keys(text: str) -> list[bytes]:
    seen: list[bytes] = []
    for pattern in KEY_PATTERNS:
        for match in pattern.findall(text):
            key = bytes.fromhex(match)
            if key not in seen:
                seen.append(key)
    return seen


def parse_dump(path: Path) -> bytes:
    return path.read_bytes()


def scratch_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="nfc-tool-"))
