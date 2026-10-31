"""Minimal PN532 HSU (UART) driver.

Speaks the PN532 frame protocol directly over pyserial. No libnfc, no CGO,
no build step. Verified against PN532 v1.6 firmware on a CH340 adapter.
"""

from __future__ import annotations

import time
import serial

ACK = bytes([0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00])
PREAMBLE = b"\x00\x00\xff"
HOST = 0xD4
CHIP = 0xD5


class PN532Error(Exception):
    pass


class PN532Timeout(PN532Error):
    pass


def build_frame(data: bytes) -> bytes:
    """Wrap payload in a PN532 frame: 00 00 FF LEN LCS <data> DCS 00."""
    if not 1 <= len(data) <= 255:
        raise ValueError("payload length out of range")
    lcs = (0x100 - len(data)) & 0xFF
    dcs = (0x100 - (sum(data) & 0xFF)) & 0xFF
    return PREAMBLE + bytes([len(data), lcs]) + data + bytes([dcs, 0x00])


def find_frame(buf: bytearray):
    """Locate one complete, checksum-valid frame. Returns (payload, consumed)."""
    i = 0
    while True:
        idx = buf.find(PREAMBLE, i)
        if idx < 0 or len(buf) < idx + 6:
            return None, 0
        length, lcs = buf[idx + 3], buf[idx + 4]
        if (length + lcs) & 0xFF != 0:
            i = idx + 1
            continue
        total = idx + 5 + length + 2
        if len(buf) < total:
            return None, 0
        payload = bytes(buf[idx + 5:idx + 5 + length])
        dcs = buf[idx + 5 + length]
        if (sum(payload) + dcs) & 0xFF != 0:
            i = idx + 1
            continue
        return payload, total


class PN532:
    def __init__(self, port: str = "COM3", baud: int = 115200):
        self.port = port
        self.baud = baud
        self.ser: serial.Serial | None = None
        self.firmware: tuple[int, int, int] | None = None

    # -- lifecycle -------------------------------------------------

    def open(self) -> tuple[int, int, int]:
        self.ser = serial.Serial(self.port, self.baud, timeout=0.05, write_timeout=1.0)
        time.sleep(0.15)
        for _ in range(16):
            self.ser.write(b"\x55")
            time.sleep(0.002)
        time.sleep(0.05)
        self.ser.reset_input_buffer()
        self.firmware = self.get_firmware()
        return self.firmware

    def close(self) -> None:
        if self.ser and self.ser.is_open:
            self.ser.close()
        self.ser = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    # -- transport -------------------------------------------------

    def call(self, cmd: bytes, timeout: float = 1.0) -> bytes:
        if not self.ser:
            raise PN532Error("port is not open")
        self.ser.reset_input_buffer()
        self.ser.write(build_frame(bytes([HOST]) + cmd))

        buf = bytearray()
        deadline = time.time() + timeout
        while time.time() < deadline:
            waiting = self.ser.in_waiting
            if waiting:
                buf += self.ser.read(waiting)
            while buf.startswith(ACK):
                del buf[:len(ACK)]
            payload, consumed = find_frame(buf)
            if payload is not None:
                del buf[:consumed]
                if payload[0] != CHIP:
                    continue
                if len(payload) >= 2 and payload[1] == 0x7F:
                    raise PN532Error(f"chip error 0x{payload[2]:02X}" if len(payload) > 2 else "chip error")
                return payload
            time.sleep(0.01)
        raise PN532Timeout(f"no response to 0x{cmd[0]:02X} within {timeout:.1f}s")

    # -- commands --------------------------------------------------

    def get_firmware(self) -> tuple[int, int, int]:
        r = self.call(b"\x02", timeout=2.0)
        if len(r) < 5:
            raise PN532Error(f"short firmware response: {r.hex(' ')}")
        return r[2], r[3], r[4]

    def list_passive(self, brty: int = 0x00, max_tg: int = 1) -> dict | None:
        """InListPassiveTarget. Returns card info or None when no card present."""
        r = self.call(b"\x4A" + bytes([max_tg, brty]), timeout=2.0)
        if len(r) < 3 or r[2] == 0:
            return None
        nb_tg, tg = r[2], r[3]
        idx = 4
        if len(r) < idx + 3:
            return None
        atqa = r[idx:idx + 2]
        sak = r[idx + 2]
        idx += 3
        if len(r) <= idx:
            return None
        uid_len = r[idx]
        idx += 1
        uid = r[idx:idx + uid_len]
        return {"target": tg, "atqa": atqa, "sak": sak, "uid": uid}

    def data_exchange(self, target: int, payload: bytes, timeout: float = 1.0) -> tuple[int, bytes]:
        """InDataExchange with crypto1 handling for MIFARE Classic."""
        r = self.call(b"\x40" + bytes([target]) + payload, timeout=timeout)
        status = r[2] if len(r) > 2 else 0xFF
        return status, r[3:]

    def communicate_thru(self, target: int, payload: bytes, timeout: float = 1.0) -> tuple[int, bytes]:
        """InCommunicateThru: raw frame to the target, no crypto1."""
        r = self.call(b"\x42" + bytes([target]) + payload, timeout=timeout)
        status = r[2] if len(r) > 2 else 0xFF
        return status, r[3:]

    # -- MIFARE helpers -------------------------------------------

    def auth(self, target: int, block: int, key: bytes, key_type: bytes = b"\x60",
             uid: bytes = b"") -> bool:
        """Authenticate one block. key_type is 0x60 (A) or 0x61 (B)."""
        payload = key_type + bytes([block]) + key
        if uid:
            payload += uid
        status, _ = self.data_exchange(target, payload)
        return status == 0x00

    def read_block(self, target: int, block: int) -> bytes:
        status, data = self.data_exchange(target, b"\x30" + bytes([block]))
        if status != 0x00:
            raise PN532Error(f"read block {block} failed, status 0x{status:02X}")
        if len(data) < 16:
            raise PN532Error(f"read block {block} short data: {data.hex(' ')}")
        return data[:16]

    def write_block(self, target: int, block: int, data: bytes) -> bool:
        if len(data) != 16:
            raise ValueError("block data must be 16 bytes")
        status, _ = self.data_exchange(target, b"\xA0" + bytes([block]) + data)
        return status == 0x00


def describe(card: dict) -> str:
    sak = card["sak"]
    uid = card["uid"].hex().upper()
    atqa = card["atqa"].hex(" ").upper()
    name = {0x08: "MIFARE Classic 1K", 0x18: "MIFARE Classic 4K",
            0x09: "MIFARE Mini", 0x00: "Ultralight"}.get(sak, f"SAK 0x{sak:02X}")
    return f"UID={uid}  ATQA={atqa}  SAK=0x{sak:02X}  {name}"


if __name__ == "__main__":
    import sys

    port = sys.argv[1] if len(sys.argv) > 1 else "COM3"
    with PN532(port) as nfc:
        ic, ver, rev = nfc.firmware
        print(f"PN532 v{ver}.{rev} (IC 0x{ic:02X}) on {port}")
        card = nfc.list_passive()
        print(describe(card) if card else "no card")
