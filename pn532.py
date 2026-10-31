"""Minimal PN532 HSU (UART) driver.

Speaks the PN532 frame protocol directly over pyserial. No libnfc, no CGO,
no build step. Verified against PN532 v1.6 firmware on a CH340 adapter.
"""

from __future__ import annotations

import time
import serial

ACK = bytes([0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00])
NACK = bytes([0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00])
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
        self._rx = bytearray()

    # -- lifecycle -------------------------------------------------

    def _wake(self, settle: float = 0.08) -> None:
        """HSU wake-up: 0x55 0x55 then zeros, the sequence libnfc uses."""
        self.ser.write(b"\x55\x55" + b"\x00" * 14)
        time.sleep(settle)
        self.ser.reset_input_buffer()
        self._rx.clear()

    def _sam_configuration(self) -> None:
        """Leave low-vbat / make sure the chip is in normal mode (D4 14 01)."""
        self.call(b"\x14\x01", timeout=1.5)

    def _configure_retries(self) -> None:
        """Bound MxRtyPassiveActivation so polling returns instead of hanging.

        MxRtyATR=0xFF, MxRtyPSL=0x01, MxRtyPassiveActivation=0x02 (libnfc's
        value when it wants a finite poll; the firmware default is 0xFF).
        """
        self.call(b"\x32\x05\xFF\x01\x02", timeout=1.5)

    def open(self) -> tuple[int, int, int]:
        self.ser = serial.Serial(self.port, self.baud, timeout=0.05, write_timeout=1.0)
        try:
            # Some CH340 boards wire DTR/RTS to the PN532 reset line.
            self.ser.dtr = False
            self.ser.rts = False
        except Exception:
            pass
        self._rx.clear()
        try:
            # A previous process may have left the chip mid-command.
            self._abort_and_drain()
            last: Exception | None = None
            for attempt in range(3):
                self._wake(settle=0.08 + 0.1 * attempt)
                try:
                    self._sam_configuration()
                    self._configure_retries()
                    self.firmware = self.get_firmware()
                    return self.firmware
                except PN532Error as exc:
                    last = exc
                    self._abort_and_drain()
                    time.sleep(0.2)
            raise last or PN532Timeout("PN532 did not answer the initial handshake")
        except Exception:
            # A failed handshake must not keep COM3 open, otherwise every retry
            # fails with "access denied" until the process exits.
            self.close()
            raise

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

    def _abort_and_drain(self, settle: float = 0.05) -> None:
        """Send an ACK frame, which aborts any command the chip is still running."""
        if self.ser and self.ser.is_open:
            try:
                self.ser.write(ACK)
            except Exception:
                pass
        time.sleep(settle)
        if self.ser and self.ser.is_open:
            self.ser.reset_input_buffer()
        self._rx.clear()

    def _wait_ack(self, timeout: float) -> bool:
        """Wait for the chip's ACK (or NACK) to the command we just sent."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            idx = self._rx.find(ACK)
            if idx >= 0:
                del self._rx[:idx + len(ACK)]
                return True
            idx = self._rx.find(NACK)
            if idx >= 0:
                del self._rx[:idx + len(NACK)]
                return False
            waiting = self.ser.in_waiting
            if waiting:
                self._rx += self.ser.read(waiting)
            else:
                time.sleep(0.005)
        return False

    def _read_response(self, expected: int, timeout: float, sent: int) -> bytes:
        """Read until the frame whose command byte is expected (cmd + 1)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            while self._rx.startswith(ACK) or self._rx.startswith(NACK):
                del self._rx[:len(ACK)]
            payload, consumed = find_frame(self._rx)
            if payload is not None:
                del self._rx[:consumed]
                if payload[0] == CHIP and len(payload) >= 2:
                    if payload[1] == 0x7F:
                        code = payload[2] if len(payload) > 2 else 0xFF
                        raise PN532Error(
                            f"chip error 0x{code:02X} (command 0x{sent:02X})")
                    if payload[1] == expected:
                        return payload
                    continue  # late answer to an earlier command
            waiting = self.ser.in_waiting
            if waiting:
                self._rx += self.ser.read(waiting)
            else:
                time.sleep(0.005)
        raise PN532Timeout(f"no response to 0x{sent:02X} within {timeout:.1f}s")

    def call(self, cmd: bytes, timeout: float = 1.0) -> bytes:
        if not self.ser:
            raise PN532Error("port is not open")
        frame = build_frame(bytes([HOST]) + cmd)
        expected = (cmd[0] + 1) & 0xFF
        for _ in range(3):
            self.ser.write(frame)
            if self._wait_ack(0.15):
                return self._read_response(expected, timeout, cmd[0])
            # No ACK: the chip is probably still busy with an earlier command.
            self._abort_and_drain()
        raise PN532Timeout(f"no ACK from PN532 for command 0x{cmd[0]:02X}")

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
