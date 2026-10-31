"""MIFARE Classic layer on top of pn532.PN532.

Sector geometry, key scanning, full-card dump, and magic-card classification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pn532 import PN532, PN532Error

# Well-known factory / vendor keys. Ordered by hit rate.
DEFAULT_KEYS: list[bytes] = [bytes.fromhex(k) for k in (
    "FFFFFFFFFFFF",
    "A0A1A2A3A4A5",
    "D3F7D3F7D3F7",
    "000000000000",
    "B0B1B2B3B4B5",
    "AABBCCDDEEFF",
    "1A982C7E459A",
    "4D3A99C351DD",
    "714C5C886E97",
    "587EE5F9350A",
    "A0478CC39091",
    "533CB6C723F6",
    "8FD0A4F256E9",
    "0000014B5C31",
    "B578F38A5C61",
    "96A301BCE267",
    "16A8B2D3F5E1",
    "0F0F0F0F0F0F",
    "123456789ABC",
    "484558414341",
)]

KEY_A, KEY_B = b"\x60", b"\x61"


@dataclass
class Geometry:
    name: str
    sectors: list[int]  # blocks per sector

    @property
    def total_blocks(self) -> int:
        return sum(self.sectors)

    def first_block(self, sector: int) -> int:
        return sum(self.sectors[:sector])

    def trailer_block(self, sector: int) -> int:
        return self.first_block(sector) + self.sectors[sector] - 1

    def data_blocks(self, sector: int) -> range:
        return range(self.first_block(sector), self.trailer_block(sector))

    def sector_of(self, block: int) -> int:
        seen = 0
        for i, n in enumerate(self.sectors):
            if block < seen + n:
                return i
            seen += n
        raise ValueError(f"block {block} out of range")


GEOMETRIES = {
    0x08: Geometry("MIFARE Classic 1K", [4] * 16),
    0x18: Geometry("MIFARE Classic 4K", [4] * 32 + [16] * 8),
    0x09: Geometry("MIFARE Mini", [4] * 5),
}


@dataclass
class SectorKey:
    sector: int
    key_type: bytes | None = None
    key: bytes | None = None

    @property
    def known(self) -> bool:
        return self.key is not None

    @property
    def label(self) -> str:
        if not self.key:
            return "未识别"
        side = "A" if self.key_type == KEY_A else "B"
        return f"Key{side} {self.key.hex().upper()}"


@dataclass
class Card:
    uid: bytes
    atqa: bytes
    sak: int
    target: int
    geometry: Geometry | None
    type_name: str
    block0: bytes | None = None
    keys: list[SectorKey] = field(default_factory=list)


def geometry_for(sak: int) -> Geometry | None:
    return GEOMETRIES.get(sak)


def read_card(pn532: PN532) -> Card | None:
    info = pn532.list_passive()
    if not info:
        return None
    geo = geometry_for(info["sak"])
    name = geo.name if geo else f"SAK 0x{info['sak']:02X}"
    return Card(uid=info["uid"], atqa=info["atqa"], sak=info["sak"],
                target=info["target"], geometry=geo, type_name=name)


def try_key(pn532: PN532, card: Card, block: int, key: bytes,
            key_type: bytes) -> bool:
    try:
        return pn532.auth(card.target, block, key, key_type, card.uid)
    except PN532Error:
        return False


def scan_sector(pn532: PN532, card: Card, sector: int,
                keys: list[bytes]) -> SectorKey:
    if card.geometry is None:
        return SectorKey(sector)
    trailer = card.geometry.trailer_block(sector)
    for key in keys:
        if try_key(pn532, card, trailer, key, KEY_A):
            return SectorKey(sector, KEY_A, key)
    for key in keys:
        if try_key(pn532, card, trailer, key, KEY_B):
            return SectorKey(sector, KEY_B, key)
    return SectorKey(sector)


def scan_all(pn532: PN532, card: Card, keys: list[bytes] | None = None,
             progress=None) -> list[SectorKey]:
    keys = keys or DEFAULT_KEYS
    if card.geometry is None:
        return []
    found = []
    for sector in range(len(card.geometry.sectors)):
        sk = scan_sector(pn532, card, sector, keys)
        found.append(sk)
        if progress:
            progress(sk, sector + 1, len(card.geometry.sectors))
    card.keys = found
    return found


def dump_card(pn532: PN532, card: Card) -> bytes | None:
    """Read every block using the already-discovered keys. Missing sectors stay zero."""
    if card.geometry is None:
        return None
    geo = card.geometry
    out = bytearray(geo.total_blocks * 16)
    for sk in card.keys:
        if not sk.key:
            continue
        # Auth is per sector, so one successful auth covers all its blocks.
        if not try_key(pn532, card, geo.first_block(sk.sector), sk.key, sk.key_type):
            continue
        for block in list(geo.data_blocks(sk.sector)) + [geo.trailer_block(sk.sector)]:
            try:
                out[block * 16:(block + 1) * 16] = pn532.read_block(card.target, block)
            except PN532Error:
                continue
    return bytes(out)


def manufacturer_block(pn532: PN532, card: Card) -> bytes | None:
    """Read block 0 if we can authenticate sector 0."""
    sk = next((k for k in card.keys if k.sector == 0 and k.key), None)
    if sk is None:
        sk = scan_sector(pn532, card, 0, DEFAULT_KEYS)
    if not sk.key:
        return None
    if not try_key(pn532, card, 0, sk.key, sk.key_type):
        return None
    try:
        return pn532.read_block(card.target, 0)
    except PN532Error:
        return None


# -- magic-card classification ------------------------------------

FACTORY_PATTERNS = {
    b"bcdefghi": "克隆卡出厂数据",
    b"\x00\x00\x00\x00\x00\x00\x00\x00": "全零厂商段",
}


def gen1a_unlock(pn532: PN532, card: Card) -> bool:
    """Non-destructive Gen1A backdoor probe: 0x40 then 0x43.

    A genuine Gen1A answers 0x0A to both. The card must be re-selected
    afterwards; callers should re-issue list_passive.
    """
    try:
        status, data = pn532.communicate_thru(card.target, b"\x40", timeout=0.5)
        if status != 0x00 or not data or data[0] != 0x0A:
            return False
        status, data = pn532.communicate_thru(card.target, b"\x43", timeout=0.5)
        return status == 0x00 and bool(data) and data[0] == 0x0A
    except PN532Error:
        return False


@dataclass
class Classification:
    kind: str
    rewritable: str          # "多次" / "一次" / "不可写" / "未知"
    confidence: str          # "高" / "低"
    evidence: list[str]


def classify(pn532: PN532, card: Card, block0: bytes | None) -> Classification:
    evidence: list[str] = []
    factory = False
    if block0:
        mfg = block0[8:16]
        shown = mfg.decode("ascii") if all(32 <= b < 127 for b in mfg) else mfg.hex(" ").upper()
        evidence.append(f"厂商段 {shown}")
        for pat, note in FACTORY_PATTERNS.items():
            if pat in block0:
                factory = True
                evidence.append(f"出厂标识: {note}")

    if gen1a_unlock(pn532, card):
        evidence.append("0x40/0x43 有应答 → UID (Gen1A)")
        return Classification("UID (Gen1A)", "多次", "高", evidence)

    evidence.append("0x40 无应答 → 非 UID (Gen1A)")
    if factory:
        evidence.append("出厂厂商段,像未写入过的空卡")
    else:
        evidence.append("无出厂标识,可能是写过的克隆卡,也可能是原卡")
    evidence.append("CUID/FUID/UFUID 与原卡在读取层无法区分,能否写块 0 只能写入测试")

    return Classification("CUID/FUID/UFUID 或原卡", "待写入测试", "低", evidence)
