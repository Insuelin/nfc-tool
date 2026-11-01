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

"""Card writing: block 0 for magic cards, full-card restore, and write tests.

Every function here changes the card. Callers must confirm with the user first.
"""

from __future__ import annotations

from dataclasses import dataclass

import mifare
from mifare import Card, Geometry, KEY_A, KEY_B
from pn532 import PN532, PN532Error


@dataclass
class WriteReport:
    sector: int
    block: int
    ok: bool
    note: str = ""
    skipped: bool = False  # no key for this sector, so nothing was attempted


def _auth(pn532: PN532, card: Card, sector: int, keys: dict[int, mifare.SectorKey]) -> bool:
    sk = keys.get(sector)
    if not sk or not sk.key:
        return False
    geo = card.geometry
    assert geo is not None
    return mifare.try_key(pn532, card, geo.first_block(sector), sk.key, sk.key_type)


def reselect(pn532: PN532, card: Card) -> bool:
    info = pn532.list_passive()
    if not info:
        return False
    card.target = info["target"]
    return True


def unlock_gen1a(pn532: PN532, card: Card) -> bool:
    """Gen1A backdoor: 0x40 then 0x43, both answered with 0x0A."""
    try:
        status, data = pn532.communicate_thru(card.target, b"\x40", timeout=0.5)
        if status != 0x00 or not data or data[0] != 0x0A:
            return False
        status, data = pn532.communicate_thru(card.target, b"\x43", timeout=0.5)
        return status == 0x00 and bool(data) and data[0] == 0x0A
    except PN532Error:
        return False


def write_block0_gen1a(pn532: PN532, card: Card, data: bytes) -> tuple[bool, str]:
    if len(data) != 16:
        return False, "block 0 must be 16 bytes"
    if not unlock_gen1a(pn532, card):
        return False, "0x40/0x43 后门无应答"
    try:
        status, resp = pn532.communicate_thru(card.target, b"\xA0\x00" + data, timeout=1.0)
    except PN532Error as exc:
        return False, f"写块失败: {exc}"
    if status != 0x00:
        return False, f"写块状态 0x{status:02X}"
    return True, "已改写(Gen1A 后门)"


def write_block0_gen2(pn532: PN532, card: Card,
                      keys: dict[int, mifare.SectorKey], data: bytes) -> tuple[bool, str]:
    if len(data) != 16:
        return False, "block 0 must be 16 bytes"
    if not _auth(pn532, card, 0, keys):
        return False, "扇区 0 认证失败"
    try:
        ok = pn532.write_block(card.target, 0, data)
    except PN532Error as exc:
        return False, f"写块失败: {exc}"
    return (True, "已改写(普通认证写入)") if ok else (False, "卡片拒绝写入块 0")


def verify_block(pn532: PN532, card: Card, block: int,
                 keys: dict[int, mifare.SectorKey], expected: bytes) -> bool:
    geo = card.geometry
    assert geo is not None
    sector = geo.sector_of(block)
    if not _auth(pn532, card, sector, keys):
        return False
    try:
        return pn532.read_block(card.target, block) == expected
    except PN532Error:
        return False


def verify_trailer(pn532: PN532, card: Card, sector: int, trailer: bytes) -> bool:
    """Read a sector trailer back using the keys that were just written."""
    geo = card.geometry
    assert geo is not None
    block = geo.trailer_block(sector)
    for key_type, key in ((KEY_A, trailer[0:6]), (KEY_B, trailer[10:16])):
        if key == b"\x00" * 6:
            continue
        if not mifare.try_key(pn532, card, block, key, key_type):
            continue
        try:
            return pn532.read_block(card.target, block) == trailer
        except PN532Error:
            return False
    return False


def check_access_bits(trailer: bytes) -> str | None:
    """Return an error string when the trailer access bits are inconsistent.

    Bytes 6-8 store the three access conditions C1/C2/C3 together with their
    complements:

        byte 6 = ~C2 (high nibble) | ~C1 (low nibble)
        byte 7 =  C1 (high nibble) | ~C3 (low nibble)
        byte 8 =  C3 (high nibble) |  C2 (low nibble)

    A normal factory trailer (FF 07 80 69) decodes to C1=C2=0, C3=1000.
    """
    if len(trailer) != 16:
        return "trailer 长度不是 16"
    b6, b7, b8 = trailer[6], trailer[7], trailer[8]
    if (b6 >> 4) != ((b8 & 0x0F) ^ 0x0F):
        return "访问位: C2 与反码不一致"
    if (b6 & 0x0F) != ((b7 >> 4) ^ 0x0F):
        return "访问位: C1 与反码不一致"
    if (b7 & 0x0F) != ((b8 >> 4) ^ 0x0F):
        return "访问位: C3 与反码不一致"
    return None


def write_card(pn532: PN532, card: Card, dump: bytes,
               keys: list[mifare.SectorKey], *,
               write_uid: bool, magic: str | None,
               write_trailers: bool = False,
               progress=None) -> list[WriteReport]:
    """Restore a dump onto the card.

    magic is "gen1a", "gen2" or None. Block 0 is only touched when write_uid
    is set and the card is known to be magic. Sector trailers (which hold
    Key A/B and the access bits) are skipped unless write_trailers is set:
    writing them would re-key the target card and can lock a sector whose
    access bits disagree with the hardware.
    """
    geo = card.geometry
    if geo is None:
        raise ValueError("不支持的卡型")
    if len(dump) != geo.total_blocks * 16:
        raise ValueError(f"dump 长度 {len(dump)} 与卡容量 {geo.total_blocks*16} 不符")

    # Never write onto a card the user did not confirm.
    info = pn532.list_passive()
    if not info:
        raise RuntimeError("写入前找不到卡片,请把目标卡放回读卡器")
    if info["uid"] != card.uid:
        raise RuntimeError(
            f"现在放的不是刚才确认的那张卡:当前 UID {info['uid'].hex().upper()},"
            f"确认的是 {card.uid.hex().upper()}")
    card.target = info["target"]

    by_sector = {k.sector: k for k in keys}
    reports: list[WriteReport] = []

    if write_uid and magic:
        block0 = dump[0:16]
        if magic == "gen1a":
            ok, note = write_block0_gen1a(pn532, card, block0)
        else:
            ok, note = write_block0_gen2(pn532, card, by_sector, block0)
        if ok:
            # The UID just changed; authentication frames must carry the new one,
            # otherwise every later auth fails.
            if len(card.uid) == 4:
                card.uid = block0[0:4]
            # A second identical write tells us whether the card locks after one
            # (FUID / locked UFUID) or accepts repeated writes (CUID / Gen1A).
            if magic == "gen1a":
                reselect(pn532, card)
                ok2, _ = write_block0_gen1a(pn532, card, block0)
            else:
                ok2, _ = write_block0_gen2(pn532, card, by_sector, block0)
            note += ",可反复写" if ok2 else ",卡已锁定,只能写这一次"
        reports.append(WriteReport(0, 0, ok, note))
        if progress:
            progress(reports[-1])
        reselect(pn532, card)

    for sector, size in enumerate(geo.sectors):
        sk = by_sector.get(sector)
        if not sk or not sk.key:
            for block in list(geo.data_blocks(sector)) + [geo.trailer_block(sector)]:
                reports.append(WriteReport(sector, block, False, "密钥未识别,已跳过",
                                           skipped=True))
            continue
        if not _auth(pn532, card, sector, by_sector):
            for block in list(geo.data_blocks(sector)) + [geo.trailer_block(sector)]:
                reports.append(WriteReport(sector, block, False, "认证失败,已跳过"))
            continue

        trailer_block = geo.trailer_block(sector)
        blocks = list(geo.data_blocks(sector))
        if write_trailers:
            trailer = dump[trailer_block * 16:(trailer_block + 1) * 16]
            problem = check_access_bits(trailer)
            if problem:
                for block in [*geo.data_blocks(sector), trailer_block]:
                    reports.append(WriteReport(sector, block, False,
                                               f"扇区未写:{problem}", skipped=True))
                continue
            # Trailer goes last so a failure cannot lock the sector mid-write.
            blocks.append(trailer_block)
        else:
            reports.append(WriteReport(sector, trailer_block, False,
                                       "尾块未写(保留目标卡密钥)", skipped=True))

        for block in blocks:
            if block == 0 and write_uid and magic:
                continue  # already handled
            data = dump[block * 16:(block + 1) * 16]
            try:
                ok = pn532.write_block(card.target, block, data)
            except PN532Error as exc:
                reports.append(WriteReport(sector, block, False, str(exc)))
                if progress:
                    progress(reports[-1])
                rest = blocks[blocks.index(block) + 1:]
                for skipped_block in rest:
                    reports.append(WriteReport(sector, skipped_block, False,
                                               "前一块失败,未执行", skipped=True))
                break
            note = ""
            if ok and write_trailers and block == trailer_block:
                # The trailer just re-keyed the sector, so verify with the keys
                # that were written instead of the ones we authenticated with.
                if not verify_trailer(pn532, card, sector, data):
                    ok, note = False, "尾块写入后新密钥回读失败"
            elif ok and not verify_block(pn532, card, block, by_sector, data):
                ok, note = False, "写入后回读不一致"
            reports.append(WriteReport(sector, block, ok, note))
            if progress:
                progress(reports[-1])
    return reports


def writability_test(pn532: PN532, card: Card,
                     keys: list[mifare.SectorKey]) -> tuple[str, str]:
    """Probe whether block 0 is writable and how many times.

    WARNING: on an FUID/OTP card this consumes the single available write.
    """
    if card.geometry is None:
        return "未知", "不支持的卡型"
    by_sector = {k.sector: k for k in keys}
    sk = by_sector.get(0)
    if not sk or not sk.key:
        return "未知", "扇区 0 密钥未知"

    if not _auth(pn532, card, 0, by_sector):
        return "未知", "扇区 0 认证失败"
    try:
        current = pn532.read_block(card.target, 0)
    except PN532Error as exc:
        return "未知", f"读块 0 失败: {exc}"

    if unlock_gen1a(pn532, card):
        return "多次", "Gen1A 后门可用,可反复写块 0"

    ok1, note1 = write_block0_gen2(pn532, card, by_sector, current)
    if not ok1:
        return "不可写", f"块 0 写入被拒绝: {note1}"

    reselect(pn532, card)
    ok2, note2 = write_block0_gen2(pn532, card, by_sector, current)
    if ok2:
        return "多次", "连续两次写入均成功"
    return "一次", f"首次写入成功,第二次失败: {note2}"
