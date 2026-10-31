"""Read a card end-to-end: identify, scan keys, dump, classify."""

import sys
import time

import mifare
from pn532 import PN532


def main() -> int:
    port = sys.argv[1] if len(sys.argv) > 1 else "COM3"
    t0 = time.time()
    with PN532(port) as nfc:
        ic, ver, rev = nfc.firmware
        print(f"reader: PN532 v{ver}.{rev} on {port}")

        card = mifare.read_card(nfc)
        if not card:
            print("no card on the reader")
            return 1
        print(f"card  : {card.type_name}  UID={card.uid.hex().upper()}  "
              f"ATQA={card.atqa.hex(' ').upper()}  SAK=0x{card.sak:02X}")

        if card.geometry is None:
            print("unsupported card geometry")
            return 1

        def progress(sk, done, total):
            print(f"  [{done:2d}/{total}] sector {sk.sector:2d}  {sk.label}")

        print("keys  : scanning")
        keys = mifare.scan_all(nfc, card, progress=progress)
        known = sum(1 for k in keys if k.known)
        print(f"keys  : {known}/{len(keys)} sectors")

        block0 = mifare.manufacturer_block(nfc, card)
        if block0:
            print(f"block0: {block0.hex(' ').upper()}")

        cls = mifare.classify(nfc, card, block0)
        print(f"type  : {cls.kind} | 可写性={cls.rewritable} | 置信度={cls.confidence}")
        for line in cls.evidence:
            print(f"        - {line}")

        # The Gen1A backdoor probe leaves the card de-selected; pick it up again.
        info = nfc.list_passive()
        if info:
            card.target = info["target"]
        dump = mifare.dump_card(nfc, card)
        if dump:
            readable = sum(1 for b in range(len(dump) // 16)
                           if dump[b * 16:(b + 1) * 16] != b"\x00" * 16)
            print(f"dump  : {len(dump)} bytes, {readable} non-zero blocks")
            for b in range(4):
                print(f"  b{b:<2d} {dump[b*16:(b+1)*16].hex(' ').upper()}")
        print(f"done  : {time.time() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
