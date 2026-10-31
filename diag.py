"""Reader diagnostics: force the RF field on and poll for cards."""

import sys
import time

from pn532 import PN532, PN532Error


def main() -> int:
    port = sys.argv[1] if len(sys.argv) > 1 else "COM3"
    with PN532(port) as nfc:
        print("firmware:", nfc.firmware)
        try:
            print("rf on  :", nfc.call(b"\x32\x01\x01").hex(" "))
        except PN532Error as exc:
            print("rf on  :", exc)
        try:
            print("release:", nfc.call(b"\x52").hex(" "))
        except PN532Error as exc:
            print("release:", exc)

        seen = 0
        for i in range(25):
            try:
                r = nfc.call(b"\x4A\x01\x00", timeout=1.0)
                if len(r) > 2 and r[2] > 0:
                    seen += 1
                    print(f"poll {i:02d}: card {r.hex(' ')}")
                else:
                    print(f"poll {i:02d}: none ({r.hex(' ')})")
            except PN532Error as exc:
                print(f"poll {i:02d}: error {exc}")
            time.sleep(0.2)
        print("hits:", seen)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
