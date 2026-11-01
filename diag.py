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
