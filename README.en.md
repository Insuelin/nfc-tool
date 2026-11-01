# nfc-tool

[中文](README.md) | English

A local PN532 card workstation. Python speaks the PN532 HSU serial protocol directly, so reading a card does not require libnfc; a browser page drives it on `127.0.0.1`. Windows only, personal use.

## Supported readers

- PN532 module in HSU/UART mode (tested over a CH340 USB-serial adapter, v1.6 firmware)
- 115200 8N1, COM3 by default
- ACR122U / PCSC are not supported, and neither are the PN532 I2C or SPI wirings

## Supported cards

| Card | SAK | Blocks | Read | Write |
|---|---:|---:|---|---|
| MIFARE Classic 1K | 0x08 | 64 | with known keys | yes |
| MIFARE Classic 4K | 0x18 | 256 | with known keys | yes |
| MIFARE Mini | 0x09 | 20 | with known keys | yes |
| Other ISO/IEC 14443A cards | other | — | UID/ATQA/SAK only | no |

Not supported: 125 kHz ID cards, ISO 15693, UHF, storage operations on DESFire / NTAG / Ultralight, NFC-B/F/V, card emulation and sniffing.

## Magic cards

| Card | How block 0 is rewritten | Rewrites |
|---|---|---|
| UID (Gen1A) | `0x40` / `0x43` backdoor | unlimited |
| CUID (Gen2) | normal authenticated write | unlimited |
| FUID | normal authenticated write | once, then permanently locked |
| UFUID | normal authenticated write | unlimited until locked; this tool has no lock/unlock command |
| Genuine card | not writable | — |

Only Gen1A can be identified without side effects (`0x40`/`0x43` answer). CUID, FUID, UFUID and genuine cards look identical at the read layer; the only way to tell them apart is to try writing block 0, and on an FUID that test uses up its single write.

## Features

- Connect/disconnect, read the firmware version
- Card read: UID, ATQA, SAK, card type, block 0, magic-card classification, whole card in one go
- Key scan: 20 common factory/vendor keys, Key A first, then Key B
- Full dump: sectors without keys are left blank (all zero)
- Full write-back: sectors without keys are skipped, trailers written last, every block read back and verified
- Block 0 write: backdoor for Gen1A, authenticated write for CUID/FUID/UFUID, followed by an automatic check of whether the card can be rewritten
- Cracking: drives the external mfoc (nested), mfcuk (darkside) and mfoc-hardnested (hardnested)
- Source / target card slots, each with its own keys and data view
- Save/load `.mfd`, hex and ASCII side by side
- Command line: `inspect_card.py` (read a whole card), `diag.py` (force the RF field on and poll for cards)

## Requirements

- Python 3.10+ (developed on 3.14)
- `pyserial`
- External cracking programs: `mfoc.exe`, `mfcuk.exe`, `mfoc-hardnested.exe` and `libnfc.dll`, expected in `tools/bin` and built from the sources in `tools/src` (none of these binaries are committed)

Cracking sets `LIBNFC_DEVICE=pn532_uart:COM3:115200` automatically; while it runs, the external program owns the reader.

## Usage

```
pip install pyserial
python app.py
```

Open <http://127.0.0.1:8770>, pick the serial port, connect, then read a card.

Command line:

```
python inspect_card.py COM3
python diag.py COM3
```

## Known limitations

- ISO/IEC 14443A 106 kbps only. Card type comes from the SAK alone, so a MIFARE Plus or compatible card reporting 0x08/0x18 is treated as Classic without verifying that authentication works.
- Only the 20 built-in keys; no custom key dictionary.
- Sectors without keys are all zero in the dump, and are skipped when writing back.
- Writing block 0 on a non-Gen1A card needs the sector 0 key.
- Sectors with inconsistent access bits are skipped entirely.
- After writing a trailer (with new keys), the read-back check still uses the old keys and may falsely report a mismatch. Trust the card contents in that case.
- Cracking takes exclusive use of the serial port, so the page cannot read cards while it runs; the external program directory is fixed at `tools/bin` and the baud rate at 115200.
- The page only listens on `127.0.0.1` with no authentication. Do not expose it to the internet.

## License

The code in this project is **GPL-3.0**, see [LICENSE](LICENSE). GPLv3 was chosen because the package is meant to ship alongside the GPL programs mfoc / mfcuk / mfoc-hardnested, and one license keeps that simple. Third-party programs and their licenses are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Disclaimer

Use it only on cards you own or are authorized to test. Do not use it on access cards, transit cards, payment cards or anyone else's card without permission. You are responsible for what you do with the cracking tools.
