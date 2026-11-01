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

"""Local web front-end for the PN532 tool.

Run:  python app.py
Then open http://127.0.0.1:8770
"""

from __future__ import annotations

import functools
import json
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

import clone
import engines
import mifare
from pn532 import PN532, PN532Error

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"

DEFAULT_PORT = "COM3"
# Built from tools/src by tools/build.sh; see README.
DEFAULT_ENGINE_DIR = str(ROOT / "tools" / "bin")


def device_op(fn):
    """Hold the device lock for one phone-book operation, never blocking a request."""
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self.device_lock(blocking=False):
            return fn(self, *args, **kwargs)
    return wrapper


class App:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.nfc: PN532 | None = None
        self.card: mifare.Card | None = None
        self.keys: list[mifare.SectorKey] = []
        self.keys_uid: bytes | None = None
        self.dump: bytes | None = None
        self.port = DEFAULT_PORT
        self.engine_dir = DEFAULT_ENGINE_DIR
        self.jobs: dict[str, dict] = {}
        self.busy = False
        # Polled by the page while a long read is in flight.
        self.progress = {"stage": "idle", "done": 0, "total": 0}

    # -- device ----------------------------------------------------

    @contextmanager
    def device_lock(self, blocking: bool = False):
        if not self.lock.acquire(blocking=blocking):
            raise RuntimeError("读卡器忙,上一个操作还没结束")
        try:
            yield
        finally:
            self.lock.release()

    @property
    def device(self) -> str:
        return f"pn532_uart:{self.port}:115200"

    def connect(self, port: str | None = None) -> dict:
        with self.device_lock(blocking=False):
            if port:
                self.port = port
            if self.nfc:
                self.nfc.close()
                self.nfc = None
                self.card = None
                self.keys = []
                self.keys_uid = None
            nfc = PN532(self.port)
            ic, ver, rev = nfc.open()
            self.nfc = nfc
            return {"ok": True, "firmware": f"v{ver}.{rev}", "port": self.port}

    def disconnect(self) -> dict:
        with self.device_lock(blocking=False):
            if self.nfc:
                self.nfc.close()
            self.nfc = None
            self.card = None
            self.keys = []
            self.keys_uid = None
            return {"ok": True}

    def require_device(self) -> PN532:
        if not self.nfc:
            raise RuntimeError("尚未连接读卡器")
        return self.nfc

    @device_op
    def read_card(self) -> dict:
        nfc = self.require_device()
        card = None
        for _ in range(4):
            try:
                card = mifare.read_card(nfc)
            except PN532Error:
                card = None
            if card:
                break
            time.sleep(0.12)
        if not card:
            self.card = None
            raise RuntimeError(
                "没有选中卡片(已重试 4 次)。请确认卡片贴正、靠近读卡器天线;"
                "并确认它是 13.56 MHz 的 ISO/IEC 14443A 卡(MIFARE Classic 等)——"
                "125 kHz 的 ID 卡、ISO 15693 卡、UHF 标签都不在支持范围;"
                "若换卡后仍然读不到,这张卡可能已经损坏(线圈断裂或芯片失效)")
        self.card = card
        block0 = mifare.manufacturer_block(nfc, card)
        if block0:
            card.block0 = block0

        verdict = None
        try:
            result = mifare.classify(nfc, card, block0)
            verdict = {"kind": result.kind, "rewritable": result.rewritable,
                       "confidence": result.confidence, "evidence": result.evidence}
            # The Gen1A probe deselects the card; bring it back for later calls.
            clone.reselect(nfc, card)
        except PN532Error:
            verdict = None

        return {
            "uid": card.uid.hex().upper(),
            "atqa": card.atqa.hex(" ").upper(),
            "sak": f"0x{card.sak:02X}",
            "type": card.type_name,
            "block0": block0.hex(" ").upper() if block0 else "",
            "verdict": verdict,
        }

    @device_op
    def read_full(self) -> dict:
        """One click: identify, classify, scan keys and dump the whole card."""
        self.progress.update(stage="identify", done=0, total=0)
        try:
            card = self.read_card()
            nfc = self.require_device()
            assert self.card is not None

            def on_key(sk, done, total):
                self.progress.update(stage="keys", done=done, total=total)

            self.keys = mifare.scan_all(nfc, self.card, progress=on_key)
            self.keys_uid = self.card.uid
            keys = [{"sector": k.sector, "known": k.known, "label": k.label,
                     "key": k.key.hex().upper() if k.key else ""} for k in self.keys]
            self.progress.update(stage="dump", done=0, total=0)
            self.dump = mifare.dump_card(nfc, self.card)
            return {
                "card": card,
                "keys": keys,
                "dump": self.dump.hex().upper() if self.dump else "",
                "size": len(self.dump) if self.dump else 0,
            }
        finally:
            self.progress.update(stage="idle", done=0, total=0)

    @device_op
    def scan_keys(self) -> dict:
        nfc = self.require_device()
        if not self.card:
            self.read_card()
        assert self.card is not None

        def on_key(sk, done, total):
            self.progress.update(stage="keys", done=done, total=total)

        try:
            self.keys = mifare.scan_all(nfc, self.card, progress=on_key)
            self.keys_uid = self.card.uid
        finally:
            self.progress.update(stage="idle", done=0, total=0)
        return {"keys": [
            {"sector": k.sector, "known": k.known, "label": k.label,
             "key": k.key.hex().upper() if k.key else ""}
            for k in self.keys
        ]}

    @device_op
    def read_dump(self) -> dict:
        nfc = self.require_device()
        if not self.card:
            self.read_card()
        assert self.card is not None
        if not self.keys:
            self.scan_keys()
        self.dump = mifare.dump_card(nfc, self.card)
        return {"dump": self.dump.hex().upper() if self.dump else "",
                "size": len(self.dump) if self.dump else 0}

    @device_op
    def writability(self) -> dict:
        nfc = self.require_device()
        if not self.card:
            self.read_card()
        assert self.card is not None
        if not self.keys:
            self.scan_keys()
        label, note = clone.writability_test(nfc, self.card, self.keys)
        clone.reselect(nfc, self.card)
        return {"result": label, "note": note}

    @device_op
    def classify(self) -> dict:
        nfc = self.require_device()
        if not self.card:
            self.read_card()
        assert self.card is not None
        block0 = self.card.block0 or mifare.manufacturer_block(nfc, self.card)
        result = mifare.classify(nfc, self.card, block0)
        # The backdoor probe leaves the card deselected.
        clone.reselect(nfc, self.card)
        return {"kind": result.kind, "rewritable": result.rewritable,
                "confidence": result.confidence, "evidence": result.evidence}


APP = App()


class Handler(BaseHTTPRequestHandler):
    server_version = "nfc-tool"

    def log_message(self, fmt, *args):
        pass

    # -- helpers ---------------------------------------------------

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length) or b"{}")

    # -- routing ---------------------------------------------------

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            if "?" in self.path:
                # Drop any query string so the address bar stays clean.
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8")
            return
        if path.startswith("/web/"):
            name = path[len("/web/"):]
            target = (WEB / name).resolve()
            if not str(target).startswith(str(WEB.resolve())) or not target.is_file():
                self._send(404, b"not found", "text/plain")
                return
            ctype = {"css": "text/css; text/css", "js": "application/javascript"}.get(
                target.suffix.lstrip("."), "application/octet-stream")
            self._send(200, target.read_bytes(), ctype)
            return
        if path == "/api/status":
            self._json({
                "connected": APP.nfc is not None,
                "port": APP.port,
                "firmware": "v{}.{}".format(*APP.nfc.firmware[1:]) if APP.nfc and APP.nfc.firmware else None,
                "card": (APP.card.uid.hex().upper() if APP.card else None),
                "sectors_known": sum(1 for k in APP.keys if k.known) if APP.keys else 0,
                "sectors_total": len(APP.keys) if APP.keys else 0,
                "dump_size": len(APP.dump) if APP.dump else 0,
                "engine_dir": APP.engine_dir,
            })
            return
        if path == "/api/progress":
            self._json(APP.progress)
            return
        if path.startswith("/api/job/"):
            job = APP.jobs.get(path.rsplit("/", 1)[-1])
            if not job:
                self._json({"error": "job not found"}, 404)
                return
            self._json(job)
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self):
        path = self.path.split("?")[0]
        try:
            body = self._body()
        except Exception as exc:
            self._json({"error": f"bad json: {exc}"}, 400)
            return

        try:
            if path == "/api/connect":
                self._json(APP.connect(body.get("port")))
            elif path == "/api/disconnect":
                self._json(APP.disconnect())
            elif path == "/api/read":
                self._json({"card": APP.read_card()})
            elif path == "/api/read_full":
                self._json(APP.read_full())
            elif path == "/api/scan":
                self._json(APP.scan_keys())
            elif path == "/api/dump":
                self._json(APP.read_dump())
            elif path == "/api/classify":
                self._json(APP.classify())
            elif path == "/api/writability":
                self._json(APP.writability())
            elif path == "/api/crack":
                self._json(self.start_crack(body))
            elif path == "/api/clone":
                self._json(self.start_clone(body))
            elif path == "/api/shutdown":
                self._json({"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                self._json({"error": "unknown endpoint"}, 404)
        except (PN532Error, RuntimeError, ValueError, OSError) as exc:
            self._json({"error": str(exc)}, 500)

    # -- long jobs -------------------------------------------------

    def _new_job(self, kind: str) -> tuple[str, dict]:
        job_id = uuid.uuid4().hex[:12]
        job = {"id": job_id, "kind": kind, "state": "running", "logs": [],
               "result": None, "started": time.time(), "finished": None}
        APP.jobs[job_id] = job
        return job_id, job

    def _log(self, job: dict, line: str):
        job["logs"].append(line)
        del job["logs"][:-400]

    def start_crack(self, body: dict) -> dict:
        if APP.busy:
            return {"error": "已有任务在运行"}
        engine = body.get("engine", "mfoc")
        job_id, job = self._new_job(f"crack:{engine}")
        threading.Thread(target=self._run_crack, args=(job, engine), daemon=True).start()
        return {"job": job_id}

    def _run_crack(self, job: dict, engine_name: str):
        APP.lock.acquire()
        APP.busy = True
        try:
            out = engines.scratch_dir() / "recovered.mfd"
            if not APP.nfc:
                raise RuntimeError("尚未连接读卡器")
            if (engine_name == "mfcuk" and APP.card and APP.keys
                    and APP.keys_uid == APP.card.uid
                    and all(k.known for k in APP.keys)):
                raise RuntimeError(
                    "这张卡所有扇区的密钥都已经识别,不需要 darkside。"
                    "直接读卡或改用 mfoc 导出即可")
            known = [k.key for k in APP.keys if k.key]
            APP.disconnect()  # external tools need the port exclusively
            self._log(job, f"device released, starting {engine_name}")

            mapping = {"mfoc": engines.Mfoc, "mfcuk": engines.Mfcuk,
                       "hardnested": engines.Hardnested}
            engine = mapping[engine_name](Path(APP.engine_dir), APP.device)

            def on_line(line: str):
                self._log(job, line)

            if isinstance(engine, engines.Mfoc):
                code, text = engine.crack(out, known, probes=20, timeout=600, on_line=on_line)
            elif isinstance(engine, engines.Hardnested):
                code, text = engine.crack(out, known, timeout=1800, on_line=on_line)
            else:
                code, text = engine.darkside(out, 0, timeout=1200, on_line=on_line)

            keys = [k.hex().upper() for k in engines.found_keys(text)]
            ok = out.is_file() and out.stat().st_size > 0
            job["result"] = {
                "exit": code, "dump_size": out.stat().st_size if ok else 0,
                "keys": keys, "ok": ok,
            }
            self._log(job, "done" if ok else "no dump produced")
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            job["result"] = {"ok": False, "error": str(exc)}
            self._log(job, f"error: {exc}")
        finally:
            try:
                if APP.nfc is None:
                    APP.connect(APP.port)
                    self._log(job, "device re-opened")
                    if APP.card:
                        APP.read_card()
            except Exception as exc:  # noqa: BLE001
                self._log(job, f"re-open failed: {exc}")
            job["state"] = "done"
            job["finished"] = time.time()
            APP.busy = False
            APP.lock.release()

    def start_clone(self, body: dict) -> dict:
        if APP.busy:
            return {"error": "已有任务在运行"}
        job_id, job = self._new_job("clone")
        threading.Thread(target=self._run_clone, args=(job, body), daemon=True).start()
        return {"job": job_id}

    def _run_clone(self, job: dict, body: dict):
        APP.lock.acquire()
        APP.busy = True
        try:
            dump_hex = body.get("dump") or (APP.dump.hex() if APP.dump else "")
            if not dump_hex:
                raise RuntimeError("没有可写入的数据,请先读卡")
            dump = bytes.fromhex(dump_hex)
            nfc = APP.require_device()
            if not APP.card:
                APP.read_card()
            assert APP.card is not None
            if not APP.keys or APP.keys_uid != APP.card.uid:
                self._log(job, "目标卡与已有密钥不匹配,重新识别目标卡密钥")
                APP.scan_keys()
                self._log(job, f"目标卡密钥: {sum(1 for k in APP.keys if k.known)}/"
                               f"{len(APP.keys)} 扇区")

            if not any(k.known for k in APP.keys):
                raise RuntimeError("这张卡没有识别出任何密钥,先破解再写")

            magic = body.get("magic") or None
            write_uid = bool(body.get("write_uid"))
            write_trailers = bool(body.get("write_trailers"))
            self._log(job, f"写入目标卡 {APP.card.uid.hex().upper()}"
                           f",块 0 {'写' if write_uid else '不写'}"
                           f",扇区尾块 {'写(会改密钥)' if write_trailers else '不写'}")

            def progress(rep):
                self._log(job, f"sector {rep.sector:2d} block {rep.block:2d} "
                                f"{'ok' if rep.ok else 'FAIL'} {rep.note}".strip())

            reports = clone.write_card(
                nfc, APP.card, dump, APP.keys,
                write_uid=write_uid, magic=magic,
                write_trailers=write_trailers, progress=progress)
            ok = sum(1 for r in reports if r.ok)
            skipped = sum(1 for r in reports if r.skipped)
            failed = len(reports) - ok - skipped
            reasons: dict[str, int] = {}
            for r in reports:
                if not r.ok and not r.skipped:
                    key = r.note or "未说明原因"
                    reasons[key] = reasons.get(key, 0) + 1
            block0 = next((r for r in reports if r.block == 0 and r.sector == 0), None)
            job["result"] = {"ok": failed == 0, "written": ok, "skipped": skipped,
                             "failed": failed, "total": len(reports),
                             "reasons": reasons,
                             "target_uid": APP.card.uid.hex().upper(),
                             "keys": [{"sector": k.sector, "known": k.known,
                                       "label": k.label,
                                       "key": k.key.hex().upper() if k.key else ""}
                                      for k in APP.keys],
                             "block0": block0.note if block0 else None,
                             "block0_ok": bool(block0 and block0.ok)}
            self._log(job, f"结果:成功 {ok} 块,失败 {failed} 块,跳过 {skipped} 块")
            for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
                self._log(job, f"  失败原因 {n} 块:{reason}")
            if block0:
                self._log(job, f"block0: {block0.note}")
        except Exception as exc:  # noqa: BLE001
            job["result"] = {"ok": False, "error": str(exc)}
            self._log(job, f"error: {exc}")
        finally:
            job["state"] = "done"
            job["finished"] = time.time()
            APP.busy = False
            APP.lock.release()


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8770), Handler)
    print("nfc-tool: http://127.0.0.1:8770")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
