# -*- coding: utf-8 -*-
import json
import logging
import socket
import time
from base64 import b64decode, b64encode

from Crypto.Cipher import DES3
from Crypto.Hash import SHA256

_logger = logging.getLogger(__name__)


# -----------------------------
# Helpers: padding / key derivs
# -----------------------------
def _pad(data: bytes, block: int = 8) -> bytes:
    padlen = block - (len(data) % block)
    return data + bytes([padlen]) * padlen


def _unpad(data: bytes) -> bytes:
    padlen = data[-1]
    if padlen < 1 or padlen > 8:
        raise ValueError("Invalid padding")
    return data[:-padlen]


def _derive_2key_3des(password: str) -> bytes:
    """Derive a 24-byte (2-key) 3DES key from password via SHA256."""
    h = SHA256.new(password.encode("utf-8")).digest()
    k1k2 = h[:16]
    return k1k2 + k1k2[:8]  # K1||K2||K1 (24 bytes)


# -----------------------------
# Main client
# -----------------------------
class HDMClient:
    """
    HDM fiscal device client.

    - Native protocol header + 3DES-ECB (PKCS#7 pad) for most firmwares.
    - Handles ACK-only devices (no JSON body) by following up with get_receipt_info.
    - Centralized sequence management to ensure correct seq reuse.
    - Tolerant login: accepts session in multiple formats / field names, or ACK-only.
    - Simulator mode for testing without hardware.
    """

    def __init__(self, simulate: bool = False):
        self.simulate = simulate
        self.sock = None
        self.session_key: bytes | None = None
        self.seq: int = 0
        self.closed = False
        self._last_receipt = None

        # Protocol constants (from vendor docs)
        self._HDR_MAGIC = bytes.fromhex("D5 80 D4 B4 D5 84 00")
        self._PROTO_VER = 0x05

        # Function codes (override via config if firmware differs)
        self._FC = {
            "get_ops_deps": 0x01,
            "login": 0x02,
            "logout": 0x03,
            "print_receipt": 0x04,
            "print_last_copy": 0x05,
            "print_return_receipt": 0x06,
            "set_header_footer": 0x07,
            "set_logo": 0x08,
            "print_report": 0x09,
            "get_receipt_info": 0x0A,   # <— used after ACK-only print
            "cash_in_out": 0x0B,
            "get_datetime": 0x0C,
            "print_template": 0x0D,
            "sync": 0x0E,
            "get_payment_systems": 0x0F,
            "check_emark": 0x10,
        }

        self._last_hdr = b""

    # ------------
    # Housekeeping
    # ------------
    def is_closed(self) -> bool:
        return self.closed

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.closed = True

    # -----------------
    # Sequence handling
    # -----------------
    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    # --------------------------
    # Basic (legacy) JSON channel
    # --------------------------
    def _send(self, ip, port, login_key, payload: dict) -> dict:
        """
        Legacy/plain JSON channel used by some devices / simulator.
        Tries \n, no-term, and \r\n framed sends; tolerant to ACK-like replies.
        """
        if self.simulate:
            op = (payload or {}).get("op")
            if op == "login":
                self.session_key = b"FAKESESSIONKEY012345678901"[:24]
                return {"ok": True, "session": "sim-session"}
            if op == "print_receipt":
                s = self._next_seq()
                self._last_receipt = {
                    "ok": True,
                    "fiscal_number": f"AM-{int(time.time())}",
                    "verification_number": f"V-{s:06d}",
                    "rseq": s,
                    "crn": "CRN-123456",
                    "qr_base64": b64encode(f"QR:{s}".encode("utf-8")).decode("ascii"),
                }
                return dict(self._last_receipt)
            if op == "print_return_receipt":
                s = self._next_seq()
                self._last_receipt = {
                    "ok": True,
                    "fiscal_number": f"AMR-{int(time.time())}",
                    "verification_number": f"VR-{s:06d}",
                    "rseq": s,
                    "crn": "CRN-123456",
                    "qr_base64": b64encode(f"RETURN:{s}".encode("utf-8")).decode("ascii"),
                }
                return dict(self._last_receipt)
            if op == "cash_in_out":
                return {"ok": True}
            if op == "ping":
                return {"ok": True}
            if op in ("get_last_receipt", "fetch_last_receipt"):
                if self._last_receipt:
                    data = dict(self._last_receipt)
                    data["ok"] = True
                    return data
                return {"ok": False, "message": "No last receipt data in simulator"}
            return {"ok": False, "message": "Unsupported op in simulator"}

        def _try_exchange(terminator: bytes):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((ip, port))
            chunks = []
            try:
                data = json.dumps(payload).encode("utf-8")
                s.sendall(data + terminator)

                start = time.time()
                while True:
                    try:
                        buf = s.recv(4096)
                    except socket.timeout:
                        break
                    except ConnectionResetError:
                        if chunks:
                            break
                        raise
                    if not buf:
                        break
                    chunks.append(buf)
                    if b"\n" in buf:
                        break
                    if time.time() - start > 10:
                        break

                raw = b"".join(chunks)
                if not raw:
                    raise Exception("No response from HDM device (empty reply)")

                nl = raw.find(b"\n")
                if nl != -1:
                    raw = raw[:nl]

                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw.decode("latin-1", errors="ignore")

                text_stripped = text.strip()
                if text_stripped:
                    try:
                        return json.loads(text_stripped)
                    except json.JSONDecodeError:
                        start_idx = text_stripped.find("{")
                        end_idx = text_stripped.rfind("}")
                        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                            candidate = text_stripped[start_idx : end_idx + 1]
                            try:
                                return json.loads(candidate)
                            except Exception:
                                pass

                # Binary ACK-only
                op = (payload or {}).get("op")
                if b"\x06" in raw or (len(raw) <= 12 and any(raw)):
                    if op in ("login", "ping", "cash_in_out", "print_receipt", "print_return_receipt"):
                        return {"ok": True, "ack": True}

                preview = text_stripped[:200] if text_stripped else raw[:32].hex()
                _logger.error("Invalid response from HDM device: %s", preview)
                raise Exception(f"Invalid response from HDM device: {preview}")
            finally:
                try:
                    s.close()
                except Exception:
                    pass

        last_exc = None
        for term in (b"\n", b"", b"\r\n"):
            try:
                return _try_exchange(term)
            except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError, Exception) as e:
                last_exc = e
                continue
        if isinstance(last_exc, ConnectionResetError):
            raise Exception(
                "HDM connection was closed by the device. Verify protocol/terminator and credentials."
            )
        raise Exception(f"HDM communication failed: {last_exc}")

    # ----------------------------
    # Native protocol (3DES-ECB)
    # ----------------------------
    def _enc3des(self, key24: bytes, data: bytes) -> bytes:
        return DES3.new(key24, DES3.MODE_ECB).encrypt(_pad(data))

    def _dec3des(self, key24: bytes, data: bytes) -> bytes:
        return _unpad(DES3.new(key24, DES3.MODE_ECB).decrypt(data))

    def _recv_all(self, s: socket.socket, nbytes: int, timeout: float = 10.0) -> bytes:
        s.settimeout(timeout)
        chunks, total, start = [], 0, time.time()
        while total < nbytes:
            if time.time() - start > timeout:
                raise socket.timeout("HDM recv timeout")
            part = s.recv(nbytes - total)
            if not part:
                break
            chunks.append(part)
            total += len(part)
        return b"".join(chunks)

    def _send_proto(self, ip, port, func_code: int, body: dict, use_session_key: bool, login_key: bytes) -> dict:
        key = self.session_key if use_session_key else login_key
        if not key or len(key) != 24:
            raise Exception("Invalid or missing HDM encryption key")

        payload = dict(body or {})
        if "seq" not in payload:
            payload["seq"] = self._next_seq()
        used_seq = int(payload["seq"])

        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        enc = self._enc3des(key, raw)
        length = len(enc)

        header = bytearray()
        header += self._HDR_MAGIC
        header.append(self._PROTO_VER)
        header.append(func_code & 0xFF)
        header += bytes([(length >> 8) & 0xFF, length & 0xFF])

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(10)
            s.connect((ip, port))
            s.sendall(header + enc)

            rh = self._recv_all(s, 11, timeout=10)
            self._last_hdr = rh
            if len(rh) < 11:
                raise Exception("Short HDM response header")

            resp_len = (rh[9] << 8) | rh[10]
            body_enc = b""
            if resp_len:
                body_enc = self._recv_all(s, resp_len, timeout=10)

            if body_enc:
                try:
                    dec = self._dec3des(key, body_enc)
                    txt = dec.decode("utf-8", errors="ignore").strip()
                    if txt:
                        resp = json.loads(txt)
                        resp.setdefault("_used_seq", used_seq)
                        return resp
                except Exception as e:
                    _logger.error(
                        "HDM proto decrypt/parse failed (hdr=%s len=%s): %s",
                        rh[:16].hex(),
                        len(body_enc),
                        e,
                    )

            # No JSON payload => ACK success
            return {"ok": True, "ack": True, "_used_seq": used_seq}
        finally:
            try:
                s.close()
            except Exception:
                pass

    # ----------------------------
    # Diagnostics / connection test
    # ----------------------------
    def test_connection(self, config):
        """Open TCP then try native login + datetime, falling back to ping."""
        if self.simulate:
            key = _derive_2key_3des(config.hdm_password or "")
            started = time.time()
            resp = self._send(config.hdm_ip, config.hdm_port, key, {"op": "ping"})
            rtt_ms = int((time.time() - started) * 1000)
            info = {"simulate": True, "rtt_ms": rtt_ms}
            if isinstance(resp, dict):
                info.update(resp)
            return {"ok": bool(isinstance(resp, dict) and resp.get("ok")), "info": info}

        # bare TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(5)
            s.connect((config.hdm_ip, config.hdm_port))
        except socket.timeout:
            raise Exception("Connection timed out")
        finally:
            try:
                s.close()
            except Exception:
                pass

        key = _derive_2key_3des(config.hdm_password or "")
        started = time.time()
        try:
            info = {}
            # try native login + get_datetime
            try:
                fc_login = int(getattr(config, "hdm_fc_login", None) or self._FC["login"])
                fc_dt = int(getattr(config, "hdm_fc_get_datetime", None) or self._FC["get_datetime"])
                login_resp = self._send_proto(
                    config.hdm_ip,
                    config.hdm_port,
                    fc_login,
                    {
                        "password": config.hdm_password or "",
                        "cashier": int(getattr(config, "hdm_cashier_id", 0) or 0),
                        "pin": getattr(config, "hdm_cashier_pin", "") or "",
                    },
                    use_session_key=False,
                    login_key=key,
                )
                if isinstance(login_resp, dict) and login_resp.get("session"):
                    try:
                        self.session_key = b64decode(login_resp.get("session"))
                    except Exception:
                        self.session_key = None
                dt = self._send_proto(
                    config.hdm_ip, config.hdm_port, fc_dt, {}, use_session_key=True, login_key=key
                )
                info.update(
                    {"native_ok": True, "dt_ok": bool(getattr(dt, "get", lambda k: False)("ok")) if isinstance(dt, dict) else False}
                )
            except Exception:
                pass

            resp = self._send(config.hdm_ip, config.hdm_port, key, {"op": "ping"})
            rtt_ms = int((time.time() - started) * 1000)
            hdr_hex = None
            try:
                hdr_hex = getattr(self, "_last_hdr", b"")[:16].hex()
            except Exception:
                hdr_hex = None
            info = {"ip": config.hdm_ip, "port": config.hdm_port, "rtt_ms": rtt_ms, "last_hdr": hdr_hex}
            if isinstance(resp, dict):
                info.update(resp)
            return {"ok": bool(isinstance(resp, dict) and resp.get("ok")), "info": info}
        except Exception as e:
            rtt_ms = int((time.time() - started) * 1000)
            return {"ok": False, "info": {"ip": config.hdm_ip, "port": config.hdm_port, "rtt_ms": rtt_ms, "error": str(e)}}

    # ------------
    # Login logic
    # ------------
    def _normalize_session_key(self, sess) -> bytes:
        """Accept base64/hex/ascii, and 16- or 24-byte 3DES keys."""
        if isinstance(sess, (bytes, bytearray)):
            key = bytes(sess)
        else:
            s = str(sess).strip()
            key = None
            # base64
            try:
                key = b64decode(s, validate=True)
            except Exception:
                pass
            # hex
            if key is None:
                try:
                    key = bytes.fromhex(s)
                except Exception:
                    pass
            # ascii
            if key is None:
                key = s.encode("utf-8")

        if len(key) == 16:  # 2-key 3DES K1||K2 -> expand to K1||K2||K1
            key = key + key[:8]
        if len(key) != 24:
            raise Exception(f"Invalid session key length: {len(key)} (need 24)")
        return key

    def ensure_login(self, config):
        if self.session_key:
            return

        login_key = _derive_2key_3des(config.hdm_password or "")
        if self.simulate:
            resp = self._send(config.hdm_ip, config.hdm_port, login_key, {"op": "login"})
            if not isinstance(resp, dict) or not resp.get("ok"):
                raise Exception(resp.get("message", "Login failed"))
            self.session_key = b"DUMMYSESSION12345678901234"[:24]
            self.seq = 0
            return

        # Try configured function code first, then fallbacks
        candidates = []
        try:
            configured = int(getattr(config, "hdm_fc_login", None) or 0)
            if configured:
                candidates.append(configured)
        except Exception:
            pass
        # Try a broader range to discover actual login function code
        for fc in ([self._FC["login"]] + list(range(1, 21))):
            if fc not in candidates:
                candidates.append(fc)

        resp = None
        last_exc = None
        for fc_login in candidates:
            try:
                resp = self._send_proto(
                    config.hdm_ip,
                    config.hdm_port,
                    fc_login,
                    {
                        "password": config.hdm_password or "",
                        "cashier": int(getattr(config, "hdm_cashier_id", 0) or 0),
                        "pin": getattr(config, "hdm_cashier_pin", "") or "",
                    },
                    use_session_key=False,
                    login_key=login_key,
                )
                if isinstance(resp, dict):
                    break
            except Exception as e:
                last_exc = e
                continue

        if not isinstance(resp, dict):
            raise Exception(f"Login failed (invalid response). {last_exc or ''}")

        sess = (
            resp.get("session")
            or resp.get("sessionKey")
            or resp.get("session_key")
            or resp.get("sid")
            or resp.get("token")
        )
        if sess:
            self.session_key = self._normalize_session_key(sess)
            self.seq = 0
            return

        raise Exception(resp.get("message", "Login did not return a session key"))

    # -----------------------------
    # Receipt field normalization
    # -----------------------------
    def _looks_base64(self, s: str) -> bool:
        try:
            b64decode(s, validate=True)
            return True
        except Exception:
            return False

    def _extract_receipt_fields(self, d: dict) -> dict:
        def g(*keys):
            for k in keys:
                v = d.get(k)
                if v:
                    return v
            return None

        fiscal = g("fiscal", "fiscal_number", "fiscalNumber")
        ver = g("verificationNumber", "verification_number", "verificationNo", "verNumber")
        rseq = g("rseq", "seq", "receiptSeq", "receiptId")
        crn = g("crn", "CRN", "receiptNumber")
        qr = g("qr", "qr_text", "qrText", "qrData", "qr_base64")

        if isinstance(qr, bytes):
            qr = qr.decode("utf-8", errors="ignore")
        if qr and not (str(qr).strip().startswith("data:") or self._looks_base64(str(qr))):
            qr = b64encode(str(qr).encode("utf-8")).decode("ascii")

        return {
            "fiscal_number": fiscal,
            "verification_number": ver,
            "rseq": rseq,
            "crn": crn,
            "qr_base64": qr,
        }

    # -------------
    # Print receipt
    # -------------
    def print_receipt(self, config, order_payload: dict):
        login_key = _derive_2key_3des(config.hdm_password or "")
        if self.simulate:
            return self._send(
                config.hdm_ip, config.hdm_port, login_key, {"op": "print_receipt", "order": order_payload, "seq": self.seq + 1}
            )

        # Build minimal body (adapt if your firmware requires lines/taxes/etc.)
        try:
            paid_total = float(order_payload.get("amount_total") or 0.0)
        except Exception:
            paid_total = 0.0

        dep = getattr(config, "hdm_department_id", None)
        try:
            dep = int(dep) if dep and str(dep).isdigit() else None
        except Exception:
            dep = None

        body = {
            # seq auto-added in _send_proto
            "paidAmount": paid_total,
            "paidAmountCard": 0.0,
            "partialAmount": 0.0,
            "prePaymentAmount": 0.0,
            "mode": 1,
            "useExtPOS": False,
            "partnerTin": None,
        }
        if dep is not None:
            body["dep"] = dep

        try:
            fc_print = int(getattr(config, "hdm_fc_print", None) or self._FC["print_receipt"])
            resp = self._send_proto(
                config.hdm_ip, config.hdm_port, fc_print, body, use_session_key=True, login_key=login_key
            )
        except Exception as e:
            return {"ok": False, "message": str(e)}

        # If response came with fields, normalize and return
        if isinstance(resp, dict) and not resp.get("ack"):
            mapped = self._extract_receipt_fields(resp)
            if any(mapped.values()):
                # if device returned rseq, sync our seq
                if mapped["rseq"]:
                    try:
                        self.seq = int(mapped["rseq"])
                    except Exception:
                        pass
                return {"ok": True, **mapped}

        # ACK-only path: fetch info for the exact seq that was used
        used_seq = int(resp.get("_used_seq") or self.seq)
        try:
            fc_info = int(getattr(config, "hdm_fc_get_receipt_info", None) or self._FC["get_receipt_info"])
            details = self._send_proto(
                config.hdm_ip, config.hdm_port, fc_info, {"seq": used_seq}, use_session_key=True, login_key=login_key
            )
            if isinstance(details, dict):
                mapped = self._extract_receipt_fields(details)
                if any(mapped.values()):
                    if mapped["rseq"]:
                        try:
                            self.seq = int(mapped["rseq"])
                        except Exception:
                            pass
                    return {"ok": True, **mapped}

            # Some firmwares expose last_copy with data; try same seq (not seq+2)
            fc_last = int(getattr(config, "hdm_fc_last_copy", None) or self._FC["print_last_copy"])
            last = self._send_proto(
                config.hdm_ip, config.hdm_port, fc_last, {"seq": used_seq}, use_session_key=True, login_key=login_key
            )
            if isinstance(last, dict):
                mapped = self._extract_receipt_fields(last)
                if any(mapped.values()):
                    if mapped["rseq"]:
                        try:
                            self.seq = int(mapped["rseq"])
                        except Exception:
                            pass
                    return {"ok": True, **mapped}

            return {"ok": True, "details": details}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    # --------------------
    # Print return receipt
    # --------------------
    def print_return_receipt(self, config, original_order, return_payload: dict):
        login_key = _derive_2key_3des(config.hdm_password or "")
        if self.simulate:
            return self._send(
                config.hdm_ip, config.hdm_port, login_key, {"op": "print_return_receipt", "seq": self.seq + 1}
            )

        body = {
            # seq auto-added
            "receiptId": str(getattr(original_order, "hdm_rseq", "") or ""),
            "crn": getattr(original_order, "hdm_crn", "") or "",
        }

        try:
            fc_ret = int(getattr(config, "hdm_fc_print_return", None) or self._FC["print_return_receipt"])
            resp = self._send_proto(
                config.hdm_ip, config.hdm_port, fc_ret, body, use_session_key=True, login_key=login_key
            )
            if isinstance(resp, dict) and not resp.get("ack"):
                mapped = self._extract_receipt_fields(resp)
                if any(mapped.values()):
                    if mapped["rseq"]:
                        try:
                            self.seq = int(mapped["rseq"])
                        except Exception:
                            pass
                    return {"ok": True, **mapped}
        except Exception:
            pass

        # Fallbacks
        try:
            fc_last = int(getattr(config, "hdm_fc_last_copy", None) or self._FC["print_last_copy"])
            details = self._send_proto(
                config.hdm_ip, config.hdm_port, fc_last, {"seq": self.seq}, use_session_key=True, login_key=login_key
            )
            if isinstance(details, dict):
                mapped = self._extract_receipt_fields(details)
                if any(mapped.values()):
                    return {"ok": True, **mapped}
        except Exception:
            pass

        return {"ok": True}

    # -------------
    # Cash in/out
    # -------------
    def cash_in_out(self, config, amount, is_cashin, description):
        login_key = _derive_2key_3des(config.hdm_password or "")
        if self.simulate:
            return self._send(config.hdm_ip, config.hdm_port, login_key, {"op": "cash_in_out"})

        body = {
            # seq auto-added
            "amount": float(amount),
            "isCashin": bool(is_cashin),
            "description": description or "",
            "cashierid": int(getattr(config, "hdm_cashier_id", 0) or 0),
        }
        fc_cash = int(getattr(config, "hdm_fc_cash_in_out", None) or self._FC["cash_in_out"])
        resp = self._send_proto(
            config.hdm_ip, config.hdm_port, fc_cash, body, use_session_key=True, login_key=login_key
        )
        return {"ok": True} if isinstance(resp, dict) else {"ok": True}
