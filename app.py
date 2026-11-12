"""
app.py — Phantom
SIP dialer with accounts, live audio, and P1 Bot batch calling.
"""

import json
import os
import queue
import random
import socket
import sqlite3
import struct
import sys
import threading
import time
from functools import wraps
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import (
    Flask, render_template_string, request, jsonify,
    Response, session, redirect,
)
from flask_sock import Sock
from werkzeug.security import generate_password_hash, check_password_hash

import math
from lead_caller_sip import (
    generate_tts, mp3_to_ulaw, normalize_number, do_call, do_bridge_call,
    do_direct_call, get_local_ip, SIPCall, build_rtp_packet, FRAME_SIZE,
)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "ph4nt0m-d3v-s3cr3t")
sock = Sock(app)


# ── database ──────────────────────────────────────────────────

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phantom.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    c = get_db()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
        pw_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS user_settings (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        data TEXT NOT NULL DEFAULT '{}'
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS call_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        number TEXT NOT NULL,
        direction TEXT NOT NULL DEFAULT 'outbound',
        status TEXT NOT NULL DEFAULT 'unknown',
        duration INTEGER DEFAULT 0,
        source TEXT NOT NULL DEFAULT 'dialer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    c.commit()
    c.close()


init_db()


# ── auth ──────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


# ── live call (dialer) ────────────────────────────────────────

live_call = None
live_call_lock = threading.Lock()

# ── persistent SIP registration ──────────────────────────────

_registrar = None
_registrar_lock = threading.Lock()


class SIPRegistrar:
    """Background SIP registration keepalive so the server shows us as reachable."""

    def __init__(self, cfg):
        self.cfg = cfg
        self._stop = threading.Event()
        self._thread = None
        self.status = "offline"  # offline | registered | failed
        self.status_msg = "not tested"

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.status = "offline"
        self.status_msg = "disconnected"

    def _loop(self):
        while not self._stop.is_set():
            try:
                local_ip = get_local_ip()
                sip = SIPCall(
                    self.cfg["server"], self.cfg["port"],
                    self.cfg["user"], self.cfg["password"],
                    self.cfg["caller_id"], local_ip,
                    self.cfg.get("sip_port", 5080),
                )
                ok = sip.register()
                if ok:
                    self.status = "registered"
                    self.status_msg = "connected"
                    # keep socket alive to answer OPTIONS qualify checks
                    self._keepalive(sip)
                else:
                    self.status = "failed"
                    self.status_msg = "registration failed"
            except Exception as e:
                self.status = "failed"
                self.status_msg = str(e)[:60]
            if self._stop.wait(timeout=30):
                break

    def _keepalive(self, sip):
        """Sit on the socket answering OPTIONS, re-register every 120s."""
        last_reg = time.time()
        while not self._stop.is_set():
            try:
                sip._drain_and_handle(seconds=5.0)
            except Exception:
                pass
            if time.time() - last_reg > 120:
                try:
                    ok = sip.register()
                    if ok:
                        self.status = "registered"
                        self.status_msg = "connected"
                        last_reg = time.time()
                    else:
                        self.status = "failed"
                        self.status_msg = "re-registration failed"
                        return  # outer loop will retry from scratch
                except Exception as e:
                    self.status = "failed"
                    self.status_msg = str(e)[:60]
                    return
            if self._stop.is_set():
                break


def _start_registrar(cfg):
    global _registrar
    with _registrar_lock:
        if _registrar:
            _registrar.stop()
        _registrar = SIPRegistrar(cfg)
        _registrar.start()


class LiveCall:
    def __init__(self, cfg, number, user_id=None):
        self.cfg = cfg
        self.number = number
        self.user_id = user_id
        self._connected_at = None
        self.active = False
        self.connected = False
        self.stop_event = threading.Event()
        self.sip = None
        self.ctx = None
        self.rtp_sock = None
        self.remote_rtp = None
        self.rtp_seq = random.randint(0, 0xFFFF)
        self.rtp_ts = 0
        self.rtp_ssrc = random.getrandbits(32)
        self._send_lock = threading.Lock()
        self.ws_clients = []

    def start(self):
        self.active = True
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        local_ip = get_local_ip()
        rtp_port = random.randint(10000, 20000) & 0xFFFE
        call_sip_port = random.randint(20000, 30000)

        try:
            self.sip = SIPCall(
                self.cfg["server"], self.cfg["port"],
                self.cfg["user"], self.cfg["password"],
                self.cfg["caller_id"], local_ip,
                call_sip_port,
            )
        except Exception as e:
            self._notify({"type": "error", "text": str(e)})
            self.active = False
            return

        self._notify({"type": "status", "text": "registering..."})
        if not self.sip.register():
            self._notify({"type": "error", "text": "registration failed"})
            self.active = False
            return

        self.rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rtp_sock.bind((local_ip, rtp_port))
        self.rtp_sock.settimeout(0.5)

        self._notify({"type": "status", "text": "ringing..."})
        code, ctx, remote_rtp = self.sip.invite(
            self.number, rtp_port, self.rtp_sock
        )

        if code != 200 or not remote_rtp:
            self._notify({"type": "error", "text": f"call failed ({code})"})
            self.active = False
            try:
                self.rtp_sock.close()
            except OSError:
                pass
            self._log_history("failed", 0)
            return

        self.ctx = ctx
        self.remote_rtp = remote_rtp
        self.connected = True
        self._connected_at = time.time()
        self._last_rtp = time.time()
        self._notify({"type": "connected"})

        threading.Thread(target=self._rtp_recv, daemon=True).start()
        threading.Thread(target=self._sip_monitor, daemon=True).start()

        self.stop_event.wait()

        try:
            self.sip.send_bye(ctx)
        except Exception:
            pass

        dur = int(time.time() - self._connected_at) if self._connected_at else 0
        self.connected = False
        self.active = False
        try:
            self.rtp_sock.close()
        except OSError:
            pass
        self._log_history("answered", dur)
        self._notify({"type": "ended"})

    def _rtp_recv(self):
        buf = bytearray()
        last_flush = time.monotonic()
        while not self.stop_event.is_set():
            try:
                data, _ = self.rtp_sock.recvfrom(4096)
            except socket.timeout:
                if buf:
                    self._flush_audio(bytes(buf))
                    buf.clear()
                    last_flush = time.monotonic()
                if time.time() - self._last_rtp > 15:
                    self.stop_event.set()
                    break
                continue
            except OSError:
                break
            self._last_rtp = time.time()
            if len(data) < 12:
                continue
            pt = data[1] & 0x7F
            if pt == 101:
                continue
            buf.extend(data[12:])
            now = time.monotonic()
            if now - last_flush >= 0.02 or len(buf) >= 160:
                self._flush_audio(bytes(buf))
                buf.clear()
                last_flush = now
        if buf:
            self._flush_audio(bytes(buf))

    def _sip_monitor(self):
        while not self.stop_event.is_set():
            try:
                data, _ = self.sip.sock.recvfrom(4096)
                text = data.decode("utf-8", errors="replace")
                if text.startswith("BYE "):
                    try:
                        via = call_id = from_h = to_h = cseq = ""
                        for line in text.split("\r\n"):
                            if line.startswith("Via:"):
                                via = line
                            elif line.startswith("Call-ID:"):
                                call_id = line
                            elif line.startswith("From:"):
                                from_h = line
                            elif line.startswith("To:"):
                                to_h = line
                            elif line.startswith("CSeq:"):
                                cseq = line
                        resp = "SIP/2.0 200 OK\r\n"
                        resp += via + "\r\n" if via else ""
                        resp += call_id + "\r\n" if call_id else ""
                        resp += from_h + "\r\n" if from_h else ""
                        resp += to_h + "\r\n" if to_h else ""
                        resp += cseq + "\r\n" if cseq else ""
                        resp += "Content-Length: 0\r\n\r\n"
                        self.sip.sock.sendto(resp.encode(), (self.cfg["server"], self.cfg["port"]))
                    except Exception:
                        pass
                    self.stop_event.set()
                    break
            except (socket.timeout, OSError):
                pass
            time.sleep(0.1)

    def _flush_audio(self, payload):
        for ws in list(self.ws_clients):
            try:
                ws.send(payload)
            except Exception:
                try:
                    self.ws_clients.remove(ws)
                except ValueError:
                    pass

    def send_audio(self, ulaw_bytes):
        if not self.connected or not self.remote_rtp:
            return
        with self._send_lock:
            offset = 0
            while offset < len(ulaw_bytes):
                chunk = ulaw_bytes[offset:offset + FRAME_SIZE]
                if len(chunk) < FRAME_SIZE:
                    chunk += bytes([0xFF] * (FRAME_SIZE - len(chunk)))
                pkt = build_rtp_packet(
                    chunk, self.rtp_seq, self.rtp_ts, self.rtp_ssrc, 0
                )
                try:
                    self.rtp_sock.sendto(pkt, self.remote_rtp)
                except OSError:
                    break
                self.rtp_seq = (self.rtp_seq + 1) & 0xFFFF
                self.rtp_ts += FRAME_SIZE
                offset += FRAME_SIZE

    def send_dtmf(self, digit):
        if not self.connected or not self.remote_rtp:
            return
        dtmf_map = {"0":0,"1":1,"2":2,"3":3,"4":4,"5":5,"6":6,"7":7,"8":8,"9":9,"*":10,"#":11}
        event = dtmf_map.get(digit)
        if event is None:
            return
        with self._send_lock:
            ts = self.rtp_ts
            dur_step = 160
            for i in range(5):
                payload = struct.pack("!BBH", event, 0, dur_step * (i + 1))
                pkt = build_rtp_packet(payload, self.rtp_seq, ts, self.rtp_ssrc, 101)
                try:
                    self.rtp_sock.sendto(pkt, self.remote_rtp)
                except OSError:
                    break
                self.rtp_seq = (self.rtp_seq + 1) & 0xFFFF
                time.sleep(0.02)
            for _ in range(3):
                payload = struct.pack("!BBH", event, 0x80, dur_step * 6)
                pkt = build_rtp_packet(payload, self.rtp_seq, ts, self.rtp_ssrc, 101)
                try:
                    self.rtp_sock.sendto(pkt, self.remote_rtp)
                except OSError:
                    break
                self.rtp_seq = (self.rtp_seq + 1) & 0xFFFF
                time.sleep(0.02)
            self.rtp_ts += dur_step * 6

    def hangup(self):
        self.stop_event.set()

    def _notify(self, msg):
        text = json.dumps(msg)
        for ws in list(self.ws_clients):
            try:
                ws.send(text)
            except Exception:
                try:
                    self.ws_clients.remove(ws)
                except ValueError:
                    pass

    def _log_history(self, status, duration):
        if not self.user_id:
            return
        try:
            c = get_db()
            c.execute(
                "INSERT INTO call_history(user_id, number, status, duration, source) "
                "VALUES(?,?,?,?,?)",
                (self.user_id, self.number, status, duration, "dialer"),
            )
            c.commit()
            c.close()
        except Exception:
            pass


# ── P1 Bot (batch calling) ────────────────────────────────────

call_log = []
call_log_lock = threading.Lock()
event_subscribers = []
event_sub_lock = threading.Lock()
MAX_LOG = 200
p1_ws_clients = []
p1_ws_lock = threading.Lock()
p1_stop_event = threading.Event()
p1_batch_state = {"running": False, "rows": [], "status_msg": "ready"}

# agent state for direct call
agent_ws_client = None
agent_ws_lock = threading.Lock()
agent_mic_q = queue.Queue()
agent_clocked_in = False


def _linear_to_ulaw(sample):
    BIAS = 0x84
    MAX = 0x7FFF
    sign = 0
    if sample < 0:
        sign = 0x80
        sample = -sample
    if sample > MAX:
        sample = MAX
    sample += BIAS
    exp_lut = [0,0,1,1,2,2,2,2,3,3,3,3,3,3,3,3,
               4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
               5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
               5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
               6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
               6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
               6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
               6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
               7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
               7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
               7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
               7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
               7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
               7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
               7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
               7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7]
    exp = exp_lut[(sample >> 4) & 0xFF]
    mantissa = (sample >> (exp + 3)) & 0x0F
    return ~(sign | (exp << 4) | mantissa) & 0xFF


def generate_hold_music(duration_sec=30):
    """Generate pleasant bank-style hold music as ulaw bytes."""
    sr = 8000
    melody = [
        (392, 0.4), (440, 0.4), (494, 0.4), (523, 0.6),
        (494, 0.4), (440, 0.4), (392, 0.8), (0, 0.3),
        (330, 0.4), (392, 0.4), (440, 0.4), (494, 0.6),
        (440, 0.4), (392, 0.4), (330, 0.8), (0, 0.3),
        (523, 0.4), (494, 0.4), (440, 0.4), (392, 0.6),
        (440, 0.4), (494, 0.4), (523, 0.8), (0, 0.5),
    ]
    loop_dur = sum(d for _, d in melody)
    repeats = int(duration_sec / loop_dur) + 1
    out = bytearray()
    for _ in range(repeats):
        for freq, dur in melody:
            ns = int(sr * dur)
            fade = int(sr * 0.015)
            for i in range(ns):
                if freq == 0:
                    s = 0
                else:
                    env = 1.0
                    if i < fade:
                        env = i / fade
                    elif i > ns - fade:
                        env = (ns - i) / fade
                    s = int(env * 6000 * math.sin(2 * math.pi * freq * i / sr))
                out.append(_linear_to_ulaw(s))
    return bytes(out[:sr * duration_sec])


def push_event(evt, data):
    msg = f"event: {evt}\ndata: {json.dumps(data)}\n\n"
    with event_sub_lock:
        dead = []
        for q in event_subscribers:
            try:
                q.put_nowait(msg)
            except Exception:
                dead.append(q)
        for q in dead:
            event_subscribers.remove(q)
    if evt == "call_start":
        p1_batch_state["running"] = True
        row = {"number": data["number"], "status": "calling",
               "dtmf": "", "ts": data.get("ts", "")}
        found = False
        for r in p1_batch_state["rows"]:
            if r["number"] == data["number"] and r["status"] == "pending":
                r.update(row); found = True; break
        if not found:
            p1_batch_state["rows"].append(row)
    elif evt == "call_end":
        for r in p1_batch_state["rows"]:
            if r["number"] == data["number"] and r["status"] == "calling":
                r["status"] = data.get("status", "failed")
                r["dtmf"] = data.get("dtmf", "")
                r["ts"] = data.get("ts", "")
                break
    elif evt == "batch_done":
        p1_batch_state["running"] = False
    elif evt == "p1_status":
        p1_batch_state["status_msg"] = data.get("msg", "ready")


def _p1_audio_send(data):
    with p1_ws_lock:
        dead = []
        for ws in p1_ws_clients:
            try:
                ws.send(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            try:
                p1_ws_clients.remove(ws)
            except ValueError:
                pass

def _p1_audio_in(data):
    _p1_audio_send(b'\x02' + data)

def _p1_audio_out(data):
    _p1_audio_send(b'\x01' + data)


def run_calls(numbers, cfg, message, response_msg, voice, pause, user_id=None):
    p1_stop_event.clear()
    p1_batch_state["running"] = True
    p1_batch_state["status_msg"] = "starting..."
    p1_batch_state["rows"] = [{"number": n, "status": "pending", "dtmf": "", "ts": ""} for n in numbers]
    try:
        local_ip = get_local_ip()
        ulaw = b""
        if message:
            p = Path("_tts.mp3")
            generate_tts(message, voice, p)
            ulaw = mp3_to_ulaw(p)
            p.unlink(missing_ok=True)
        resp_ulaw = b""
        if response_msg:
            p = Path("_tts_r.mp3")
            generate_tts(response_msg, voice, p)
            resp_ulaw = mp3_to_ulaw(p)
            p.unlink(missing_ok=True)

        push_event("p1_status", {"msg": f"starting batch — {len(numbers)} numbers"})

        for i, num in enumerate(numbers):
            if p1_stop_event.is_set():
                push_event("batch_done", {"n": len(numbers), "stopped": True})
                return
            entry = {
                "number": num, "status": "calling", "dtmf": "",
                "ts": time.strftime("%H:%M:%S"), "i": i + 1, "n": len(numbers),
            }
            push_event("call_start", entry)
            push_event("p1_status", {"msg": f"dialing {num} ({i+1}/{len(numbers)})..."})
            result = do_call(
                cfg["server"], cfg["port"], cfg["user"], cfg["password"],
                cfg["caller_id"], num, ulaw, pause, local_ip,
                random.randint(20000, 30000),
                retries=cfg.get("retries", 3),
                retry_delay=cfg.get("retry_delay", 3),
                response_ulaw=resp_ulaw or None,
                audio_cb=_p1_audio_in,
                audio_out_cb=_p1_audio_out,
                stop_event=p1_stop_event,
            )
            if result == "answered":
                entry["status"] = "answered"
                push_event("p1_status", {"msg": f"{num} — answered"})
            elif result == "screening":
                entry["status"] = "screening"
                push_event("p1_status", {"msg": f"{num} — automated screening detected"})
            elif result == "disconnected":
                entry["status"] = "disconnected"
                push_event("p1_status", {"msg": f"{num} — call disconnected"})
            elif result == "busy":
                entry["status"] = "failed"
                push_event("p1_status", {"msg": f"{num} — busy"})
            elif result == "declined":
                entry["status"] = "failed"
                push_event("p1_status", {"msg": f"{num} — declined"})
            elif result == "unavailable":
                entry["status"] = "failed"
                push_event("p1_status", {"msg": f"{num} — unavailable"})
            elif result == "cancelled":
                entry["status"] = "failed"
                push_event("p1_status", {"msg": f"{num} — cancelled"})
            else:
                entry["status"] = "failed"
                push_event("p1_status", {"msg": f"{num} — no answer"})
            with call_log_lock:
                call_log.append(entry)
                if len(call_log) > MAX_LOG:
                    call_log.pop(0)
            push_event("call_end", entry)
            if user_id:
                try:
                    c = get_db()
                    c.execute(
                        "INSERT INTO call_history(user_id, number, status, source) "
                        "VALUES(?,?,?,?)",
                        (user_id, num, entry["status"], "p1bot"),
                    )
                    c.commit()
                    c.close()
                except Exception:
                    pass
            if i < len(numbers) - 1:
                d = cfg.get("delay", 3)
                remaining = len(numbers) - i - 1
                push_event("p1_status", {"msg": f"waiting {d}s... ({remaining} remaining)"})
                for _ in range(int(d * 10)):
                    if p1_stop_event.is_set():
                        break
                    time.sleep(0.1)
        push_event("batch_done", {"n": len(numbers)})
        push_event("p1_status", {"msg": f"batch complete — {len(numbers)} numbers processed"})
    except Exception as e:
        import traceback; traceback.print_exc()
        push_event("p1_status", {"msg": f"error: {str(e)[:40]}"})
        push_event("batch_done", {"n": len(numbers), "error": str(e)})


def run_direct_calls(numbers, cfg, message, voice, pause, trigger_digit,
                     hangup_digit, hold_play, hold_tts_msg, user_id=None):
    """Direct Call: play TTS, wait for DTMF trigger, bridge to clocked-in agent."""
    p1_stop_event.clear()
    p1_batch_state["running"] = True
    p1_batch_state["status_msg"] = "starting..."
    p1_batch_state["rows"] = [{"number": n, "status": "pending", "dtmf": "", "ts": ""} for n in numbers]
    try:
        local_ip = get_local_ip()

        ulaw = b""
        if message:
            push_event("p1_status", {"msg": "generating tts..."})
            p = Path("_tts_dc.mp3")
            generate_tts(message, voice, p)
            ulaw = mp3_to_ulaw(p)
            p.unlink(missing_ok=True)

        hold_ulaw = None
        if hold_play == "music":
            push_event("p1_status", {"msg": "loading hold music..."})
            for hf in ["hold_music.mp3", "hold_music.wav"]:
                hp = Path(hf)
                if hp.exists():
                    hold_ulaw = mp3_to_ulaw(hp)
                    break
            if not hold_ulaw:
                push_event("p1_status", {"msg": "no hold music file found"})
        elif hold_play == "tts" and hold_tts_msg:
            push_event("p1_status", {"msg": "generating hold tts..."})
            p = Path("_tts_hold.mp3")
            generate_tts(hold_tts_msg, voice, p)
            hold_ulaw = mp3_to_ulaw(p)
            p.unlink(missing_ok=True)

        use_agent = agent_clocked_in and agent_ws_client is not None
        if not use_agent:
            push_event("p1_status", {"msg": "no agent clocked in — cannot start direct call"})
            push_event("batch_done", {"n": len(numbers), "stopped": True})
            return

        push_event("p1_status", {"msg": f"starting — {len(numbers)} numbers, agent clocked in"})

        for i, num in enumerate(numbers):
            if p1_stop_event.is_set():
                push_event("batch_done", {"n": len(numbers), "stopped": True})
                return
            entry = {
                "number": num, "status": "calling", "dtmf": "",
                "ts": time.strftime("%H:%M:%S"), "i": i + 1, "n": len(numbers),
            }
            push_event("call_start", entry)
            push_event("p1_status", {"msg": f"dialing {num} ({i+1}/{len(numbers)})..."})

            while not agent_mic_q.empty():
                agent_mic_q.get_nowait()

            result = do_direct_call(
                cfg["server"], cfg["port"], cfg["user"], cfg["password"],
                cfg["caller_id"], num, ulaw, int(pause), local_ip,
                random.randint(20000, 30000),
                trigger_digit=trigger_digit,
                hangup_digit=hangup_digit if hangup_digit != "none" else None,
                hold_ulaw=hold_ulaw,
                audio_out_cb=_agent_audio_out,
                audio_in_q=agent_mic_q,
                audio_monitor_cb=_p1_audio_in,
                audio_cb=_p1_audio_in,
                audio_out_monitor_cb=_p1_audio_out,
                retries=cfg.get("retries", 3),
                retry_delay=cfg.get("retry_delay", 3),
                stop_event=p1_stop_event,
                bridge_cb=_notify_agent_bridge,
            )

            if result == "bridged":
                entry["status"] = "answered"
                entry["dtmf"] = trigger_digit
                push_event("p1_status", {"msg": f"{num} — bridged to agent"})
            elif result == "hangup":
                entry["status"] = "answered"
                entry["dtmf"] = hangup_digit or ""
                push_event("p1_status", {"msg": f"{num} — caller hung up (pressed {hangup_digit})"})
            elif result == "answered":
                entry["status"] = "answered"
                push_event("p1_status", {"msg": f"{num} — answered, no transfer"})
            elif result == "disconnected":
                entry["status"] = "disconnected"
                push_event("p1_status", {"msg": f"{num} — call disconnected"})
            elif result == "screening":
                entry["status"] = "screening"
                push_event("p1_status", {"msg": f"{num} — automated screening detected"})
            elif result == "busy":
                entry["status"] = "failed"
                push_event("p1_status", {"msg": f"{num} — busy"})
            elif result == "declined":
                entry["status"] = "failed"
                push_event("p1_status", {"msg": f"{num} — declined"})
            elif result == "unavailable":
                entry["status"] = "failed"
                push_event("p1_status", {"msg": f"{num} — unavailable"})
            elif result == "cancelled":
                entry["status"] = "failed"
                push_event("p1_status", {"msg": f"{num} — cancelled"})
            else:
                entry["status"] = "failed"
                push_event("p1_status", {"msg": f"{num} — no answer"})

            with call_log_lock:
                call_log.append(entry)
                if len(call_log) > MAX_LOG:
                    call_log.pop(0)
            push_event("call_end", entry)
            if user_id:
                try:
                    c = get_db()
                    c.execute(
                        "INSERT INTO call_history(user_id, number, status, source) "
                        "VALUES(?,?,?,?)",
                        (user_id, num, entry["status"], "p1bot"),
                    )
                    c.commit()
                    c.close()
                except Exception:
                    pass
            if i < len(numbers) - 1:
                d = cfg.get("delay", 3)
                remaining = len(numbers) - i - 1
                push_event("p1_status", {"msg": f"waiting {d}s... ({remaining} remaining)"})
                for _ in range(int(d * 10)):
                    if p1_stop_event.is_set():
                        break
                    time.sleep(0.1)
        push_event("batch_done", {"n": len(numbers)})
        push_event("p1_status", {"msg": f"batch complete — {len(numbers)} numbers processed"})
    except Exception as e:
        import traceback; traceback.print_exc()
        push_event("p1_status", {"msg": f"error: {str(e)[:40]}"})
        push_event("batch_done", {"n": len(numbers), "error": str(e)})


# ── helpers ───────────────────────────────────────────────────

def _build_sip_cfg(d):
    return {
        "server": d.get("server") or os.getenv("SIP_SERVER", "sip.suii.us"),
        "port": int(d.get("port") or os.getenv("SIP_PORT", "5060")),
        "user": d.get("sip_user") or os.getenv("SIP_USER", ""),
        "password": d.get("sip_pass") or os.getenv("SIP_PASSWORD", ""),
        "caller_id": d.get("caller_id") or os.getenv("SIP_CALLER_ID", "18002893557"),
        "sip_port": int(d.get("sip_port") or os.getenv("SIP_LOCAL_PORT", "5080")),
        "retries": int(d.get("retries", 3)),
        "retry_delay": float(d.get("retry_delay", 3)),
        "delay": float(d.get("delay", 3)),
    }


# ── auth routes ───────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "uid" in session:
        return redirect("/")
    err = None
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        c = get_db()
        row = c.execute(
            "SELECT * FROM users WHERE username=?", (u,)
        ).fetchone()
        c.close()
        if row and check_password_hash(row["pw_hash"], p):
            session["uid"] = row["id"]
            session["uname"] = row["username"]
            return redirect("/")
        err = "invalid credentials"
    return render_template_string(AUTH_HTML, error=err, mode="login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "uid" in session:
        return redirect("/")
    err = None
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        p2 = request.form.get("confirm", "")
        if not u or not p:
            err = "all fields required"
        elif len(u) < 3:
            err = "username too short"
        elif len(p) < 6:
            err = "6+ character password"
        elif p != p2:
            err = "passwords don't match"
        else:
            c = get_db()
            try:
                c.execute(
                    "INSERT INTO users(username, pw_hash) VALUES(?,?)",
                    (u, generate_password_hash(p)),
                )
                c.commit()
                row = c.execute(
                    "SELECT * FROM users WHERE username=?", (u,)
                ).fetchone()
                session["uid"] = row["id"]
                session["uname"] = row["username"]
                c.close()
                return redirect("/")
            except sqlite3.IntegrityError:
                c.close()
                err = "username taken"
    return render_template_string(AUTH_HTML, error=err, mode="register")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ── app routes ────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template_string(DASH_HTML, uname=session.get("uname", ""))


@app.route("/api/dial", methods=["POST"])
@login_required
def api_dial():
    global live_call
    with live_call_lock:
        if live_call and live_call.active:
            return jsonify(error="call in progress"), 400
    d = request.json or {}
    num = normalize_number(d.get("number", "").strip())
    if not num:
        return jsonify(error="invalid number"), 400
    cfg = _build_sip_cfg(d)
    if not cfg["user"] or not cfg["password"]:
        return jsonify(error="sip credentials required"), 400
    with live_call_lock:
        live_call = LiveCall(cfg, num, user_id=session["uid"])
        live_call.start()
    return jsonify(ok=True)


@app.route("/api/hangup", methods=["POST"])
@login_required
def api_hangup():
    global live_call
    with live_call_lock:
        if live_call and live_call.active:
            live_call.hangup()
    return jsonify(ok=True)


@app.route("/api/call", methods=["POST"])
@login_required
def api_call():
    d = request.json or {}
    raw = d.get("numbers", "").strip()
    if not raw:
        return jsonify(error="no numbers"), 400
    nums = [normalize_number(n.strip()) for n in raw.splitlines() if n.strip()]
    if not nums:
        return jsonify(error="no valid numbers"), 400
    cfg = _build_sip_cfg(d)
    if not cfg["user"] or not cfg["password"]:
        return jsonify(error="sip credentials required"), 400
    mode = d.get("mode", "tts")
    if mode == "direct":
        if not agent_clocked_in:
            return jsonify(error="no agent clocked in"), 400
        msg = d.get("message", "")
        voice = d.get("voice", "en-US-AriaNeural")
        pause = int(d.get("pause", 3))
        trigger = d.get("trigger_digit", "2")
        hangup_dig = d.get("hangup_digit", "1")
        threading.Thread(
            target=run_direct_calls,
            args=(nums, cfg, msg, voice, pause, trigger, hangup_dig,
                  d.get("dc_play", "none"), d.get("dc_tts_msg", ""),
                  session["uid"]),
            daemon=True,
        ).start()
    else:
        msg = d.get("message", "")
        resp = d.get("response", "")
        voice = d.get("voice", "en-US-AriaNeural")
        pause = int(d.get("pause", 3))
        threading.Thread(
            target=run_calls,
            args=(nums, cfg, msg, resp, voice, pause, session["uid"]),
            daemon=True,
        ).start()
    return jsonify(ok=True, count=len(nums))


@app.route("/api/settings", methods=["GET"])
@login_required
def api_get_settings():
    c = get_db()
    row = c.execute(
        "SELECT data FROM user_settings WHERE user_id=?", (session["uid"],)
    ).fetchone()
    c.close()
    return jsonify(json.loads(row["data"]) if row else {})


@app.route("/api/settings", methods=["POST"])
@login_required
def api_save_settings():
    d = request.json or {}
    c = get_db()
    c.execute(
        "INSERT INTO user_settings(user_id, data) VALUES(?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET data=excluded.data",
        (session["uid"], json.dumps(d)),
    )
    c.commit()
    c.close()
    return jsonify(ok=True)


@app.route("/api/sip-test", methods=["POST"])
@login_required
def api_sip_test():
    d = request.json or {}
    cfg = _build_sip_cfg(d)
    if not cfg["user"] or not cfg["password"]:
        return jsonify(ok=False, msg="credentials required")
    try:
        _start_registrar(cfg)
        time.sleep(3)
        with _registrar_lock:
            if _registrar:
                return jsonify(
                    ok=_registrar.status == "registered",
                    msg=_registrar.status_msg,
                )
        return jsonify(ok=False, msg="registrar not started")
    except Exception as e:
        return jsonify(ok=False, msg=str(e))


@app.route("/api/sip-status")
@login_required
def api_sip_status():
    with _registrar_lock:
        if _registrar:
            return jsonify(
                status=_registrar.status,
                msg=_registrar.status_msg,
            )
    return jsonify(status="offline", msg="not connected")


@app.route("/api/history")
@login_required
def api_history():
    c = get_db()
    rows = c.execute(
        "SELECT number, direction, status, source, created_at "
        "FROM call_history WHERE user_id=? ORDER BY id DESC LIMIT 50",
        (session["uid"],),
    ).fetchall()
    c.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/log")
@login_required
def api_log():
    with call_log_lock:
        return jsonify(call_log[-50:])


@app.route("/api/events")
@login_required
def api_events():
    q = queue.Queue(maxsize=256)
    with event_sub_lock:
        event_subscribers.append(q)
    def stream():
        try:
            while True:
                try:
                    yield q.get(timeout=30)
                except queue.Empty:
                    yield ": ka\n\n"
        finally:
            with event_sub_lock:
                try:
                    event_subscribers.remove(q)
                except ValueError:
                    pass
    return Response(stream(), mimetype="text/event-stream")


@app.route("/api/p1-stop", methods=["POST"])
@login_required
def api_p1_stop():
    p1_stop_event.set()
    return jsonify(ok=True)


@app.route("/api/p1-state")
@login_required
def api_p1_state():
    return jsonify(p1_batch_state)


@app.route("/api/agent-status")
@login_required
def api_agent_status():
    return jsonify({"clocked_in": agent_clocked_in})


# ── websocket ─────────────────────────────────────────────────

@sock.route("/ws/p1audio")
def p1_audio_ws(ws):
    with p1_ws_lock:
        p1_ws_clients.append(ws)
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
    except Exception:
        pass
    finally:
        with p1_ws_lock:
            try:
                p1_ws_clients.remove(ws)
            except ValueError:
                pass


@sock.route("/ws/audio")
def audio_ws(ws):
    global live_call
    if not live_call or not live_call.active:
        ws.send(json.dumps({"type": "error", "text": "no active call"}))
        return

    live_call.ws_clients.append(ws)
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            if isinstance(data, bytes) and live_call and live_call.connected:
                live_call.send_audio(data)
            elif isinstance(data, str):
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "dtmf" and live_call and live_call.connected:
                        live_call.send_dtmf(msg.get("digit", ""))
                except (json.JSONDecodeError, AttributeError):
                    pass
    except Exception:
        pass
    finally:
        if live_call:
            try:
                live_call.ws_clients.remove(ws)
            except ValueError:
                pass


agent_reconnect_grace = 3

@sock.route("/ws/agent")
def agent_audio_ws(ws):
    global agent_ws_client, agent_clocked_in
    with agent_ws_lock:
        agent_ws_client = ws
        agent_clocked_in = True
    push_event("agent_status", {"clocked_in": True})
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            if isinstance(data, bytes):
                agent_mic_q.put(data)
    except Exception:
        pass
    finally:
        with agent_ws_lock:
            if agent_ws_client is ws:
                agent_ws_client = None
        time.sleep(agent_reconnect_grace)
        with agent_ws_lock:
            if agent_ws_client is None:
                agent_clocked_in = False
                push_event("agent_status", {"clocked_in": False})


def _agent_audio_out(ulaw_bytes):
    """Send target audio to the agent's browser."""
    with agent_ws_lock:
        ws = agent_ws_client
    if ws:
        try:
            ws.send(ulaw_bytes)
        except Exception:
            pass


def _notify_agent_bridge(info):
    """Notify agent browser that a caller is being bridged."""
    import json as _json
    if isinstance(info, str):
        info = {"number": info}
    info["ts"] = time.strftime("%I:%M %p").lstrip("0")
    push_event("agent_bridge", info)
    with agent_ws_lock:
        ws = agent_ws_client
    if ws:
        try:
            ws.send(_json.dumps({"type": "bridge", **info}))
        except Exception:
            pass


# ── HTML ──────────────────────────────────────────────────────

AUTH_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phantom</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='8' fill='%2322c55e'/%3E%3C/svg%3E">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#080808;--bd:#1a1a1a;--tx:#666;--hi:#c8c8c8;--ac:#22c55e;--er:#dc2626;--ib:#0a0a0a}
*{margin:0;padding:0;box-sizing:border-box;scrollbar-color:#222 transparent}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#222;border-radius:3px}::-webkit-scrollbar-thumb:hover{background:#333}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased}
.a{width:100%;max-width:340px;padding:0 20px}
.br{font-size:.95rem;font-weight:600;color:var(--hi);letter-spacing:.18em;text-transform:uppercase;margin-bottom:28px}
.br::after{content:'';display:block;width:20px;height:2px;background:var(--ac);margin-top:10px}
.f{margin-bottom:14px}
.f label{display:block;font-size:.7rem;letter-spacing:.06em;text-transform:uppercase;margin-bottom:5px}
.f input{width:100%;padding:9px 11px;font-size:.84rem;font-family:inherit;background:var(--ib);border:1px solid var(--bd);border-radius:2px;color:var(--hi);outline:none;transition:border-color .15s}
.f input:focus{border-color:#333}
.btn{width:100%;padding:9px;font-size:.84rem;font-weight:500;font-family:inherit;background:var(--ac);color:#000;border:none;border-radius:2px;cursor:pointer;margin-top:4px;transition:opacity .15s}
.btn:hover{opacity:.85}
.alt{margin-top:20px;font-size:.78rem;text-align:center}
.alt a{color:var(--ac);text-decoration:none}
.alt a:hover{text-decoration:underline}
.err{background:rgba(220,38,38,.06);border:1px solid rgba(220,38,38,.15);color:var(--er);padding:7px 10px;font-size:.78rem;border-radius:2px;margin-bottom:14px}
</style></head><body>
<div class="a">
<div class="br">Phantom</div>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<form method="POST">
<div class="f"><label>username</label><input name="username" autocomplete="username" required></div>
<div class="f"><label>password</label><input name="password" type="password" autocomplete="{% if mode == 'register' %}new-password{% else %}current-password{% endif %}" required></div>
{% if mode == 'register' %}<div class="f"><label>confirm password</label><input name="confirm" type="password" autocomplete="new-password" required></div>{% endif %}
<button class="btn" type="submit">{% if mode == 'register' %}create account{% else %}sign in{% endif %}</button>
</form>
<div class="alt">{% if mode == 'register' %}have an account? <a href="/login">sign in</a>{% else %}no account? <a href="/register">register</a>{% endif %}</div>
</div>
</body></html>"""


DASH_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phantom</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='8' fill='%2322c55e'/%3E%3C/svg%3E">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#060606;--sf:#0c0c0c;--bd:#181818;
  --tx:#555;--hi:#d0d0d0;--dm:#2a2a2a;
  --ac:#22c55e;--acb:rgba(34,197,94,.06);
  --er:#dc2626;--wn:#eab308;--ib:#0a0a0a;
  --card:#0a0a0a;
}
*{margin:0;padding:0;box-sizing:border-box;scrollbar-color:#222 transparent}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#222;border-radius:3px}::-webkit-scrollbar-thumb:hover{background:#333}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;-webkit-font-smoothing:antialiased}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid var(--bd);position:sticky;top:0;background:var(--bg);z-index:10}
.brand{font-size:.82rem;font-weight:700;color:var(--hi);letter-spacing:.18em;text-transform:uppercase;text-decoration:none}
.ub{display:flex;align-items:center;gap:12px;font-size:.74rem}
.ub .nm{color:var(--tx);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ub a{color:var(--dm);text-decoration:none;transition:color .15s}
.ub a:hover{color:var(--tx)}
.gear{background:none;border:none;cursor:pointer;padding:4px;display:flex;align-items:center;transition:opacity .15s}
.gear:hover{opacity:.7}
.gear svg{width:17px;height:17px}

.sbar{display:none}
.sbar .dot{width:7px;height:7px;border-radius:50%;background:var(--dm);flex-shrink:0;transition:background .3s}
.sbar .dot.on{background:var(--ac);box-shadow:0 0 6px rgba(34,197,94,.4)}
.sbar .dot.fail{background:var(--er)}
.sbar .stxt{color:var(--dm);transition:color .3s}
.sbar .stxt.on{color:var(--tx)}

.wrap{max-width:960px;margin:0 auto;padding:20px 16px 60px}

.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--bd);border-radius:3px;padding:12px 14px}
.stat .sv{font-size:1.4rem;font-weight:700;color:var(--hi);font-variant-numeric:tabular-nums;line-height:1}
.stat .sl2{font-size:.64rem;letter-spacing:.08em;text-transform:uppercase;color:var(--dm);margin-top:5px}

.sec{margin-bottom:16px}
.sl{font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;color:var(--dm);margin-bottom:5px}
.cid-row{display:flex;gap:8px;align-items:flex-end}
.cid-row input{flex:1}
.cid-row .cid-tag{font-size:.64rem;color:var(--dm);white-space:nowrap;padding-bottom:10px}

input,textarea,select{width:100%;padding:8px 10px;font-size:.84rem;font-family:inherit;background:var(--ib);border:1px solid var(--bd);border-radius:2px;color:var(--hi);outline:none;transition:border-color .15s}
input:focus,textarea:focus,select:focus{border-color:#2a2a2a}
input:disabled{opacity:.4}
textarea{resize:vertical;min-height:72px;font-family:'Courier New',Consolas,monospace;font-size:.8rem;line-height:1.5}
select{cursor:pointer;-webkit-appearance:none;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%23555'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center}
.row{display:flex;gap:10px}
.row>div{flex:1}
.btn{width:100%;padding:10px;font-size:.84rem;font-weight:600;font-family:inherit;background:var(--ac);color:#000;border:none;border-radius:2px;cursor:pointer;transition:opacity .15s;letter-spacing:.02em}
.btn:hover{opacity:.85}
.btn:disabled{opacity:.35;cursor:not-allowed}
.btn-sm{padding:8px 14px;font-size:.76rem;width:auto}
.btn-ghost{background:transparent;color:var(--tx);border:1px solid var(--bd)}
.btn-ghost:hover{border-color:#333;color:var(--hi)}
.tabs{display:flex;border-bottom:1px solid var(--bd);margin-bottom:20px}
.tab{background:none;border:none;color:var(--dm);font-size:.76rem;font-family:inherit;padding:9px 18px;cursor:pointer;border-bottom:2px solid transparent;transition:color .15s;text-transform:lowercase;letter-spacing:.02em}
.tab.active{color:var(--hi);border-bottom-color:var(--ac)}
.tab:hover{color:var(--tx)}
.btn-end{background:var(--er);color:#fff}
.btn-mic{background:var(--sf);color:var(--tx);border:1px solid var(--bd)}
.btn-mic.on{background:var(--ac);color:#000;border-color:var(--ac)}
.dlr-wrap{display:flex;gap:0;min-height:calc(100vh - 200px)}
.dlr-phone{width:300px;flex-shrink:0;border-right:1px solid var(--bd);padding:20px 16px;display:flex;flex-direction:column;align-items:center}
.dlr-side{flex:1;padding:16px 14px;overflow-y:auto;max-height:calc(100vh - 200px)}
.dlr-display{background:transparent;border:none;border-bottom:1px solid var(--bd);color:var(--hi);font-size:1.6rem;font-weight:300;text-align:center;width:100%;padding:12px 0 10px;font-variant-numeric:tabular-nums;letter-spacing:.05em;font-family:inherit;outline:none}
.dlr-display::placeholder{color:var(--dm);font-size:.9rem;font-weight:400;letter-spacing:.02em}
.dlr-info{display:flex;align-items:center;justify-content:center;gap:10px;min-height:24px;padding:6px 0 4px;font-size:.78rem}
.dlr-info #dial-st{color:var(--ac)}
.dlr-info #call-timer{color:var(--hi);font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:.04em}
.dial-pad{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;width:100%;margin:8px 0}
.dp-btn{background:var(--sf);border:1px solid var(--bd);border-radius:6px;color:var(--hi);font-size:1.1rem;font-weight:600;padding:14px 0;cursor:pointer;transition:background .1s;display:flex;flex-direction:column;align-items:center;line-height:1.1}
.dp-btn:hover{background:#191919;border-color:#252525}
.dp-btn:active{background:#1a1a1a;transform:scale(.98)}
.dp-sub{font-size:.5rem;font-weight:400;text-transform:uppercase;letter-spacing:.1em;opacity:.45;margin-top:2px}
.dlr-actions{display:flex;gap:8px;width:100%;margin-top:8px}
.dlr-call{flex:3}
.dlr-del{flex:1;font-size:1.2rem;padding:10px 0}
@media(max-width:700px){.dlr-wrap{flex-direction:column}.dlr-phone{width:100%;border-right:none;border-bottom:1px solid var(--bd)}.dlr-side{max-height:none}}
/* p1 two-panel */
.p1-wrap{display:flex;gap:0;min-height:calc(100vh - 200px)}
.p1-left{width:280px;flex-shrink:0;border-right:1px solid var(--bd);padding:16px 14px;overflow-y:auto;max-height:calc(100vh - 200px)}
.p1-right{flex:1;padding:16px 14px;overflow-y:auto;max-height:calc(100vh - 200px)}
@media(max-width:700px){.p1-wrap{flex-direction:column}.p1-left,.p1-right{width:100%;max-height:none;border-right:none}.p1-left{border-bottom:1px solid var(--bd)}}

.p1-sec{margin-bottom:14px}
.p1-secn{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.p1-secn .n{width:20px;height:20px;border-radius:50%;background:var(--ac);color:#000;font-size:.66rem;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.p1-secn .t{font-size:.72rem;font-weight:600;color:var(--hi);text-transform:uppercase;letter-spacing:.06em}

.p1-nums{resize:vertical;min-height:80px;font-family:'Courier New',Consolas,monospace;font-size:.78rem;line-height:1.5}
.p1-count{font-size:.68rem;color:var(--dm);margin-top:4px;display:flex;justify-content:space-between;align-items:center}
.p1-csv{font-size:.68rem;color:var(--ac);background:none;border:none;cursor:pointer;font-family:inherit;text-decoration:none}
.p1-csv:hover{text-decoration:underline}

/* mode toggle */
.mode-pills{display:flex;border:1px solid var(--bd);border-radius:4px;overflow:hidden;margin-bottom:12px}
.mode-pill{flex:1;display:flex;align-items:center;justify-content:center;gap:6px;padding:10px 8px;background:transparent;border:none;color:var(--dm);font-size:.72rem;font-family:inherit;cursor:pointer;transition:all .15s;border-right:1px solid var(--bd)}
.mode-pill:last-child{border-right:none}
.mode-pill.active{background:var(--acb);color:var(--ac)}
.mode-pill svg{flex-shrink:0}
.mode-pill .mp-label{font-weight:600}
.mode-pill .mp-sub{font-size:.6rem;color:var(--dm)}

/* direct call panel */
.dc-panel{display:none}
.dc-panel.active{display:block}
.dc-connect{display:flex;gap:4px;margin-top:8px}
.dc-opt{flex:1;padding:6px 8px;font-size:.68rem;font-family:inherit;background:transparent;border:1px solid var(--bd);border-radius:3px;color:var(--dm);cursor:pointer;text-align:center;transition:all .15s}
.dc-opt.active{background:var(--ac);color:#000;border-color:var(--ac);font-weight:600}
.dc-dig{width:32px;height:32px;font-size:.74rem;font-family:inherit;font-weight:600;background:transparent;border:1px solid var(--bd);border-radius:3px;color:var(--dm);cursor:pointer;transition:all .15s;display:flex;align-items:center;justify-content:center}
.dc-dig.active{background:var(--ac);color:#000;border-color:var(--ac)}
.clock-btn{width:100%;padding:10px;font-size:.74rem;font-family:inherit;font-weight:600;border:1px solid var(--bd);border-radius:3px;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:8px}
.clock-btn.out{background:transparent;color:var(--dm)}
.clock-btn.in{background:rgba(34,197,94,.1);color:var(--ac);border-color:var(--ac)}
.clock-btn .clock-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;transition:all .2s}
.clock-btn.out .clock-dot{background:var(--dm)}
.clock-btn.in .clock-dot{background:var(--ac);box-shadow:0 0 8px rgba(34,197,94,.5)}
.p1-status-bar{padding:6px 10px;font-size:.68rem;color:var(--dm);background:var(--card);border:1px solid var(--bd);border-radius:3px;margin-bottom:10px;min-height:24px;display:flex;align-items:center;gap:6px}
.p1-status-bar .pulse{width:6px;height:6px;border-radius:50%;background:var(--ac);flex-shrink:0;animation:pulse-glow 1.5s infinite}
@keyframes pulse-glow{0%,100%{opacity:.3}50%{opacity:1}}

/* tts steps */
.tts-step{background:var(--ib);border:1px solid var(--bd);border-radius:3px;padding:10px;margin-bottom:8px}
.tts-step-head{display:flex;align-items:center;gap:6px;margin-bottom:6px}
.tts-step-del{background:none;border:none;color:var(--dm);cursor:pointer;padding:2px 6px;font-size:.85rem;opacity:.4;margin-left:auto;line-height:1}
.tts-step-del:hover{color:#e55;opacity:1}
.tts-step-num{width:16px;height:16px;border-radius:3px;background:var(--bd);color:var(--dm);font-size:.6rem;font-weight:700;display:flex;align-items:center;justify-content:center}
.tts-step textarea{min-height:48px;font-size:.76rem}
.tts-dtmf{display:flex;gap:6px;margin-top:6px;align-items:center}
.tts-dtmf select,.tts-dtmf input{width:auto;flex:1;padding:5px 8px;font-size:.74rem}
.tts-dtmf .sl{font-size:.6rem;margin-bottom:2px}
.tts-add{font-size:.68rem;color:var(--ac);background:none;border:1px dashed var(--bd);border-radius:3px;padding:6px;width:100%;cursor:pointer;font-family:inherit;margin-top:4px;transition:border-color .15s}
.tts-add:hover{border-color:var(--ac)}

/* adv toggle */
.adv-toggle{display:flex;align-items:center;gap:6px;font-size:.68rem;color:var(--dm);background:none;border:none;cursor:pointer;font-family:inherit;padding:4px 0;margin-bottom:8px;letter-spacing:.04em;text-transform:uppercase}
.adv-toggle svg{transition:transform .2s}
.adv-toggle.open svg{transform:rotate(90deg)}
.adv-body{display:none}.adv-body.open{display:block}

/* start/pause row */
.p1-actions{display:flex;gap:8px;margin-top:6px}
.p1-actions .btn{flex:1;padding:10px}
.btn-start{background:var(--ac);color:#000}
.btn-pause{background:var(--sf);color:var(--tx);border:1px solid var(--bd)}

/* right: stats row */
.p1-stats{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}
.p1-stat{background:var(--card);border:1px solid var(--bd);border-radius:3px;padding:10px 12px;flex:1;min-width:70px;text-align:center}
.p1-stat .pv{font-size:1.2rem;font-weight:700;font-variant-numeric:tabular-nums;line-height:1}
.p1-stat .pl{font-size:.58rem;letter-spacing:.08em;text-transform:uppercase;margin-top:3px}
.p1-stat.pending .pv{color:var(--dm)}.p1-stat.pending .pl{color:var(--dm)}
.p1-stat.dialing .pv{color:var(--wn)}.p1-stat.dialing .pl{color:var(--wn)}
.p1-stat.answered .pv{color:var(--ac)}.p1-stat.answered .pl{color:var(--ac)}
.p1-stat.completed .pv{color:var(--ac)}.p1-stat.completed .pl{color:var(--ac)}
.p1-stat.failed .pv{color:var(--er)}.p1-stat.failed .pl{color:var(--er)}

/* progress bar */
.p1-pbar{margin-bottom:14px}
.p1-pbar-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.p1-pbar-label{font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;color:var(--dm)}
.p1-pbar-pct{font-size:.82rem;font-weight:700;color:var(--ac)}
.p1-pbar-track{height:4px;background:var(--bd);border-radius:2px;overflow:hidden}
.p1-pbar-fill{height:100%;background:var(--ac);transition:width .3s;border-radius:2px;width:0}
.p1-pbar-legend{display:flex;gap:12px;margin-top:6px;font-size:.62rem}
.p1-pbar-legend span{display:flex;align-items:center;gap:4px}
.p1-pbar-legend .dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}

/* audio monitor bar */
.p1-monitor{display:flex;align-items:center;gap:8px;padding:8px 10px;background:var(--card);border:1px solid var(--bd);border-radius:3px;margin-bottom:14px}
.p1-monitor .mon-icon{width:18px;height:18px;color:var(--ac);flex-shrink:0}
.p1-monitor .mon-label{font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;color:var(--dm);flex:1}
.p1-monitor .mon-mute{font-size:.64rem;padding:4px 10px;border-radius:12px;border:1px solid var(--bd);background:transparent;color:var(--dm);cursor:pointer;font-family:inherit;transition:all .15s}
.p1-monitor .mon-mute.muted{background:var(--er);color:#fff;border-color:var(--er)}
.p1-monitor .mon-mute:hover{border-color:#333}

/* live table */
.p1-live-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.p1-live-title{font-size:.76rem;font-weight:600;color:var(--hi)}
.p1-filters{display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap}
.p1-filt{font-size:.64rem;padding:4px 10px;border-radius:12px;border:1px solid var(--bd);background:transparent;color:var(--dm);cursor:pointer;font-family:inherit;transition:all .15s}
.p1-filt.active{background:var(--ac);color:#000;border-color:var(--ac)}
.p1-filt:hover{border-color:#333}
.p1-table{width:100%;border-collapse:collapse;font-size:.74rem}
.p1-table th{text-align:left;font-size:.6rem;letter-spacing:.08em;text-transform:uppercase;color:var(--dm);font-weight:600;padding:6px 8px;border-bottom:1px solid var(--bd)}
.p1-table td{padding:6px 8px;border-bottom:1px solid #0e0e0e;color:var(--tx);font-variant-numeric:tabular-nums}
.p1-table .num{color:var(--hi);font-weight:500}
.p1-table .s-ok{color:var(--ac)}.p1-table .s-fail{color:var(--er)}.p1-table .s-call{color:var(--wn)}.p1-table .s-pending{color:var(--dm)}.p1-table .s-warn{color:#f59e0b}
.p1-empty{text-align:center;padding:40px 0;color:var(--dm);font-size:.78rem}
.p1-overlay{display:none}
hr.dv{border:none;border-top:1px solid var(--bd);margin:16px 0}

.view{display:none}.view.active{display:block}
.back{background:none;border:none;color:var(--dm);font-size:.78rem;font-family:inherit;cursor:pointer;padding:0;margin-bottom:16px;display:flex;align-items:center;gap:5px;transition:color .15s}
.back:hover{color:var(--tx)}
.stt{font-size:.88rem;font-weight:600;color:var(--hi);letter-spacing:.04em;margin-bottom:20px}
.srow{margin-bottom:10px}
.conn-row{display:flex;align-items:center;gap:10px;margin:12px 0 18px}
.conn-dot{width:9px;height:9px;border-radius:50%;background:var(--dm);flex-shrink:0}
.conn-dot.on{background:var(--ac);box-shadow:0 0 8px rgba(34,197,94,.5)}
.conn-dot.fail{background:var(--er)}
.conn-txt{font-size:.78rem;color:var(--dm);flex:1}
.conn-txt.on{color:var(--ac)}
.conn-txt.fail{color:var(--er)}
.scat{font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;color:var(--dm);margin-bottom:8px;margin-top:18px;padding-top:14px;border-top:1px solid var(--bd)}
.sp-box{background:var(--ib);border:1px solid var(--bd);border-radius:6px;padding:10px 14px;font-size:.82rem;font-family:monospace}
.sp-row{display:flex;justify-content:space-between;padding:3px 0}
.sp-lbl{color:var(--dm)}
.sp-val{color:var(--hi);user-select:all}

.log{font-family:'Courier New',Consolas,monospace;font-size:.76rem;max-height:300px;overflow-y:auto}
.log:empty::after{content:'—';color:var(--dm)}
.lr{display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid #0e0e0e}
.lr .n{color:var(--hi);font-variant-numeric:tabular-nums}
.s-ok{color:var(--ac)}.s-fail{color:var(--er)}.s-call{color:var(--wn)}.s-warn{color:#f59e0b}
.lr .m{color:var(--dm);font-size:.68rem}
.empty{color:var(--dm);font-size:.78rem;padding:8px 0}
.redial{background:none;border:none;cursor:pointer;padding:2px;color:var(--dm);transition:color .15s;display:flex;align-items:center}
.redial:hover{color:var(--ac)}
@media(max-width:480px){.row{flex-direction:column;gap:6px}.stats{grid-template-columns:1fr 1fr}}
.bridge-toast{position:fixed;top:20px;right:20px;z-index:9999;width:320px;background:var(--card);border:1px solid var(--bd);border-left:3px solid var(--ac);border-radius:8px;padding:0;font-family:'Inter',sans-serif;animation:bslide .3s ease;overflow:hidden}
@keyframes bslide{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}
@keyframes bshine{0%{background-position:-200% 0}100%{background-position:200% 0}}
.bridge-toast .bt-bar{height:2px;background:linear-gradient(90deg,transparent,var(--ac),transparent);background-size:200% 100%;animation:bshine 2s linear infinite}
.bridge-toast .bt-body{padding:14px 16px}
.bridge-toast .bt-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.bridge-toast .bt-label{font-size:.68rem;font-weight:600;text-transform:uppercase;letter-spacing:.12em;color:var(--ac)}
.bridge-toast .bt-time{font-size:.65rem;color:var(--dm);font-variant-numeric:tabular-nums}
.bridge-toast .bt-x{background:none;border:none;color:var(--dm);cursor:pointer;font-size:.9rem;padding:0 0 0 8px;line-height:1;transition:color .15s}
.bridge-toast .bt-x:hover{color:var(--hi)}
.bridge-toast .bt-num{font-size:1.15rem;font-weight:700;color:var(--hi);letter-spacing:.3px;font-family:'Courier New',monospace;margin-bottom:8px}
.bridge-toast .bt-details{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;font-size:.72rem}
.bridge-toast .bt-k{color:var(--dm)}
.bridge-toast .bt-v{color:var(--tx)}
.bridge-toast .bt-footer{display:flex;justify-content:flex-end;padding:8px 16px;border-top:1px solid var(--bd)}
.bridge-toast .bt-btn{background:none;border:1px solid var(--bd);color:var(--tx);padding:5px 14px;border-radius:5px;font-size:.72rem;cursor:pointer;font-family:'Inter',sans-serif;transition:all .15s}
.bridge-toast .bt-btn:hover{border-color:var(--ac);color:var(--ac)}
</style></head><body>
<header>
<a href="/" class="brand">Phantom</a>
<div class="ub"><span class="nm">{{ uname }}</span><a href="/logout">sign out</a><button class="gear" onclick="showSettings()" title="settings"><svg viewBox="0 0 24 24" fill="none" stroke="#444" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg></button></div>
</header>

<div class="sbar">
<div class="dot" id="sbar-dot"></div>
<span class="stxt" id="sbar-txt">not connected</span>
</div>

<div class="wrap">

<!-- main view -->
<div id="view-main" class="view active">

<div class="stats">
<div class="stat"><div class="sv" id="st-total">0</div><div class="sl2">total calls</div></div>
<div class="stat"><div class="sv" id="st-ok">0</div><div class="sl2">answered</div></div>
<div class="stat"><div class="sv" id="st-fail">0</div><div class="sl2">failed</div></div>
</div>

<div class="sec">
<div class="sl">caller id</div>
<input id="cid" value="18002893557" placeholder="caller id">
</div>

<div class="tabs">
<button class="tab active" data-tab="dialer" onclick="switchTab('dialer')">dialer</button>
<button class="tab" data-tab="p1bot" onclick="switchTab('p1bot')">p1 bot</button>
</div>

<!-- dialer -->
<div id="tab-dialer" class="tc">
<div class="dlr-wrap">
<div class="dlr-phone">
<input id="dial-num" class="dlr-display" placeholder="enter number" autocomplete="off">
<div class="dlr-info"><span id="dial-st"></span><span id="call-timer"></span></div>
<div class="dial-pad">
<button class="dp-btn" onclick="dialKey('1')">1</button>
<button class="dp-btn" onclick="dialKey('2')">2<span class="dp-sub">abc</span></button>
<button class="dp-btn" onclick="dialKey('3')">3<span class="dp-sub">def</span></button>
<button class="dp-btn" onclick="dialKey('4')">4<span class="dp-sub">ghi</span></button>
<button class="dp-btn" onclick="dialKey('5')">5<span class="dp-sub">jkl</span></button>
<button class="dp-btn" onclick="dialKey('6')">6<span class="dp-sub">mno</span></button>
<button class="dp-btn" onclick="dialKey('7')">7<span class="dp-sub">pqrs</span></button>
<button class="dp-btn" onclick="dialKey('8')">8<span class="dp-sub">tuv</span></button>
<button class="dp-btn" onclick="dialKey('9')">9<span class="dp-sub">wxyz</span></button>
<button class="dp-btn" onclick="dialKey('*')">*</button>
<button class="dp-btn" onclick="dialKey('0')">0<span class="dp-sub">+</span></button>
<button class="dp-btn" onclick="dialKey('#')">#</button>
</div>
<div id="dial-idle" class="dlr-actions">
<button class="btn dlr-call" onclick="dial()">call</button>
<button class="btn btn-ghost dlr-del" onclick="dialDel()">&#9003;</button>
</div>
<div id="dial-active" class="dlr-actions" style="display:none">
<button class="btn btn-end" onclick="hangup()">hang up</button>
<button class="btn btn-mic" id="mic-btn" onclick="toggleMic()">mic off</button>
</div>
</div>
<div class="dlr-side">
<div class="sec"><div class="sl">audio</div><div class="row">
<div><div class="sl"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:3px"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/></svg>mic</div><select id="mic-sel"><option value="">default</option></select></div>
<div><div class="sl"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:3px"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/></svg>speaker</div><select id="spk-sel"><option value="">default</option></select></div>
</div></div>
<hr class="dv">
<div class="sec">
<div class="sl">recent calls</div>
<div class="log" id="history"></div>
</div>
</div>
</div>
</div>

<!-- p1 bot -->
<div id="tab-p1bot" class="tc" style="display:none">
<div class="p1-wrap">

<!-- left: setup -->
<div class="p1-left">

<div class="p1-sec">
<div class="p1-secn"><span class="n">1</span><span class="t">phone numbers</span></div>
<textarea id="numbers" class="p1-nums" placeholder="one per line, comma, or csv"></textarea>
<div class="p1-count"><span id="p1-numcount">0 numbers</span><label class="p1-csv">+ upload csv<input type="file" id="csv-upload" accept=".csv,.txt" style="display:none" onchange="loadCSV(this)"></label></div>
</div>

<div class="p1-sec">
<div class="p1-secn"><span class="n">2</span><span class="t">call settings</span></div>
<div class="sl">caller id</div>
<input id="p1-cid" value="18002893557" style="margin-bottom:8px">
<div class="row" style="margin-bottom:8px">
<div><div class="sl">voice</div><select id="voice">
<option value="en-US-AriaNeural">Aria</option>
<option value="en-US-GuyNeural">Guy</option>
<option value="en-US-JennyNeural">Jenny</option>
<option value="en-US-DavisNeural">Davis</option>
</select></div>
<div><div class="sl">pause (s)</div><input id="pause" type="number" value="3" min="0" max="10"></div>
</div>
</div>

<div class="mode-pills">
<button class="mode-pill active" id="pill-tts" onclick="setCallMode('tts')">
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/></svg>
<div><div class="mp-label">TTS Step</div><div class="mp-sub">voice messages &amp; IVR</div></div>
</button>
<button class="mode-pill" id="pill-dc" onclick="setCallMode('direct')">
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
<div><div class="mp-label">Direct Call</div><div class="mp-sub">bridge to a live agent</div></div>
</button>
</div>

<div class="p1-sec" id="panel-tts">
<div class="p1-secn"><span class="n">3</span><span class="t">tts steps</span></div>
<div id="tts-steps">
<div class="tts-step" data-step="1">
<div class="tts-step-head"><span class="tts-step-num">1</span><span class="sl" style="margin:0">tts message</span><button class="tts-step-del" onclick="removeTTSStep(this)" title="remove step">&times;</button></div>
<textarea placeholder="message on answer...">Hello, this is a call regarding your inquiry. Press 1 to speak with a representative.</textarea>
<div class="tts-dtmf">
<div style="flex:1"><div class="sl">on dtmf</div><select><option value="">auto-timer</option><option value="any">any key</option><option value="1">1</option><option value="2">2</option><option value="3">3</option></select></div>
<div style="flex:1"><div class="sl">then</div><select><option value="next">next step</option><option value="hangup">hang up</option><option value="transfer">transfer to agent</option></select></div>
</div>
</div>
<div class="tts-step" data-step="2">
<div class="tts-step-head"><span class="tts-step-num">2</span><span class="sl" style="margin:0">response message</span><button class="tts-step-del" onclick="removeTTSStep(this)" title="remove step">&times;</button></div>
<textarea placeholder="response on keypress (optional)...">Thank you! A representative will be with you shortly. Goodbye.</textarea>
<div class="tts-dtmf">
<div style="flex:1"><div class="sl">on dtmf</div><select><option value="">auto-timer</option><option value="any">any key</option></select></div>
<div style="flex:1"><div class="sl">then</div><select><option value="hangup">hang up</option><option value="next">next step</option><option value="transfer">transfer to agent</option></select></div>
</div>
</div>
</div>
<button class="tts-add" onclick="addTTSStep()">+ add step</button>
</div>

<div class="dc-panel" id="panel-dc">
<div class="p1-secn"><span class="n">3</span><span class="t">agent</span></div>

<div class="sl">agent status</div>
<button class="clock-btn out" id="clock-btn" onclick="toggleClockIn()">
<span class="clock-dot"></span>
<span id="clock-label">clock in</span>
</button>
<div style="font-size:.6rem;color:var(--dm);margin:-4px 0 10px">clock in to receive calls through your browser</div>

<div class="p1-secn"><span class="n">4</span><span class="t">dtmf routing</span></div>
<div class="sl">transfer to agent when caller presses</div>
<div id="dc-trigger-row" class="dc-digits" style="display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap">
<button class="dc-dig" onclick="setTrigger(this)" data-val="1">1</button>
<button class="dc-dig active" onclick="setTrigger(this)" data-val="2">2</button>
<button class="dc-dig" onclick="setTrigger(this)" data-val="3">3</button>
<button class="dc-dig" onclick="setTrigger(this)" data-val="4">4</button>
<button class="dc-dig" onclick="setTrigger(this)" data-val="5">5</button>
<button class="dc-dig" onclick="setTrigger(this)" data-val="0">0</button>
<button class="dc-dig" onclick="setTrigger(this)" data-val="9">9</button>
</div>
<div class="sl">hang up when caller presses</div>
<div id="dc-hangup-row" class="dc-digits" style="display:flex;gap:4px;margin-bottom:10px;flex-wrap:wrap">
<button class="dc-dig active" onclick="setHangupDig(this)" data-val="1">1</button>
<button class="dc-dig" onclick="setHangupDig(this)" data-val="2">2</button>
<button class="dc-dig" onclick="setHangupDig(this)" data-val="3">3</button>
<button class="dc-dig" onclick="setHangupDig(this)" data-val="0">0</button>
<button class="dc-dig" onclick="setHangupDig(this)" data-val="*">*</button>
<button class="dc-dig" onclick="setHangupDig(this)" data-val="none">none</button>
</div>

<div class="p1-secn"><span class="n">5</span><span class="t">while connecting</span></div>
<div class="sl">play while transferring to agent</div>
<div class="dc-connect">
<button class="dc-opt active" data-val="none" onclick="setDCPlay(this)">None</button>
<button class="dc-opt" data-val="music" onclick="setDCPlay(this)">Hold Music</button>
<button class="dc-opt" data-val="tts" onclick="setDCPlay(this)">TTS Message</button>
</div>
<input id="dc-tts-msg" placeholder="hold message while transferring..." value="Thank you for your patience. A representative will be with you shortly. Please stay on the line." style="display:none;margin-top:8px">
<div style="font-size:.58rem;color:var(--dm);margin-top:6px">TTS steps above play first — when they press the trigger digit, they transfer to you</div>
</div>

<button class="adv-toggle" id="adv-tog" onclick="toggleAdv()"><svg width="8" height="8" viewBox="0 0 8 8"><path d="M2 0l4 4-4 4z" fill="currentColor"/></svg> advanced settings</button>
<div class="adv-body" id="adv-body">
<div class="row" style="margin-bottom:8px">
<div><div class="sl">retry count</div><input id="retries" type="number" value="3" min="0" max="10"></div>
<div><div class="sl">delay (s)</div><input id="delay" type="number" value="3" min="0" max="30"></div>
</div>
<div class="row">
<div><div class="sl">ring timeout (s)</div><input id="ring-timeout" type="number" value="30" min="5" max="60"></div>
<div></div>
</div>
</div>

<div class="p1-actions">
<button class="btn btn-start" id="p1-start" onclick="startP1()"><svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-1px;margin-right:4px"><polygon points="5 3 19 12 5 21"/></svg>start</button>
<button class="btn btn-pause" id="p1-pause" onclick="stopP1()" disabled><svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-1px;margin-right:4px"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>stop</button>
</div>

</div>

<!-- right: live dashboard -->
<div class="p1-right">

<div class="p1-stats">
<div class="p1-stat pending"><div class="pv" id="ps-pending">0</div><div class="pl">pending</div></div>
<div class="p1-stat dialing"><div class="pv" id="ps-dialing">0</div><div class="pl">dialing</div></div>
<div class="p1-stat answered"><div class="pv" id="ps-answered">0</div><div class="pl">answered</div></div>
<div class="p1-stat completed"><div class="pv" id="ps-completed">0</div><div class="pl">completed</div></div>
<div class="p1-stat failed"><div class="pv" id="ps-failed">0</div><div class="pl">failed</div></div>
</div>

<div class="p1-pbar">
<div class="p1-pbar-head"><span class="p1-pbar-label">progress</span><span class="p1-pbar-pct" id="p1-pct">0%</span></div>
<div class="p1-pbar-track"><div class="p1-pbar-fill" id="p1-bar"></div></div>
<div class="p1-pbar-legend">
<span><span class="dot" style="background:var(--ac)"></span> completed</span>
<span><span class="dot" style="background:var(--er)"></span> failed</span>
<span><span class="dot" style="background:var(--wn)"></span> active</span>
<span id="p1-total-label">0 total</span>
</div>
</div>

<div class="p1-status-bar" id="p1-status-bar">
<span class="pulse" id="p1-pulse" style="display:none"></span>
<span id="p1-status-msg">ready</span>
</div>

<div class="p1-monitor" id="p1-monitor">
<svg class="mon-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></svg>
<span class="mon-label">live audio monitor</span>
<button class="mon-mute" id="p1-mute" onclick="toggleP1Mute()">mute</button>
</div>

<div class="p1-live-head">
<span class="p1-live-title">live call status</span>
</div>
<div class="p1-filters">
<button class="p1-filt active" data-filter="all" onclick="setP1Filter('all',this)">all</button>
<button class="p1-filt" data-filter="calling" onclick="setP1Filter('calling',this)">dialing</button>
<button class="p1-filt" data-filter="answered" onclick="setP1Filter('answered',this)">answered</button>
<button class="p1-filt" data-filter="failed" onclick="setP1Filter('failed',this)">failed</button>
<button class="p1-filt" data-filter="pending" onclick="setP1Filter('pending',this)">pending</button>
</div>
<table class="p1-table">
<thead><tr><th>number</th><th>status</th><th>dtmf</th><th>dur</th><th>time</th></tr></thead>
<tbody id="p1-tbody"></tbody>
</table>
<div class="p1-empty" id="p1-empty">start a campaign to see live status</div>

</div>

</div>
</div>

</div>

<!-- settings view -->
<div id="view-settings" class="view">
<button class="back" onclick="hideSettings()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg> back</button>
<div class="stt">settings</div>

<div class="sl">sip connection</div>
<div class="conn-row">
<div class="conn-dot" id="conn-dot"></div>
<span class="conn-txt" id="conn-txt">not tested</span>
<button class="btn btn-sm btn-ghost" id="conn-btn" onclick="testConn()">test</button>
</div>

<div class="srow"><div class="row"><div><div class="sl">server</div><input id="server" value="sip.suii.us"></div><div><div class="sl">port</div><input id="port" type="number" value="5060"></div></div></div>
<div class="srow"><div class="row"><div><div class="sl">username</div><input id="sip_user" autocomplete="off"></div><div><div class="sl">password</div><input id="sip_pass" type="password" autocomplete="off"></div></div></div>

<div class="scat">softphone</div>
<div class="sl" style="margin-bottom:6px">connect with MicroSIP or any SIP client for best audio</div>
<div class="sp-box" id="sp-box">
<div class="sp-row"><span class="sp-lbl">server</span><span class="sp-val" id="sp-srv">—</span></div>
<div class="sp-row"><span class="sp-lbl">port</span><span class="sp-val" id="sp-port">—</span></div>
<div class="sp-row"><span class="sp-lbl">username</span><span class="sp-val" id="sp-user">—</span></div>
<div class="sp-row"><span class="sp-lbl">password</span><span class="sp-val" id="sp-pass">—</span></div>
<div class="sp-row"><span class="sp-lbl">caller id</span><span class="sp-val" id="sp-cid">—</span></div>
</div>
<div style="display:flex;gap:8px;margin-top:8px">
<button class="btn btn-sm" onclick="downloadMicroSIP()">download microsip config</button>
<button class="btn btn-sm btn-ghost" onclick="copySIPDetails()">copy details</button>
</div>

<div class="scat">advanced</div>
<div class="srow"><div class="row"><div><div class="sl">local sip port</div><input id="sip_port" type="number" value="5080"></div><div><div class="sl">retries</div><input id="retries" type="number" value="3" min="1" max="10"></div></div></div>
<div class="srow"><div class="row"><div><div class="sl">delay between calls (s)</div><input id="delay" type="number" value="3" min="0" max="30"></div><div></div></div></div>
</div>

</div>


<script>
const $=id=>document.getElementById(id);

function switchTab(t){
document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===t));
document.querySelectorAll('.tc').forEach(c=>c.style.display=c.id==='tab-'+t?'':'none');
document.querySelector('.wrap').classList.toggle('wide',t==='p1bot'||t==='dialer');
}
function showSettings(){$('view-main').classList.remove('active');$('view-settings').classList.add('active')}
function hideSettings(){$('view-settings').classList.remove('active');$('view-main').classList.add('active')}

const SAVE_FIELDS=['cid','server','port','sip_user','sip_pass','sip_port','retries','delay','p1-cid','dc-agent','dc-timeout','dc-tts-msg'];
let _saveTimer=null;
function autoSave(){
clearTimeout(_saveTimer);
_saveTimer=setTimeout(()=>{
const d={};SAVE_FIELDS.forEach(k=>{const e=$(k);if(e)d[k]=e.value});
d.trigger_digit=triggerDigit;d.hangup_digit=hangupDigit;
fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
},600);
}
SAVE_FIELDS.forEach(k=>{const e=$(k);if(e)e.addEventListener('input',autoSave)});
fetch('/api/settings').then(r=>r.json()).then(d=>{
SAVE_FIELDS.forEach(k=>{if(d[k]!==undefined&&$(k))$(k).value=d[k]});
if(d.trigger_digit){triggerDigit=d.trigger_digit;document.querySelectorAll('#dc-trigger-row .dc-dig').forEach(b=>{b.classList.toggle('active',b.dataset.val===d.trigger_digit)});}
if(d.hangup_digit){hangupDigit=d.hangup_digit;document.querySelectorAll('#dc-hangup-row .dc-dig').forEach(b=>{b.classList.toggle('active',b.dataset.val===d.hangup_digit)});}
});

function sipCfg(){return{server:$('server').value,port:$('port').value,sip_user:$('sip_user').value,sip_pass:$('sip_pass').value,caller_id:$('cid').value,sip_port:$('sip_port').value,retries:$('retries').value,delay:$('delay').value}}

function updateSPBox(){
$('sp-srv').textContent=$('server').value||'—';
$('sp-port').textContent=$('port').value||'—';
$('sp-user').textContent=$('sip_user').value||'—';
$('sp-pass').textContent=$('sip_pass').value||'—';
$('sp-cid').textContent=$('cid').value||'—';
}
['server','port','sip_user','sip_pass','cid'].forEach(k=>{const e=$(k);if(e)e.addEventListener('input',updateSPBox)});
setTimeout(updateSPBox,500);

function downloadMicroSIP(){
const ini=`[Settings]
sipServer=${$('server').value}
sipPort=${$('port').value}
domain=${$('server').value}
authID=${$('sip_user').value}
displayName=${$('cid').value}
account=${$('sip_user').value}
accountPassword=${$('sip_pass').value}
`;
const blob=new Blob([ini],{type:'text/plain'});
const a=document.createElement('a');
a.href=URL.createObjectURL(blob);
a.download='microsip.ini';
a.click();URL.revokeObjectURL(a.href);
}

function copySIPDetails(){
const txt=`Server: ${$('server').value}\nPort: ${$('port').value}\nUsername: ${$('sip_user').value}\nPassword: ${$('sip_pass').value}\nCaller ID: ${$('cid').value}`;
navigator.clipboard.writeText(txt).then(()=>{
const btn=event.target;btn.textContent='copied!';setTimeout(()=>btn.textContent='copy details',1500);
});
}

/* device enumeration */
async function loadDevices(){
try{await navigator.mediaDevices.getUserMedia({audio:true}).then(s=>s.getTracks().forEach(t=>t.stop()))}catch(e){}
const devs=await navigator.mediaDevices.enumerateDevices();
const ms=$('mic-sel'),ss=$('spk-sel');
ms.innerHTML='<option value="">default</option>';
ss.innerHTML='<option value="">default</option>';
devs.forEach(d=>{
if(d.kind==='audioinput'){const o=document.createElement('option');o.value=d.deviceId;o.textContent=d.label||'mic '+ms.options.length;ms.appendChild(o)}
if(d.kind==='audiooutput'){const o=document.createElement('option');o.value=d.deviceId;o.textContent=d.label||'speaker '+ss.options.length;ss.appendChild(o)}
});
}
loadDevices();

/* connection test */
function setConn(state,txt){
['sbar-dot','conn-dot'].forEach(id=>{const e=$(id);if(e){e.className=id==='sbar-dot'?'dot':'conn-dot';if(state==='on')e.classList.add('on');if(state==='fail')e.classList.add('fail')}});
['sbar-txt','conn-txt'].forEach(id=>{const e=$(id);if(e){e.textContent=txt;e.className=id==='sbar-txt'?'stxt':'conn-txt';if(state==='on')e.classList.add('on');if(state==='fail')e.classList.add('fail')}});
}
function testConn(){
const b=$('conn-btn');b.disabled=true;b.textContent='testing...';
setConn('','testing...');
fetch('/api/sip-test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(sipCfg())})
.then(r=>r.json()).then(d=>{
setConn(d.ok?'on':'fail',d.msg);
b.disabled=false;b.textContent='test';
}).catch(e=>{setConn('fail','error');b.disabled=false;b.textContent='test'});
}

/* poll sip status */
function pollSipStatus(){
fetch('/api/sip-status').then(r=>r.json()).then(d=>{
const st=d.status==='registered'?'on':d.status==='failed'?'fail':'';
setConn(st,d.msg);
}).catch(()=>{});
}
setInterval(pollSipStatus,10000);
pollSipStatus();

/* ulaw codec */
function ulD(u){u=(~u)&0xFF;const s=u&0x80,e=(u>>4)&7,m=u&0xF;let v=((m<<3)+132)<<e;v-=132;return s?-v/32768:v/32768}
function ulE(s){s=Math.max(-1,Math.min(1,s));let v=Math.round(s*32768),g=0;if(v<0){g=0x80;v=-v}if(v>32635)v=32635;v+=132;let e=7;for(let i=0;i<8;i++){if(v&(16384>>i)){e=7-i;break}}return(~(g|(e<<4)|((v>>(e+3))&0xF)))&0xFF}

/* audio player — accumulate then schedule, browser resamples */
class Player{
constructor(){
this.ctx=new AudioContext({latencyHint:'interactive'});
const sid=$('spk-sel').value;
if(sid&&this.ctx.setSinkId)this.ctx.setSinkId(sid).catch(()=>{});
const ULAW=new Float32Array(256);
for(let i=0;i<256;i++){let b=~i&0xFF;let s=((b&0x0F)<<3)+0x84;s<<=(b>>4)&7;if(b&0x80)s=-s;ULAW[i]=s/32768}
this.ULAW=ULAW;this.nt=0;this.acc=[];this.accLen=0;
}
feed(b){
this.acc.push(b);this.accLen+=b.length;
if(this.accLen<640)return;
const fl=new Float32Array(this.accLen);
let off=0;
for(const chunk of this.acc){for(let i=0;i<chunk.length;i++)fl[off++]=this.ULAW[chunk[i]]}
this.acc=[];this.accLen=0;
const buf=this.ctx.createBuffer(1,fl.length,8000);
buf.getChannelData(0).set(fl);
const src=this.ctx.createBufferSource();
src.buffer=buf;src.connect(this.ctx.destination);
const now=this.ctx.currentTime;
if(this.nt<now+0.005)this.nt=now+0.01;
else if(this.nt>now+0.15)this.nt=now+0.01;
src.start(this.nt);this.nt+=fl.length/8000;
}
close(){try{this.ctx.close()}catch(e){}}
}

/* dialer */
let ws=null,player=null,micStream=null,micProc=null,micCtx=null,micOn=false;
let _callTimer=null,_callStart=0;

function fmtTime(s){const m=Math.floor(s/60),sec=s%60;return String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0')}

function startCallTimer(){
_callStart=Date.now();
$('call-timer').textContent='00:00';
_callTimer=setInterval(()=>{
const elapsed=Math.floor((Date.now()-_callStart)/1000);
$('call-timer').textContent=fmtTime(elapsed);
},1000);
}

function stopCallTimer(){if(_callTimer){clearInterval(_callTimer);_callTimer=null}}

function redial(num){$('dial-num').value=num;dial()}

function dial(){
const num=$('dial-num').value.trim();if(!num)return;
fetch('/api/dial',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({number:num,...sipCfg()})})
.then(r=>r.json()).then(d=>{
if(d.error){alert(d.error);return}
$('dial-idle').style.display='none';$('dial-active').style.display='';
$('dial-st').textContent='connecting...';
$('call-timer').textContent='';
$('dial-num').disabled=true;
connectAudio();
}).catch(e=>alert(e));
}

function connectAudio(){
const proto=location.protocol==='https:'?'wss':'ws';
ws=new WebSocket(proto+'://'+location.host+'/ws/audio');
ws.binaryType='arraybuffer';
player=new Player();
ws.onmessage=e=>{
if(e.data instanceof ArrayBuffer){player.feed(new Uint8Array(e.data))}
else{const m=JSON.parse(e.data);
if(m.type==='connected'){$('dial-st').textContent='picked up';$('dial-st').style.color='var(--ac)';startCallTimer();if(!micOn){startMic();micOn=true;$('mic-btn').textContent='mic on';$('mic-btn').classList.add('on')}}
else if(m.type==='status'){$('dial-st').textContent=m.text;$('dial-st').style.color='var(--dm)'}
else if(m.type==='ended'||m.type==='error'){
stopCallTimer();
const dur=$('call-timer').textContent;
$('dial-st').textContent=(m.text||'hung up')+(dur?' - '+dur:'');
$('dial-st').style.color=m.type==='error'?'var(--er)':'var(--dm)';
setTimeout(()=>{resetDialer();loadHistory();loadStats()},1500)}}
};
ws.onclose=()=>{if($('dial-active').style.display!=='none')resetDialer()};
}

function dialKey(d){
if($('dial-active').style.display!=='none'){sendDTMF(d)}
else{var inp=$('dial-num');inp.value+=d;inp.dispatchEvent(new Event('input'))}
}
function dialDel(){var inp=$('dial-num');inp.value=inp.value.slice(0,-1);inp.dispatchEvent(new Event('input'))}
function sendDTMF(d){if(ws&&ws.readyState===1)ws.send(JSON.stringify({type:'dtmf',digit:d}))}
function hangup(){fetch('/api/hangup',{method:'POST'})}

function resetDialer(){
stopCallTimer();stopMic();if(ws){try{ws.close()}catch(e){}}ws=null;if(player){try{player.close()}catch(e){}}player=null;
$('dial-idle').style.display='';$('dial-active').style.display='none';
$('dial-num').disabled=false;$('dial-st').textContent='';$('call-timer').textContent='';
micOn=false;$('mic-btn').textContent='mic off';$('mic-btn').classList.remove('on');
}

function toggleMic(){
if(!micOn){startMic();micOn=true;$('mic-btn').textContent='mic on';$('mic-btn').classList.add('on')}
else{stopMic();micOn=false;$('mic-btn').textContent='mic off';$('mic-btn').classList.remove('on')}
}

async function startMic(){
const devId=$('mic-sel').value;
const constraints={audio:{
...(devId?{deviceId:{exact:devId}}:{}),
echoCancellation:true,noiseSuppression:true,autoGainControl:true
}};
try{micStream=await navigator.mediaDevices.getUserMedia(constraints)}catch(e){alert('mic access denied');return}
micCtx=new AudioContext();
const src=micCtx.createMediaStreamSource(micStream);
const aaf=micCtx.createBiquadFilter();
aaf.type='lowpass';aaf.frequency.value=3400;aaf.Q.value=0.707;
src.connect(aaf);
micProc=micCtx.createScriptProcessor(2048,1,1);
const ratio=micCtx.sampleRate/8000;
micProc.onaudioprocess=e=>{
if(!ws||ws.readyState!==1)return;
const inp=e.inputBuffer.getChannelData(0),len=Math.floor(inp.length/ratio);
const ul=new Uint8Array(len);
for(let i=0;i<len;i++){
const pos=i*ratio;const idx=Math.floor(pos);const fr=pos-idx;
ul[i]=ulE((inp[idx]||0)*(1-fr)+(inp[idx+1]||0)*fr);
}
for(let o=0;o+160<=ul.length;o+=160)ws.send(ul.slice(o,o+160).buffer);
};
aaf.connect(micProc);micProc.connect(micCtx.destination);
}

function stopMic(){
if(micProc){micProc.disconnect();micProc=null}
if(micStream){micStream.getTracks().forEach(t=>t.stop());micStream=null}
if(micCtx){micCtx.close();micCtx=null}
}

/* P1 Bot */
let p1AudioWs=null,p1Ctx=null,p1Muted=false,p1Proc=null;
let p1Rows=[],p1Filter='all',p1Running=false;
let agentWs=null,agentCtx=null,agentNext=0,agentClockedIn=false;
let agentMicStream=null,agentMicCtx=null,agentMicProc=null;
let triggerDigit='2',hangupDigit='1';
let p1Mode='tts',dcPlay='none';

function setCallMode(m){
p1Mode=m;
$('pill-tts').classList.toggle('active',m==='tts');
$('pill-dc').classList.toggle('active',m==='direct');
$('panel-tts').style.display=m==='tts'?'':'none';
$('panel-dc').classList.toggle('active',m==='direct');
}
function setDCPlay(btn){
document.querySelectorAll('.dc-opt').forEach(b=>b.classList.remove('active'));
btn.classList.add('active');dcPlay=btn.dataset.val;
$('dc-tts-msg').style.display=dcPlay==='tts'?'':'none';
}
function setTrigger(btn){
btn.parentElement.querySelectorAll('.dc-dig').forEach(b=>b.classList.remove('active'));
btn.classList.add('active');triggerDigit=btn.dataset.val;autoSave();
}
function setHangupDig(btn){
btn.parentElement.querySelectorAll('.dc-dig').forEach(b=>b.classList.remove('active'));
btn.classList.add('active');hangupDigit=btn.dataset.val;autoSave();
}

function countNums(){
const t=$('numbers').value.trim();
const n=t?t.split(/[\\n,]+/).filter(s=>s.trim()).length:0;
$('p1-numcount').textContent=n+' number'+(n!==1?'s':'');
}
$('numbers').addEventListener('input',countNums);

function loadCSV(inp){
if(!inp.files[0])return;
const r=new FileReader();
r.onload=function(){
const lines=r.result.split(/[\\n,]+/).map(s=>s.trim().replace(/[^0-9+]/g,'')).filter(s=>s.length>=7);
$('numbers').value=($('numbers').value.trim()?$('numbers').value.trim()+'\\n':'')+lines.join('\\n');
countNums();
};r.readAsText(inp.files[0]);inp.value='';
}

function addTTSStep(){
const box=$('tts-steps');
const n=box.children.length+1;
const d=document.createElement('div');d.className='tts-step';d.dataset.step=n;
d.innerHTML='<div class="tts-step-head"><span class="tts-step-num">'+n+'</span><span class="sl" style="margin:0">tts message</span><button class="tts-step-del" onclick="removeTTSStep(this)" title="remove step">&times;</button></div><textarea placeholder="message for step '+n+' (optional)..."></textarea><div class="tts-dtmf"><div style="flex:1"><div class="sl">on dtmf</div><select><option value="">auto-timer</option><option value="any">any key</option><option value="1">1</option><option value="2">2</option><option value="3">3</option></select></div><div style="flex:1"><div class="sl">then</div><select><option value="hangup">hang up</option><option value="next">next step</option><option value="transfer">transfer to agent</option></select></div></div>';
box.appendChild(d);
}
function removeTTSStep(btn){
const step=btn.closest('.tts-step');step.remove();
document.querySelectorAll('#tts-steps .tts-step').forEach((s,i)=>{s.dataset.step=i+1;s.querySelector('.tts-step-num').textContent=i+1});
}

function toggleAdv(){
$('adv-tog').classList.toggle('open');
$('adv-body').classList.toggle('open');
}

function getTTSSteps(){
const steps=[];
document.querySelectorAll('#tts-steps .tts-step').forEach(s=>{
const msg=s.querySelector('textarea').value.trim();
const sels=s.querySelectorAll('select');
steps.push({message:msg,dtmf:sels[0].value,action:sels[1].value});
});
return steps;
}

function startP1(){
const nums=$('numbers').value.trim();
if(!nums){alert('add numbers first');return}
$('p1-start').disabled=true;$('p1-start').textContent='calling...';
$('p1-pause').disabled=false;
p1Running=true;
const numList=nums.split(/[\\n,]+/).map(s=>s.trim()).filter(Boolean);
initP1Dashboard(numList);

const payload={...sipCfg(),numbers:nums,caller_id:$('p1-cid').value||$('cid').value,mode:p1Mode};
const steps=getTTSSteps();
payload.message=steps[0]?steps[0].message:'';
payload.voice=$('voice').value;
payload.pause=$('pause').value;
if(p1Mode==='tts'){
payload.response=steps[1]?steps[1].message:'';
} else {
payload.trigger_digit=triggerDigit;
payload.hangup_digit=hangupDigit;
payload.dc_play=dcPlay;
if(dcPlay==='tts')payload.dc_tts_msg=$('dc-tts-msg').value;
}

fetch('/api/call',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
.then(r=>r.json()).then(d=>{if(d.error){alert(d.error);resetP1Buttons();return}
startP1Audio()})
.catch(e=>{alert(e);resetP1Buttons()});
}

function stopP1(){
fetch('/api/p1-stop',{method:'POST'});
$('p1-pause').textContent='stopping...';$('p1-pause').disabled=true;
}

function resetP1Buttons(){
$('p1-start').disabled=false;$('p1-start').innerHTML='<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-1px;margin-right:4px"><polygon points="5 3 19 12 5 21"/></svg>start';
$('p1-pause').disabled=true;$('p1-pause').innerHTML='<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-1px;margin-right:4px"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>stop';
p1Running=false;
}

/* p1 dashboard */
function initP1Dashboard(nums){
p1Rows=nums.map(n=>({number:n,status:'pending',dtmf:'',dur:'',time:''}));
$('ps-pending').textContent=nums.length;
$('ps-dialing').textContent=0;$('ps-answered').textContent=0;$('ps-completed').textContent=0;$('ps-failed').textContent=0;
$('p1-pct').textContent='0%';$('p1-bar').style.width='0';
$('p1-total-label').textContent=nums.length+' total';
$('p1-empty').style.display='none';
renderP1Table();
}

function updateP1Stats(){
let pending=0,dialing=0,answered=0,completed=0,failed=0;
p1Rows.forEach(r=>{
if(r.status==='pending')pending++;
else if(r.status==='calling')dialing++;
else if(r.status==='answered'||r.status==='screening'){answered++;completed++}
else if(r.status==='failed'||r.status==='disconnected'){failed++;completed++}
});
$('ps-pending').textContent=pending;$('ps-dialing').textContent=dialing;
$('ps-answered').textContent=answered;$('ps-completed').textContent=completed;$('ps-failed').textContent=failed;
const pct=p1Rows.length?(completed/p1Rows.length*100):0;
$('p1-pct').textContent=Math.round(pct)+'%';
$('p1-bar').style.width=pct.toFixed(1)+'%';
}

function renderP1Table(){
const tb=$('p1-tbody');tb.innerHTML='';
const show=p1Rows.filter(r=>p1Filter==='all'||r.status===p1Filter||(p1Filter==='calling'&&r.status==='calling'));
if(!show.length){$('p1-empty').style.display='';$('p1-empty').textContent='no matching calls';return}
$('p1-empty').style.display='none';
show.forEach(r=>{
const tr=document.createElement('tr');
const sc=r.status==='answered'?'s-ok':r.status==='screening'?'s-warn':r.status==='disconnected'?'s-fail':r.status==='failed'?'s-fail':r.status==='calling'?'s-call':'s-pending';
tr.innerHTML='<td class="num">'+r.number+'</td><td class="'+sc+'">'+r.status+'</td><td>'+(r.dtmf||'—')+'</td><td>'+(r.dur||'—')+'</td><td>'+(r.time||'—')+'</td>';
tb.appendChild(tr);
});
}

function setP1Filter(f,btn){
p1Filter=f;
document.querySelectorAll('.p1-filt').forEach(b=>b.classList.toggle('active',b===btn));
renderP1Table();
}

/* p1 audio — ring-buffer playback with low-pass filter */
function startP1Audio(){
stopP1Audio();
const proto=location.protocol==='https:'?'wss:':'ws:';
p1AudioWs=new WebSocket(proto+'//'+location.host+'/ws/p1audio');
p1AudioWs.binaryType='arraybuffer';
p1Ctx=new AudioContext();
const SR=p1Ctx.sampleRate;
const RATIO=SR/8000;
const ULAW=new Float32Array(256);
for(let i=0;i<256;i++){let b=~i&0xFF;let s=((b&0x0F)<<3)+0x84;s<<=(b>>4)&7;if(b&0x80)s=-s;ULAW[i]=s/32768}
const RING=16000;
const ringIn=new Float32Array(RING);
const ringOut=new Float32Array(RING);
let riW=0,riR=0,roW=0,roR=0;
let inPh=0,outPh=0;
function avail(w,r){return(w-r+RING)%RING}
const lpf=p1Ctx.createBiquadFilter();
lpf.type='lowpass';lpf.frequency.value=3400;lpf.Q.value=0.707;
const lpf2=p1Ctx.createBiquadFilter();
lpf2.type='lowpass';lpf2.frequency.value=3800;lpf2.Q.value=0.707;
lpf.connect(lpf2);lpf2.connect(p1Ctx.destination);
const proc=p1Ctx.createScriptProcessor(2048,0,1);
proc.connect(lpf);
proc.onaudioprocess=function(e){
const out=e.outputBuffer.getChannelData(0);
for(let i=0;i<out.length;i++){
let s=0;
if(avail(riW,riR)>1){
const i0=riR,i1=(riR+1)%RING;
s+=ringIn[i0]*(1-inPh)+ringIn[i1]*inPh;
inPh+=1/RATIO;
while(inPh>=1){riR=(riR+1)%RING;inPh-=1}}
if(avail(roW,roR)>1){
const o0=roR,o1=(roR+1)%RING;
s+=0.5*(ringOut[o0]*(1-outPh)+ringOut[o1]*outPh);
outPh+=1/RATIO;
while(outPh>=1){roR=(roR+1)%RING;outPh-=1}}
out[i]=s>1?1:s<-1?-1:s}};
p1AudioWs.onmessage=function(ev){
if(!(ev.data instanceof ArrayBuffer)||p1Muted)return;
const raw=new Uint8Array(ev.data);if(raw.length<2)return;
const dir=raw[0];const ulaw=raw.subarray(1);
if(dir===1){for(let i=0;i<ulaw.length;i++){ringOut[roW]=ULAW[ulaw[i]];roW=(roW+1)%RING}}
else{for(let i=0;i<ulaw.length;i++){ringIn[riW]=ULAW[ulaw[i]];riW=(riW+1)%RING}}};
p1AudioWs.onerror=function(){};p1AudioWs.onclose=function(){p1AudioWs=null};
p1Proc=proc;
}
function toggleP1Mute(){
p1Muted=!p1Muted;
const btn=$('p1-mute');
btn.textContent=p1Muted?'unmute':'mute';
btn.classList.toggle('muted',p1Muted);
}
function stopP1Audio(){
if(p1AudioWs){try{p1AudioWs.close()}catch(e){}}p1AudioWs=null;
if(p1Proc){try{p1Proc.disconnect()}catch(e){}}p1Proc=null;
if(p1Ctx){try{p1Ctx.close()}catch(e){}}p1Ctx=null}

/* agent clock-in */
function toggleClockIn(){
if(agentClockedIn){clockOut()}else{clockIn()}
}
async function clockIn(){
const proto=location.protocol==='https:'?'wss:':'ws:';
agentWs=new WebSocket(proto+'//'+location.host+'/ws/agent');
agentWs.binaryType='arraybuffer';
agentCtx=new AudioContext({sampleRate:8000});agentNext=0;
agentWs.onopen=async function(){
agentClockedIn=true;
$('clock-btn').className='clock-btn in';
$('clock-label').textContent='clocked in';
const constraints={audio:$('mic-sel').value?{deviceId:{exact:$('mic-sel').value}}:true};
try{agentMicStream=await navigator.mediaDevices.getUserMedia(constraints)}catch(e){return}
agentMicCtx=new AudioContext();
const src=agentMicCtx.createMediaStreamSource(agentMicStream);
agentMicProc=agentMicCtx.createScriptProcessor(4096,1,1);
const ratio=agentMicCtx.sampleRate/8000;
agentMicProc.onaudioprocess=e=>{
if(!agentWs||agentWs.readyState!==1)return;
const inp=e.inputBuffer.getChannelData(0),len=Math.floor(inp.length/ratio);
const ul=new Uint8Array(len);
for(let i=0;i<len;i++)ul[i]=ulE(inp[Math.floor(i*ratio)]);
for(let o=0;o+160<=ul.length;o+=160)agentWs.send(ul.slice(o,o+160).buffer);
};
src.connect(agentMicProc);agentMicProc.connect(agentMicCtx.destination);
};
agentWs.onmessage=function(ev){
if(typeof ev.data==='string'){
try{const m=JSON.parse(ev.data);
if(m.type==='bridge'){showBridgeAlert(m)}}catch(e){}
return}
if(!(ev.data instanceof ArrayBuffer))return;
const ulaw=new Uint8Array(ev.data);
const pcm=new Float32Array(ulaw.length);
for(let i=0;i<ulaw.length;i++){let b=~ulaw[i]&0xFF;let s=((b&0x0F)<<3)+0x84;s<<=(b>>4)&7;if(b&0x80)s=-s;pcm[i]=s/32768}
const buf=agentCtx.createBuffer(1,pcm.length,8000);
buf.getChannelData(0).set(pcm);
const src=agentCtx.createBufferSource();src.buffer=buf;src.connect(agentCtx.destination);
const now=agentCtx.currentTime;
if(agentNext<now)agentNext=now;
if(agentNext>now+0.15)agentNext=now+0.01;
src.start(agentNext);agentNext+=buf.duration;
};
agentWs.onerror=function(){};
agentWs.onclose=function(){agentWs=null;clockOutUI()};
}
function showBridgeAlert(data){
const d=typeof data==='object'?data:{number:data};
const num=d.number||'unknown';
const cid=d.caller_id||$('cid')?.value||'—';
const digits=d.digits||'—';
const ts=d.ts||new Date().toLocaleTimeString([],{hour:'numeric',minute:'2-digit'});
const el=document.createElement('div');el.className='bridge-toast';
el.innerHTML=`<div class="bt-bar"></div>
<div class="bt-body">
<div class="bt-head"><span class="bt-label">incoming transfer</span><span class="bt-time">${ts}</span><button class="bt-x" onclick="this.closest('.bridge-toast').remove()">&times;</button></div>
<div class="bt-num">${num}</div>
<div class="bt-details">
<span class="bt-k">caller id</span><span class="bt-v">${cid}</span>
<span class="bt-k">dtmf</span><span class="bt-v">${digits}</span>
<span class="bt-k">status</span><span class="bt-v" style="color:var(--ac)">bridging</span>
</div>
</div>
<div class="bt-footer"><button class="bt-btn" onclick="this.closest('.bridge-toast').remove()">dismiss</button></div>`;
document.body.appendChild(el);
setTimeout(()=>{if(el.parentNode){el.style.transition='opacity .3s';el.style.opacity='0';setTimeout(()=>el.remove(),300)}},20000);
}
function clockOut(){
if(agentMicProc){agentMicProc.disconnect();agentMicProc=null}
if(agentMicStream){agentMicStream.getTracks().forEach(t=>t.stop());agentMicStream=null}
if(agentMicCtx){agentMicCtx.close();agentMicCtx=null}
if(agentWs){try{agentWs.close()}catch(e){}}agentWs=null;
if(agentCtx){try{agentCtx.close()}catch(e){}}agentCtx=null;agentNext=0;
clockOutUI();
}
function clockOutUI(){
agentClockedIn=false;
$('clock-btn').className='clock-btn out';
$('clock-label').textContent='clock in';
}

/* SSE */
const sse=new EventSource('/api/events');
sse.addEventListener('p1_status',e=>{
const d=JSON.parse(e.data);
$('p1-status-msg').textContent=d.msg;
$('p1-pulse').style.display=d.msg==='ready'?'none':'';
});
sse.addEventListener('call_start',e=>{
const d=JSON.parse(e.data);
$('p1-start').disabled=true;$('p1-start').textContent='calling '+d.i+'/'+d.n;
const row=p1Rows.find(r=>r.number===d.number&&r.status==='pending');
if(row){row.status='calling';row.time=d.ts}
updateP1Stats();renderP1Table();
});
sse.addEventListener('call_end',e=>{
const d=JSON.parse(e.data);
const row=p1Rows.find(r=>r.number===d.number&&r.status==='calling');
if(row){row.status=d.status;row.dtmf=d.dtmf||'';row.time=d.ts}
updateP1Stats();renderP1Table();loadStats();
});
sse.addEventListener('agent_bridge',e=>{
const d=JSON.parse(e.data);showBridgeAlert(d);
});
sse.addEventListener('batch_done',()=>{
resetP1Buttons();loadHistory();stopP1Audio();
$('p1-status-msg').textContent='ready';$('p1-pulse').style.display='none';
});

/* stats */
function loadStats(){
fetch('/api/history').then(r=>r.json()).then(rows=>{
let ok=0,fail=0;rows.forEach(r=>{if(r.status==='answered')ok++;else if(r.status==='failed')fail++});
$('st-total').textContent=rows.length;$('st-ok').textContent=ok;$('st-fail').textContent=fail;
});
}
loadStats();

/* restore p1 dashboard state on refresh */
fetch('/api/p1-state').then(r=>r.json()).then(st=>{
if(st.rows&&st.rows.length){
p1Rows=st.rows.map(r=>({number:r.number,status:r.status,dtmf:r.dtmf||'',dur:'',time:r.ts||''}));
$('p1-empty').style.display='none';
updateP1Stats();renderP1Table();
if(st.running){
p1Running=true;
$('p1-start').disabled=true;$('p1-start').textContent='running...';
$('p1-pause').disabled=false;
}
}
if(st.status_msg&&st.status_msg!=='ready'){
$('p1-status-msg').textContent=st.status_msg;
$('p1-pulse').style.display='';
}
}).catch(()=>{});

fetch('/api/agent-status').then(r=>r.json()).then(d=>{
if(d.clocked_in&&!agentClockedIn)clockIn();
}).catch(()=>{});

/* call history */
const REDIAL_SVG='<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 4v6h6"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>';
function loadHistory(){
fetch('/api/history').then(r=>r.json()).then(rows=>{
const h=$('history');h.innerHTML='';
if(!rows.length){h.innerHTML='<div class="empty">no calls yet</div>';return}
rows.forEach(r=>{
const d=document.createElement('div');d.className='lr';
const c=r.status==='answered'?'s-ok':r.status==='failed'?'s-fail':'s-call';
const src=r.source==='p1bot'?'<span style="color:var(--dm);font-size:.66rem;margin-left:4px">p1</span>':'';
const t=r.created_at?r.created_at.split(' ').pop().slice(0,5):'';
d.innerHTML='<span><span class="n">'+r.number+'</span> <span class="'+c+'">'+r.status+'</span>'+src+'</span><span style="display:flex;align-items:center;gap:6px"><span class="m">'+t+'</span><button class="redial" data-num="'+r.number+'" title="redial">'+REDIAL_SVG+'</button></span>';
d.querySelector('.redial').onclick=function(){redial(this.dataset.num)};
h.appendChild(d);
});
});
}
loadHistory();
</script>
</body></html>"""


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True, debug=False)
