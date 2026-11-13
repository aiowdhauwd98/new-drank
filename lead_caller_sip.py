"""
lead_caller_sip.py — raw SIP lead caller
direct UDP sockets, no pyVoIP — headers matched to PJSIP format.
dials leads, waits after pickup, plays TTS via RTP.

deps: pip install edge-tts miniaudio
"""

import argparse
import asyncio
import audioop
import csv
import hashlib
import random
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

try:
    import miniaudio
except ImportError:
    sys.exit("pip install miniaudio")

try:
    import edge_tts
except ImportError:
    sys.exit("pip install edge-tts")

SAMPLE_RATE = 8000
FRAME_SIZE = 160   # 20ms at 8kHz
CRLF = "\r\n"
DEBUG = True


# ── TTS + audio ────────────────────────────────────────────────

def generate_tts(text: str, voice: str, out_path: Path):
    async def _gen():
        comm = edge_tts.Communicate(text, voice)
        await comm.save(str(out_path))
    asyncio.run(_gen())
    print(f"[*] tts saved: {out_path}")


def mp3_to_ulaw(mp3_path: Path) -> bytes:
    decoded = miniaudio.decode_file(
        str(mp3_path),
        output_format=miniaudio.SampleFormat.SIGNED16,
        nchannels=1,
        sample_rate=SAMPLE_RATE,
    )
    pcm = bytes(decoded.samples)
    ulaw = audioop.lin2ulaw(pcm, 2)
    print(f"[*] audio: {len(pcm)} bytes pcm -> {len(ulaw)} bytes ulaw "
          f"({len(ulaw) / SAMPLE_RATE:.1f}s)")
    return ulaw


def normalize_number(num: str) -> str:
    """Clean number to 11-digit US format (1XXXXXXXXXX) — matching MicroSIP."""
    num = re.sub(r"[\s\-\(\)\.]+", "", num)
    if num.startswith("+"):
        num = num[1:]
    if len(num) == 10 and num[0] != "1":
        num = "1" + num
    return num


def is_us_number(num: str) -> bool:
    """Check if a normalized number is a valid US number."""
    n = normalize_number(num)
    return len(n) == 11 and n.startswith("1") and n[1] in "2345678"


def load_leads(path: str) -> list[str]:
    p = Path(path)
    numbers = []
    if p.suffix.lower() == ".csv":
        with open(p, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if row:
                    num = row[0].strip()
                    if num and num[0] in "0123456789+":
                        numbers.append(normalize_number(num))
    else:
        for line in p.read_text(encoding="utf-8").splitlines():
            num = line.strip()
            if num and num[0] in "0123456789+":
                numbers.append(normalize_number(num))
    return numbers


# ── SIP helpers ─────────────────────────────────────────────────

def gen_branch():
    return "z9hG4bKPj" + "%032x" % random.getrandbits(128)

def gen_tag():
    return "%032x" % random.getrandbits(128)

def gen_call_id():
    return "%032x" % random.getrandbits(128)

def gen_cnonce():
    return "%032x" % random.getrandbits(128)

def gen_sdp(local_ip: str, rtp_port: int, session_id: int) -> str:
    ssrc = random.getrandbits(32)
    cname = "%016x" % random.getrandbits(64)
    rtcp_port = rtp_port + 1
    sdp  = "v=0" + CRLF
    sdp += f"o=- {session_id} {session_id} IN IP4 {local_ip}" + CRLF
    sdp += "s=pjmedia" + CRLF
    sdp += "b=AS:84" + CRLF
    sdp += "t=0 0" + CRLF
    sdp += "a=X-nat:0" + CRLF
    sdp += f"m=audio {rtp_port} RTP/AVP 8 0 101" + CRLF
    sdp += f"c=IN IP4 {local_ip}" + CRLF
    sdp += "b=TIAS:64000" + CRLF
    sdp += f"a=rtcp:{rtcp_port} IN IP4 {local_ip}" + CRLF
    sdp += "a=sendrecv" + CRLF
    sdp += "a=rtpmap:8 PCMA/8000" + CRLF
    sdp += "a=rtpmap:0 PCMU/8000" + CRLF
    sdp += "a=rtpmap:101 telephone-event/8000" + CRLF
    sdp += "a=fmtp:101 0-16" + CRLF
    sdp += f"a=ssrc:{ssrc} cname:{cname}" + CRLF
    return sdp

def digest_response(username, realm, password, method, uri, nonce,
                    qop=None, cnonce=None, nc=None):
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    if qop:
        return hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
        ).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

def parse_www_authenticate(header_val):
    realm = re.search(r'realm="([^"]*)"', header_val)
    nonce = re.search(r'nonce="([^"]*)"', header_val)
    opaque = re.search(r'opaque="([^"]*)"', header_val)
    qop = re.search(r'qop="([^"]*)"', header_val)
    return {
        "realm": realm.group(1) if realm else "",
        "nonce": nonce.group(1) if nonce else "",
        "opaque": opaque.group(1) if opaque else "",
        "qop": qop.group(1) if qop else "",
    }

def build_auth_header(username, realm, nonce, uri, response_hash,
                      opaque="", qop="", cnonce="", nc=""):
    parts = [
        f'Digest username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response_hash}"',
        'algorithm=MD5',
    ]
    if cnonce:
        parts.append(f'cnonce="{cnonce}"')
    if opaque:
        parts.append(f'opaque="{opaque}"')
    if qop:
        parts.append(f'qop={qop}')
    if nc:
        parts.append(f'nc={nc}')
    return ", ".join(parts)

def parse_sip_message(data: bytes):
    """Parse any SIP message — request or response.
    Returns (type, code_or_method, headers, body).
    type is 'response' or 'request'.
    """
    text = data.decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    if not lines:
        return None, None, {}, ""

    first = lines[0]
    msg_type = None
    code_or_method = None

    m_resp = re.match(r"SIP/2\.0\s+(\d+)\s+(.*)", first)
    m_req = re.match(r"^(OPTIONS|INVITE|ACK|BYE|CANCEL|NOTIFY|INFO|REFER|MESSAGE|UPDATE|SUBSCRIBE|REGISTER)\s+", first)

    if m_resp:
        msg_type = "response"
        code_or_method = int(m_resp.group(1))
    elif m_req:
        msg_type = "request"
        code_or_method = m_req.group(1)
    else:
        return None, None, {}, ""

    headers = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line == "":
            body_start = i + 1
            break
        if ":" in line:
            key, val = line.split(":", 1)
            k = key.strip()
            headers[k] = val.strip()
            headers.setdefault(k.lower(), val.strip())
    body = "\r\n".join(lines[body_start:]) if body_start else ""
    return msg_type, code_or_method, headers, body


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


ALLOW = "PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS"
SUPPORTED = "replaces, 100rel, timer, norefersub"


# ── RTP ──────────────────────────────────────────────────────

def build_rtp_packet(payload: bytes, seq: int, timestamp: int, ssrc: int,
                     payload_type: int = 0) -> bytes:
    byte0 = 0x80
    byte1 = payload_type & 0x7F
    header = struct.pack("!BBHII", byte0, byte1, seq & 0xFFFF, timestamp, ssrc)
    return header + payload


# ── SIP client ──────────────────────────────────────────────

class SIPCall:
    def __init__(self, server, port, username, password, caller_id, local_ip=None, local_port=5080):
        self.server = server
        self.port = port
        self.server_ip = socket.gethostbyname(server)
        self.username = username
        self.password = password
        self.caller_id = caller_id
        self.local_ip = local_ip or get_local_ip()
        self.local_port = local_port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.local_ip, self.local_port))
        self.sock.settimeout(10)

        self.cseq = random.randint(10000, 60000)
        self.registered = False

    def _send(self, msg: str):
        if DEBUG:
            first = msg.split("\r\n")[0]
            print(f"  >> {first}")
        self.sock.sendto(msg.encode(), (self.server_ip, self.port))

    def _recv(self, timeout=10):
        self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(65535)
            return data, addr
        except socket.timeout:
            return None, None

    def _recv_response(self, timeout=10):
        """Read from socket, handle OPTIONS requests, return SIP responses."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            data, addr = self._recv(timeout=min(remaining, 2))
            if not data:
                continue

            msg_type, code_or_method, headers, body = parse_sip_message(data)

            if msg_type == "request":
                self._handle_incoming_request(code_or_method, headers, data, addr)
                continue

            if msg_type == "response":
                return code_or_method, headers, body

        return None, {}, ""

    def _handle_incoming_request(self, method, headers, raw_data, addr):
        """Respond to incoming SIP requests (OPTIONS, etc.)."""
        if method == "OPTIONS":
            via = headers.get("Via", headers.get("via", ""))
            from_hdr = headers.get("From", headers.get("from", ""))
            to_hdr = headers.get("To", headers.get("to", ""))
            call_id = headers.get("Call-ID", headers.get("call-id", ""))
            cseq = headers.get("CSeq", headers.get("cseq", ""))

            # add tag to To if not present
            if "tag=" not in to_hdr:
                to_hdr += f";tag={gen_tag()}"

            resp  = "SIP/2.0 200 OK" + CRLF
            resp += f"Via: {via}" + CRLF
            resp += f"Call-ID: {call_id}" + CRLF
            resp += f"From: {from_hdr}" + CRLF
            resp += f"To: {to_hdr}" + CRLF
            resp += f"CSeq: {cseq}" + CRLF
            resp += f"Allow: {ALLOW}" + CRLF
            resp += f"Supported: {SUPPORTED}" + CRLF
            resp += f"User-Agent: Phantom/1.0.0" + CRLF
            resp += "Content-Length:  0" + CRLF + CRLF

            self.sock.sendto(resp.encode(), addr)
            print(f"    [*] responded 200 OK to OPTIONS from {addr}")
        else:
            print(f"    [?] incoming {method} from {addr} (ignored)")

    def _drain_and_handle(self, seconds=1.0):
        """Drain socket for a period, responding to any incoming requests."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            data, addr = self._recv(timeout=min(remaining, 0.5))
            if not data:
                continue
            msg_type, code_or_method, headers, body = parse_sip_message(data)
            if msg_type == "request":
                self._handle_incoming_request(code_or_method, headers, data, addr)

    def _next_cseq(self):
        self.cseq += 1
        return self.cseq

    def register(self):
        branch = gen_branch()
        tag = gen_tag()
        call_id = gen_call_id()
        cseq = self._next_cseq()

        reg  = f"REGISTER sip:{self.server} SIP/2.0" + CRLF
        reg += f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};rport;branch={branch}" + CRLF
        reg += "Max-Forwards: 70" + CRLF
        reg += f'From: "{self.caller_id}" <sip:{self.username}@{self.server}>;tag={tag}' + CRLF
        reg += f'To: "{self.caller_id}" <sip:{self.username}@{self.server}>' + CRLF
        reg += f"Call-ID: {call_id}" + CRLF
        reg += f"CSeq: {cseq} REGISTER" + CRLF
        reg += f"User-Agent: Phantom/1.0.0" + CRLF
        reg += f'Contact: "{self.caller_id}" <sip:{self.username}@{self.local_ip}:{self.local_port};ob>' + CRLF
        reg += "Expires: 300" + CRLF
        reg += f"Allow: {ALLOW}" + CRLF
        reg += "Content-Length:  0" + CRLF + CRLF

        print(f"[*] REGISTER -> {self.server}:{self.port}")
        self._send(reg)

        code, hdrs, _ = self._recv_response()
        if code is None:
            print("[!] no response to REGISTER")
            return False

        print(f"[*] REGISTER response: {code}")

        if code == 401:
            www_auth = hdrs.get("WWW-Authenticate", hdrs.get("www-authenticate", ""))
            auth_params = parse_www_authenticate(www_auth)
            if not auth_params["nonce"]:
                print("[!] no nonce in 401")
                return False

            uri = f"sip:{self.server}"
            cnonce = gen_cnonce()
            nc = "00000001"
            qop = auth_params["qop"].split(",")[0].strip() if auth_params["qop"] else ""

            response_hash = digest_response(
                self.username, auth_params["realm"], self.password,
                "REGISTER", uri, auth_params["nonce"],
                qop=qop or None, cnonce=cnonce if qop else None,
                nc=nc if qop else None,
            )

            auth_value = build_auth_header(
                self.username, auth_params["realm"], auth_params["nonce"],
                uri, response_hash,
                opaque=auth_params["opaque"], qop=qop,
                cnonce=cnonce if qop else "", nc=nc if qop else "",
            )

            branch2 = gen_branch()
            cseq2 = self._next_cseq()

            reg2  = f"REGISTER sip:{self.server} SIP/2.0" + CRLF
            reg2 += f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};rport;branch={branch2}" + CRLF
            reg2 += "Max-Forwards: 70" + CRLF
            reg2 += f'From: "{self.caller_id}" <sip:{self.username}@{self.server}>;tag={tag}' + CRLF
            reg2 += f'To: "{self.caller_id}" <sip:{self.username}@{self.server}>' + CRLF
            reg2 += f"Call-ID: {call_id}" + CRLF
            reg2 += f"CSeq: {cseq2} REGISTER" + CRLF
            reg2 += f"User-Agent: Phantom/1.0.0" + CRLF
            reg2 += f'Contact: "{self.caller_id}" <sip:{self.username}@{self.local_ip}:{self.local_port};ob>' + CRLF
            reg2 += "Expires: 300" + CRLF
            reg2 += f"Allow: {ALLOW}" + CRLF
            reg2 += f"Authorization: {auth_value}" + CRLF
            reg2 += "Content-Length:  0" + CRLF + CRLF

            print(f"[*] REGISTER (auth) -> {self.server}")
            self._send(reg2)

            code2, _, _ = self._recv_response()
            if code2 is None:
                print("[!] no response to auth REGISTER")
                return False
            print(f"[*] REGISTER auth response: {code2}")
            if code2 == 200:
                self.registered = True
                print("[+] registered")
                # drain and respond to OPTIONS qualify check
                print("[*] waiting for qualify OPTIONS ...")
                self._drain_and_handle(seconds=2.0)
                return True
            else:
                print(f"[!] registration failed: {code2}")
                return False

        elif code == 200:
            self.registered = True
            print("[+] registered (no auth needed)")
            self._drain_and_handle(seconds=2.0)
            return True
        else:
            print(f"[!] unexpected REGISTER response: {code}")
            return False

    def invite(self, number: str, rtp_port: int, rtp_sock=None, cancel_event=None):
        """Send INVITE, handle auth challenge, return (code, headers, body, call_state)."""
        session_id = random.getrandbits(31)
        sdp = gen_sdp(self.local_ip, rtp_port, session_id)
        branch = gen_branch()
        tag = gen_tag()
        call_id = gen_call_id()
        cseq = self._next_cseq()

        inv  = f"INVITE sip:{number}@{self.server} SIP/2.0" + CRLF
        inv += f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};rport;branch={branch}" + CRLF
        inv += "Max-Forwards: 70" + CRLF
        inv += f'From: "{self.caller_id}" <sip:{self.username}@{self.server}>;tag={tag}' + CRLF
        inv += f"To: <sip:{number}@{self.server}>" + CRLF
        inv += f'Contact: "{self.caller_id}" <sip:{self.username}@{self.local_ip}:{self.local_port};ob>' + CRLF
        inv += f"Call-ID: {call_id}" + CRLF
        inv += f"CSeq: {cseq} INVITE" + CRLF
        inv += f"Allow: {ALLOW}" + CRLF
        inv += f"Supported: {SUPPORTED}" + CRLF
        inv += "Session-Expires: 1800" + CRLF
        inv += "Min-SE: 90" + CRLF
        inv += "User-Agent: Phantom/1.0.0" + CRLF
        inv += "Content-Type: application/sdp" + CRLF
        inv += f"Content-Length:   {len(sdp)}" + CRLF + CRLF
        inv += sdp

        if DEBUG:
            print(f"\n--- INVITE packet ---")
            print(inv)
            print(f"--- end INVITE ---\n")

        print(f"[*] INVITE {number} -> {self.server}")
        self._send(inv)

        invite_ctx = {
            "call_id": call_id,
            "from_tag": tag,
            "to_tag": "",
            "branch": branch,
            "cseq": cseq,
            "number": number,
            "rtp_port": rtp_port,
            "session_id": session_id,
        }

        return self._handle_invite_responses(invite_ctx, sdp, rtp_sock, cancel_event=cancel_event)

    def _handle_invite_responses(self, ctx, sdp, rtp_sock=None, cancel_event=None):
        """Read SIP responses until final (2xx/3xx/4xx/5xx/6xx) or timeout."""
        deadline = time.time() + 60
        remote_rtp = None
        early_media_thread = None
        early_media_stop = threading.Event()

        while time.time() < deadline:
            if cancel_event and cancel_event.is_set():
                early_media_stop.set()
                print("[!] cancel requested — sending CANCEL")
                self._send_cancel(ctx)
                return -1, None, None

            remaining = deadline - time.time()
            if remaining <= 0:
                break

            data, addr = self._recv(timeout=min(remaining, 1))
            if not data:
                continue

            msg_type, code_or_method, hdrs, body = parse_sip_message(data)

            # handle incoming requests (OPTIONS, etc.)
            if msg_type == "request":
                self._handle_incoming_request(code_or_method, hdrs, data, addr)
                continue

            if msg_type != "response" or code_or_method is None:
                continue

            # filter by Call-ID — ignore stale responses from previous calls
            resp_call_id = hdrs.get("Call-ID", hdrs.get("call-id", ""))
            if resp_call_id != ctx["call_id"]:
                print(f"    [stale] ignoring response with wrong Call-ID")
                continue

            code = code_or_method
            print(f"    <- {code}")

            if DEBUG and code >= 400:
                text = data.decode("utf-8", errors="replace")
                print(f"    --- full {code} response ---")
                print(text)
                print(f"    --- end ---")

            if code == 100:
                continue
            if code in (180, 183):
                to_hdr = hdrs.get("To", hdrs.get("to", ""))
                tag_m = re.search(r'tag=([^\s;]+)', to_hdr)
                if tag_m:
                    ctx["to_tag"] = tag_m.group(1)
                elapsed = time.time() - (deadline - 60)
                print(f"    [{code} at {elapsed:.1f}s] ringing/progress")

                if body and rtp_sock and not early_media_thread:
                    c_m = re.search(r'c=IN IP4 (\S+)', body)
                    m_m = re.search(r'm=audio (\d+)', body)
                    if c_m and m_m:
                        remote_rtp = (c_m.group(1), int(m_m.group(1)))
                        print(f"    [*] early media -> {remote_rtp[0]}:{remote_rtp[1]}")

                        if DEBUG:
                            print(f"    [*] 183 SDP:\n{body}")

                        def _send_early_media(sock, addr, stop_evt):
                            ssrc = random.getrandbits(32)
                            seq = random.randint(0, 0xFFFF)
                            ts = 0
                            silence = bytes([0xFF] * FRAME_SIZE)
                            while not stop_evt.is_set():
                                pkt = build_rtp_packet(silence, seq, ts, ssrc, 0)
                                try:
                                    sock.sendto(pkt, addr)
                                except Exception:
                                    break
                                seq = (seq + 1) & 0xFFFF
                                ts += FRAME_SIZE
                                stop_evt.wait(0.02)

                        early_media_thread = threading.Thread(
                            target=_send_early_media,
                            args=(rtp_sock, remote_rtp, early_media_stop),
                            daemon=True,
                        )
                        early_media_thread.start()
                continue

            if code in (401, 407):
                auth_hdr_key = "WWW-Authenticate" if code == 401 else "Proxy-Authenticate"
                www_auth = hdrs.get(auth_hdr_key, hdrs.get(auth_hdr_key.lower(), ""))
                auth_params = parse_www_authenticate(www_auth)
                if not auth_params["nonce"]:
                    print("[!] no nonce in INVITE auth challenge")
                    return code, None, None

                uri = f"sip:{ctx['number']}@{self.server}"
                cnonce = gen_cnonce()
                nc = "00000001"
                qop = auth_params["qop"].split(",")[0].strip() if auth_params["qop"] else ""

                response_hash = digest_response(
                    self.username, auth_params["realm"], self.password,
                    "INVITE", uri, auth_params["nonce"],
                    qop=qop or None, cnonce=cnonce if qop else None,
                    nc=nc if qop else None,
                )

                auth_header_name = "Proxy-Authorization" if code == 407 else "Authorization"
                auth_value = build_auth_header(
                    self.username, auth_params["realm"], auth_params["nonce"],
                    uri, response_hash,
                    opaque=auth_params["opaque"], qop=qop,
                    cnonce=cnonce if qop else "", nc=nc if qop else "",
                )

                self._send_ack(ctx, hdrs)

                branch2 = gen_branch()
                cseq2 = self._next_cseq()
                ctx["branch"] = branch2
                ctx["cseq"] = cseq2

                sdp2 = gen_sdp(self.local_ip, ctx["rtp_port"], ctx["session_id"])

                inv2  = f"INVITE sip:{ctx['number']}@{self.server} SIP/2.0" + CRLF
                inv2 += f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};rport;branch={branch2}" + CRLF
                inv2 += "Max-Forwards: 70" + CRLF
                inv2 += f'From: "{self.caller_id}" <sip:{self.username}@{self.server}>;tag={ctx["from_tag"]}' + CRLF
                inv2 += f'To: <sip:{ctx["number"]}@{self.server}>' + CRLF
                inv2 += f'Contact: "{self.caller_id}" <sip:{self.username}@{self.local_ip}:{self.local_port};ob>' + CRLF
                inv2 += f'Call-ID: {ctx["call_id"]}' + CRLF
                inv2 += f"CSeq: {cseq2} INVITE" + CRLF
                inv2 += f"Allow: {ALLOW}" + CRLF
                inv2 += f"Supported: {SUPPORTED}" + CRLF
                inv2 += "Session-Expires: 1800" + CRLF
                inv2 += "Min-SE: 90" + CRLF
                inv2 += "User-Agent: Phantom/1.0.0" + CRLF
                inv2 += f"{auth_header_name}: {auth_value}" + CRLF
                inv2 += "Content-Type: application/sdp" + CRLF
                inv2 += f"Content-Length:   {len(sdp2)}" + CRLF + CRLF
                inv2 += sdp2

                if DEBUG:
                    print(f"\n--- INVITE (auth) packet ---")
                    print(inv2)
                    print(f"--- end INVITE (auth) ---\n")

                print(f"[*] INVITE (auth) -> {self.server}")
                self._send(inv2)
                continue

            if code == 200:
                early_media_stop.set()
                to_hdr = hdrs.get("To", hdrs.get("to", ""))
                tag_m = re.search(r'tag=([^\s;]+)', to_hdr)
                if tag_m:
                    ctx["to_tag"] = tag_m.group(1)

                if body:
                    c_m = re.search(r'c=IN IP4 (\S+)', body)
                    m_m = re.search(r'm=audio (\d+)', body)
                    if c_m and m_m:
                        remote_rtp = (c_m.group(1), int(m_m.group(1)))

                self._send_ack_200(ctx, hdrs)
                print(f"[+] call answered, remote RTP: {remote_rtp}")
                return 200, ctx, remote_rtp

            if code >= 300:
                early_media_stop.set()
                reason = hdrs.get("Reason", hdrs.get("reason", ""))
                print(f"[!] INVITE failed: {code} {reason}")
                if code >= 400:
                    self._send_ack(ctx, hdrs)
                return code, None, None

        early_media_stop.set()
        print("[!] INVITE timeout — sending CANCEL")
        self._send_cancel(ctx)
        return 0, None, None

    def _send_cancel(self, ctx):
        """CANCEL a pending INVITE."""
        cancel  = f"CANCEL sip:{ctx['number']}@{self.server} SIP/2.0" + CRLF
        cancel += f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};rport;branch={ctx['branch']}" + CRLF
        cancel += "Max-Forwards: 70" + CRLF
        cancel += f'From: "{self.caller_id}" <sip:{self.username}@{self.server}>;tag={ctx["from_tag"]}' + CRLF
        cancel += f'To: <sip:{ctx["number"]}@{self.server}>' + CRLF
        cancel += f'Call-ID: {ctx["call_id"]}' + CRLF
        cancel += f'CSeq: {ctx["cseq"]} CANCEL' + CRLF
        cancel += "User-Agent: Phantom/1.0.0" + CRLF
        cancel += "Content-Length:  0" + CRLF + CRLF
        self._send(cancel)
        # drain the 200/487 responses
        self._drain_and_handle(seconds=2.0)

    def _send_ack(self, ctx, resp_hdrs):
        """ACK for non-2xx responses."""
        to_hdr = resp_hdrs.get("To", resp_hdrs.get("to", ""))
        ack  = f"ACK sip:{ctx['number']}@{self.server} SIP/2.0" + CRLF
        ack += f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};rport;branch={ctx['branch']}" + CRLF
        ack += "Max-Forwards: 70" + CRLF
        ack += f'From: "{self.caller_id}" <sip:{self.username}@{self.server}>;tag={ctx["from_tag"]}' + CRLF
        ack += f"To: {to_hdr}" + CRLF
        ack += f'Call-ID: {ctx["call_id"]}' + CRLF
        ack += f'CSeq: {ctx["cseq"]} ACK' + CRLF
        ack += "Content-Length:  0" + CRLF + CRLF
        self._send(ack)

    def _send_ack_200(self, ctx, resp_hdrs):
        """ACK for 200 OK — uses Contact from response as Request-URI."""
        contact = resp_hdrs.get("Contact", resp_hdrs.get("contact", ""))
        contact_uri = re.search(r'<([^>]+)>', contact)
        req_uri = contact_uri.group(1) if contact_uri else f"sip:{ctx['number']}@{self.server}"

        to_hdr = resp_hdrs.get("To", resp_hdrs.get("to", ""))

        ack  = f"ACK {req_uri} SIP/2.0" + CRLF
        ack += f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};rport;branch={gen_branch()}" + CRLF
        ack += "Max-Forwards: 70" + CRLF
        ack += f'From: "{self.caller_id}" <sip:{self.username}@{self.server}>;tag={ctx["from_tag"]}' + CRLF
        ack += f"To: {to_hdr}" + CRLF
        ack += f'Call-ID: {ctx["call_id"]}' + CRLF
        ack += f'CSeq: {ctx["cseq"]} ACK' + CRLF
        ack += f'Contact: "{self.caller_id}" <sip:{self.username}@{self.local_ip}:{self.local_port};ob>' + CRLF
        ack += "User-Agent: Phantom/1.0.0" + CRLF
        ack += "Content-Length:  0" + CRLF + CRLF
        self._send(ack)

    def send_bye(self, ctx):
        branch = gen_branch()
        cseq = self._next_cseq()

        bye  = f"BYE sip:{ctx['number']}@{self.server} SIP/2.0" + CRLF
        bye += f"Via: SIP/2.0/UDP {self.local_ip}:{self.local_port};rport;branch={branch}" + CRLF
        bye += "Max-Forwards: 70" + CRLF
        bye += f'From: "{self.caller_id}" <sip:{self.username}@{self.server}>;tag={ctx["from_tag"]}' + CRLF
        to_tag_part = f";tag={ctx['to_tag']}" if ctx.get('to_tag') else ""
        bye += f'To: <sip:{ctx["number"]}@{self.server}>{to_tag_part}' + CRLF
        bye += f'Call-ID: {ctx["call_id"]}' + CRLF
        bye += f"CSeq: {cseq} BYE" + CRLF
        bye += f'Contact: "{self.caller_id}" <sip:{self.username}@{self.local_ip}:{self.local_port};ob>' + CRLF
        bye += "User-Agent: Phantom/1.0.0" + CRLF
        bye += "Content-Length:  0" + CRLF + CRLF

        self._send(bye)
        print("[*] BYE sent")

        code, _, _ = self._recv_response(timeout=5)
        if code:
            print(f"    <- BYE response: {code}")

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ── DTMF detection ─────────────────────────────────────────────

DTMF_EVENTS = {
    0: "0", 1: "1", 2: "2", 3: "3", 4: "4",
    5: "5", 6: "6", 7: "7", 8: "8", 9: "9",
    10: "*", 11: "#", 12: "A", 13: "B", 14: "C", 15: "D",
}

def dtmf_listener(rtp_sock, stop_evt, digits_list, dtmf_pt=101, audio_cb=None,
                   disconnect_evt=None, screening_flag=None, voicemail_evt=None):
    """Background thread: receives RTP, detects RFC 4733 DTMF events.
    If audio_cb is set, forwards non-DTMF audio payloads to it.
    Sets disconnect_evt if no RTP received for 8s.
    Sets screening_flag[0]=True if AMD detects machine.
    Sets voicemail_evt if AMD detects machine (same signal, separate event)."""
    AMD_GRACE       = 1.5    # ignore connection artifacts
    AMD_INIT_SIL    = 4.5    # no speech at all → machine (dead air pickup)
    AMD_VOICE_MAX   = 3.0    # accumulated voice time (not span) → machine
    AMD_HUMAN_VOICE = 1.5    # accumulated voice under this + silence → human
    AMD_AFTER_SIL   = 1.5    # silence after speech before deciding
    AMD_MAX_WORDS   = 6      # word count above this → machine
    AMD_WORD_GAP    = 0.10   # silence between words
    AMD_MIN_WORD    = 0.12   # minimum duration to count as a word
    AMD_WINDOW      = 7.0    # total analysis window
    AMD_ENERGY      = 250    # RMS threshold (decoded 16-bit PCM)

    seen_ts = set()
    buf = bytearray()
    last_flush = time.time()
    last_rtp_time = time.time()
    start_time = time.time()

    amd_decided = False
    amd_in_speech = False
    amd_first_speech = None
    amd_last_speech = None
    amd_cur_word_start = None
    amd_silence_start = None
    amd_word_count = 0
    amd_voice_accum = 0.0

    def amd_machine(reason):
        nonlocal amd_decided
        if amd_decided:
            return
        amd_decided = True
        print(f"  [AMD] MACHINE — {reason}")
        if screening_flag is not None:
            screening_flag[0] = True
        if voicemail_evt:
            voicemail_evt.set()

    def amd_human(reason):
        nonlocal amd_decided
        if amd_decided:
            return
        amd_decided = True
        print(f"  [AMD] HUMAN — {reason}")

    while not stop_evt.is_set():
        try:
            data, _ = rtp_sock.recvfrom(4096)
        except socket.timeout:
            if audio_cb and buf:
                try: audio_cb(bytes(buf))
                except Exception: pass
                buf.clear()
                last_flush = time.time()
            if disconnect_evt and time.time() - last_rtp_time > 8:
                print("  [!] no RTP for 8s — call disconnected")
                disconnect_evt.set()
                break
            continue
        except OSError:
            if disconnect_evt:
                disconnect_evt.set()
            break
        last_rtp_time = time.time()
        if len(data) < 16:
            continue
        pt = data[1] & 0x7F
        if pt == dtmf_pt:
            ts = struct.unpack("!I", data[4:8])[0]
            event = data[12]
            end_flag = (data[13] >> 7) & 1
            if end_flag and ts not in seen_ts:
                seen_ts.add(ts)
                digit = DTMF_EVENTS.get(event, f"?{event}")
                digits_list.append(digit)
                print(f"  [DTMF] '{digit}' detected")
        elif len(data) > 12:
            payload = data[12:]
            now = time.time()
            elapsed = now - start_time

            if not amd_decided and elapsed < AMD_WINDOW and elapsed > AMD_GRACE:
                lin = audioop.ulaw2lin(payload, 2)
                rms = audioop.rms(lin, 2)
                is_speech = rms > AMD_ENERGY

                if is_speech:
                    amd_last_speech = now
                    amd_silence_start = None
                    if not amd_in_speech:
                        amd_in_speech = True
                        amd_cur_word_start = now
                        if amd_first_speech is None:
                            amd_first_speech = now
                            if elapsed > AMD_INIT_SIL:
                                amd_machine(f"initial silence {elapsed:.1f}s")
                    else:
                        amd_voice_accum += 0.02
                    if amd_voice_accum > AMD_VOICE_MAX:
                        amd_machine(f"voice {amd_voice_accum:.1f}s")
                else:
                    if amd_in_speech:
                        if amd_silence_start is None:
                            amd_silence_start = now
                        elif now - amd_silence_start > AMD_WORD_GAP:
                            if amd_cur_word_start and now - amd_cur_word_start >= AMD_MIN_WORD:
                                amd_word_count += 1
                                if amd_word_count > AMD_MAX_WORDS:
                                    amd_machine(f"{amd_word_count} words")
                            amd_in_speech = False
                            amd_cur_word_start = None
                    if amd_first_speech and amd_silence_start:
                        sil_dur = now - amd_silence_start
                        if sil_dur > AMD_AFTER_SIL:
                            if amd_voice_accum < AMD_HUMAN_VOICE:
                                amd_human(f"short voice {amd_voice_accum:.1f}s + silence")
                            else:
                                amd_machine(f"long voice {amd_voice_accum:.1f}s + silence")
            elif not amd_decided and elapsed >= AMD_WINDOW:
                if amd_first_speech:
                    if amd_voice_accum > AMD_HUMAN_VOICE:
                        amd_machine(f"timeout with {amd_voice_accum:.1f}s voice")
                    else:
                        amd_human("timeout — short voice")
                else:
                    amd_machine("timeout — no speech detected")

            if audio_cb:
                buf.extend(payload)
                if now - last_flush >= 0.16 or len(buf) >= 1280:
                    try: audio_cb(bytes(buf))
                    except Exception: pass
                    buf.clear()
                    last_flush = now
    if audio_cb and buf:
        try: audio_cb(bytes(buf))
        except Exception: pass


# ── RTP streamer ──────────────────────────────────────────────

def stream_rtp(rtp_sock, remote_addr, ulaw_data: bytes, pause_sec: int,
               digits_list=None, audio_cb=None, disconnect_evt=None, stop_event=None,
               voicemail_evt=None):
    """Stream silence (pause) then ulaw audio as RTP packets. Returns when done.
    If disconnect_evt, stop_event, or voicemail_evt is set externally, stops early."""
    ssrc = random.getrandbits(32)
    seq = random.randint(0, 0xFFFF)
    timestamp = 0
    pt = 0  # PCMU

    silence = bytes([0xFF] * FRAME_SIZE)

    pause_frames = (pause_sec * SAMPLE_RATE) // FRAME_SIZE
    print(f"  [+] sending {pause_sec}s silence ({pause_frames} frames) ...")
    for _ in range(pause_frames):
        if (disconnect_evt and disconnect_evt.is_set()) or (stop_event and stop_event.is_set()) or (voicemail_evt and voicemail_evt.is_set()):
            print("  [!] stopped during pause — aborting stream")
            return seq, timestamp, ssrc
        pkt = build_rtp_packet(silence, seq, timestamp, ssrc, pt)
        rtp_sock.sendto(pkt, remote_addr)
        seq = (seq + 1) & 0xFFFF
        timestamp += FRAME_SIZE
        time.sleep(0.02)

    print(f"  [+] streaming audio ({len(ulaw_data) / SAMPLE_RATE:.1f}s) ...")
    offset = 0
    while offset < len(ulaw_data):
        if (disconnect_evt and disconnect_evt.is_set()) or (stop_event and stop_event.is_set()) or (voicemail_evt and voicemail_evt.is_set()):
            print("  [!] stopped during audio — aborting stream")
            return seq, timestamp, ssrc
        chunk = ulaw_data[offset:offset + FRAME_SIZE]
        if len(chunk) < FRAME_SIZE:
            chunk += bytes([0xFF] * (FRAME_SIZE - len(chunk)))
        pkt = build_rtp_packet(chunk, seq, timestamp, ssrc, pt)
        rtp_sock.sendto(pkt, remote_addr)
        if audio_cb:
            audio_cb(chunk)
        seq = (seq + 1) & 0xFFFF
        timestamp += FRAME_SIZE
        offset += FRAME_SIZE
        time.sleep(0.02)

    print("  [+] audio done, listening for DTMF (10s) ...")
    listen_frames = (10 * SAMPLE_RATE) // FRAME_SIZE
    for _ in range(listen_frames):
        if (disconnect_evt and disconnect_evt.is_set()) or (stop_event and stop_event.is_set()) or (voicemail_evt and voicemail_evt.is_set()):
            break
        pkt = build_rtp_packet(silence, seq, timestamp, ssrc, pt)
        rtp_sock.sendto(pkt, remote_addr)
        seq = (seq + 1) & 0xFFFF
        timestamp += FRAME_SIZE
        time.sleep(0.02)
        if digits_list and len(digits_list) > 0:
            break

    for _ in range(25):
        if (disconnect_evt and disconnect_evt.is_set()) or (stop_event and stop_event.is_set()):
            break
        pkt = build_rtp_packet(silence, seq, timestamp, ssrc, pt)
        rtp_sock.sendto(pkt, remote_addr)
        seq = (seq + 1) & 0xFFFF
        timestamp += FRAME_SIZE
        time.sleep(0.02)

    return seq, timestamp, ssrc


def stream_rtp_continue(rtp_sock, remote_addr, ulaw_data: bytes,
                        seq: int, timestamp: int, ssrc: int, audio_cb=None):
    """Continue streaming on the same RTP session (same ssrc/seq/ts)."""
    pt = 0
    silence = bytes([0xFF] * FRAME_SIZE)

    print(f"  [+] streaming response ({len(ulaw_data) / SAMPLE_RATE:.1f}s) ...")
    offset = 0
    while offset < len(ulaw_data):
        chunk = ulaw_data[offset:offset + FRAME_SIZE]
        if len(chunk) < FRAME_SIZE:
            chunk += bytes([0xFF] * (FRAME_SIZE - len(chunk)))
        pkt = build_rtp_packet(chunk, seq, timestamp, ssrc, pt)
        rtp_sock.sendto(pkt, remote_addr)
        if audio_cb:
            audio_cb(chunk)
        seq = (seq + 1) & 0xFFFF
        timestamp += FRAME_SIZE
        offset += FRAME_SIZE
        time.sleep(0.02)

    for _ in range(25):
        pkt = build_rtp_packet(silence, seq, timestamp, ssrc, pt)
        rtp_sock.sendto(pkt, remote_addr)
        seq = (seq + 1) & 0xFFFF
        timestamp += FRAME_SIZE
        time.sleep(0.02)

    print("  [+] response done")


# ── rtp bridge ────────────────────────────────────────────────

def _rtp_bridge(sock_a, sock_b, remote_a, remote_b, stop_evt, audio_cb=None):
    """Forward RTP between two sockets until stop_evt is set."""
    import select
    while not stop_evt.is_set():
        ready, _, _ = select.select([sock_a, sock_b], [], [], 0.1)
        for s in ready:
            try:
                data, _ = s.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            if len(data) < 12:
                continue
            if s is sock_a:
                try:
                    sock_b.sendto(data, remote_b)
                except OSError:
                    pass
                if audio_cb and len(data) > 12:
                    try:
                        audio_cb(data[12:])
                    except Exception:
                        pass
            else:
                try:
                    sock_a.sendto(data, remote_a)
                except OSError:
                    pass


def do_bridge_call(server, port, username, password, caller_id, number,
                   agent_number, local_ip, sip_port, ring_timeout=30,
                   hold_ulaw=None, retries=3, retry_delay=3, audio_cb=None):
    """Call target, then bridge to agent when target answers. Returns True if bridged."""
    rtp_port_a = random.randint(10000, 15000) & 0xFFFE
    rtp_port_b = random.randint(16000, 20000) & 0xFFFE
    sip_port_b = sip_port + 2

    sip_a = SIPCall(server, port, username, password, caller_id, local_ip, sip_port)
    sip_b = None

    try:
        if not sip_a.register():
            print("  [!] registration failed for target call")
            return False

        rtp_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_a.bind((local_ip, rtp_port_a))
        rtp_a.settimeout(1)

        print(f"  [bridge] calling target {number}...")
        code, ctx_a, remote_a = sip_a.invite(number, rtp_port_a, rtp_a)

        if code != 200 or not remote_a:
            print(f"  [bridge] target did not answer ({code})")
            rtp_a.close()
            return False

        print(f"  [bridge] target answered, calling agent {agent_number}...")

        sip_b = SIPCall(server, port, username, password, caller_id, local_ip, sip_port_b)
        if not sip_b.register():
            print("  [!] registration failed for agent call")
            sip_a.send_bye(ctx_a)
            rtp_a.close()
            return False

        rtp_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_b.bind((local_ip, rtp_port_b))
        rtp_b.settimeout(1)

        code_b, ctx_b, remote_b = sip_b.invite(agent_number, rtp_port_b, rtp_b)

        if code_b != 200 or not remote_b:
            print(f"  [bridge] agent did not answer ({code_b})")
            sip_a.send_bye(ctx_a)
            rtp_a.close()
            rtp_b.close()
            return False

        print(f"  [bridge] both answered — bridging audio")
        stop = threading.Event()
        bridge_thread = threading.Thread(
            target=_rtp_bridge,
            args=(rtp_a, rtp_b, remote_a, remote_b, stop, audio_cb),
            daemon=True,
        )
        bridge_thread.start()

        deadline = time.time() + 3600
        while time.time() < deadline and not stop.is_set():
            for s, ctx, other_s, other_ctx, other_sip, label in [
                (sip_a, ctx_a, sip_b, ctx_b, sip_b, "target"),
                (sip_b, ctx_b, sip_a, ctx_a, sip_a, "agent"),
            ]:
                try:
                    data, _ = s.sock.recvfrom(4096)
                    text = data.decode("utf-8", errors="replace")
                    if text.startswith("BYE "):
                        print(f"  [bridge] {label} hung up")
                        stop.set()
                        break
                except (socket.timeout, OSError):
                    pass
            time.sleep(0.05)

        stop.set()
        bridge_thread.join(timeout=2)

        try:
            sip_a.send_bye(ctx_a)
        except Exception:
            pass
        try:
            sip_b.send_bye(ctx_b)
        except Exception:
            pass
        rtp_a.close()
        rtp_b.close()
        return True

    except Exception as e:
        print(f"  [bridge] error: {e}")
        import traceback; traceback.print_exc()
        return False
    finally:
        sip_a.close()
        if sip_b:
            sip_b.close()


def _ws_rtp_bridge(rtp_sock, remote_rtp, stop_evt, audio_out_cb, audio_in_q,
                   audio_monitor_cb=None,
                   audio_monitor_in_cb=None, audio_monitor_out_cb=None):
    """Bridge RTP socket <-> WebSocket queues until stop_evt is set.
    audio_out_cb(ulaw_bytes) sends target audio to agent browser.
    audio_in_q.get() returns ulaw_bytes from agent mic.
    audio_monitor_in_cb/audio_monitor_out_cb split incoming/outgoing for the monitor.
    Falls back to audio_monitor_cb for both if split cbs not provided.
    """
    import select
    ssrc = random.getrandbits(32)
    seq = random.randint(0, 0xFFFF)
    timestamp = 0
    pt = 0

    while not stop_evt.is_set():
        ready, _, _ = select.select([rtp_sock], [], [], 0.02)
        for s in ready:
            try:
                data, _ = s.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            if len(data) > 12:
                payload = data[12:]
                try:
                    audio_out_cb(payload)
                except Exception:
                    pass
                mon_in = audio_monitor_in_cb or audio_monitor_cb
                if mon_in:
                    try:
                        mon_in(payload)
                    except Exception:
                        pass

        try:
            while not audio_in_q.empty():
                chunk = audio_in_q.get_nowait()
                if len(chunk) < FRAME_SIZE:
                    chunk += bytes([0xFF] * (FRAME_SIZE - len(chunk)))
                pkt = build_rtp_packet(chunk, seq, timestamp, ssrc, pt)
                rtp_sock.sendto(pkt, remote_rtp)
                mon_out = audio_monitor_out_cb or audio_monitor_cb
                if mon_out:
                    try:
                        mon_out(chunk)
                    except Exception:
                        pass
                seq = (seq + 1) & 0xFFFF
                timestamp += FRAME_SIZE
        except Exception:
            pass


def do_direct_call(server, port, username, password, caller_id, number,
                   ulaw_data, pause_sec, local_ip, sip_port,
                   trigger_digit="2", hangup_digit=None, hold_ulaw=None,
                   audio_out_cb=None, audio_in_q=None,
                   audio_monitor_cb=None, audio_cb=None,
                   retries=3, retry_delay=3, stop_event=None,
                   audio_out_monitor_cb=None, bridge_cb=None,
                   answer_event=None):
    """Call target, play TTS, wait for DTMF routing, then bridge or hangup.
    Returns 'bridged', 'answered', 'hangup', 'disconnected', 'screening',
    'busy', 'declined', 'unavailable', 'cancelled', or False."""
    for attempt in range(1, retries + 1):
        rtp_port = random.randint(10000, 20000) & 0xFFFE
        sip = SIPCall(server, port, username, password, caller_id, local_ip, sip_port)

        try:
            rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rtp_sock.bind((local_ip, rtp_port))
            rtp_sock.settimeout(1)

            code, ctx, remote_rtp = sip.invite(number, rtp_port, rtp_sock, cancel_event=stop_event)

            if stop_event and stop_event.is_set():
                rtp_sock.close()
                return "cancelled"

            if code == 200 and remote_rtp:
                digits = []
                disconnect_evt = threading.Event()
                voicemail_evt = threading.Event()
                screening_flag = [False]
                dtmf_stop = threading.Event()
                dtmf_thread = threading.Thread(
                    target=dtmf_listener,
                    args=(rtp_sock, dtmf_stop, digits),
                    kwargs={"audio_cb": audio_cb, "disconnect_evt": disconnect_evt,
                            "screening_flag": screening_flag,
                            "voicemail_evt": voicemail_evt},
                    daemon=True,
                )
                dtmf_thread.start()

                if ulaw_data:
                    rtp_state = stream_rtp(rtp_sock, remote_rtp, ulaw_data,
                                           pause_sec, digits_list=digits,
                                           audio_cb=audio_out_monitor_cb,
                                           disconnect_evt=disconnect_evt,
                                           stop_event=stop_event,
                                           voicemail_evt=voicemail_evt)
                else:
                    time.sleep(5)
                    rtp_state = None

                if stop_event and stop_event.is_set():
                    print("  [direct] call cancelled by user")
                    dtmf_stop.set()
                    dtmf_thread.join(timeout=1)
                    try: sip.send_bye(ctx)
                    except Exception: pass
                    rtp_sock.close()
                    return "cancelled"

                if voicemail_evt.is_set():
                    print("  [direct] voicemail detected — hanging up")
                    dtmf_stop.set()
                    dtmf_thread.join(timeout=1)
                    try: sip.send_bye(ctx)
                    except Exception: pass
                    rtp_sock.close()
                    return "voicemail"

                if disconnect_evt.is_set():
                    print("  [direct] call disconnected mid-stream")
                    dtmf_stop.set()
                    dtmf_thread.join(timeout=1)
                    try: sip.send_bye(ctx)
                    except Exception: pass
                    rtp_sock.close()
                    return "disconnected"

                if screening_flag[0]:
                    print("  [direct] automated screening detected on this number")

                dtmf_stop.set()
                dtmf_thread.join(timeout=1)

                got_trigger = trigger_digit in digits
                got_hangup = hangup_digit and hangup_digit in digits
                print(f"  [direct] digits: {''.join(digits)}, trigger={got_trigger}, hangup={got_hangup}")

                if got_hangup:
                    print(f"  [direct] caller pressed {hangup_digit} — hanging up")
                    sip.send_bye(ctx)
                    rtp_sock.close()
                    return "hangup"

                if got_trigger and audio_out_cb and audio_in_q:
                    print(f"  [direct] target pressed {trigger_digit} — bridging to agent")
                    if bridge_cb:
                        try: bridge_cb({"number": number, "caller_id": caller_id, "digits": "".join(digits)})
                        except Exception: pass

                    if hold_ulaw and rtp_state:
                        seq_h, ts_h, ssrc_h = rtp_state
                        answered = False
                        while not answered:
                            off = 0
                            while off < len(hold_ulaw):
                                if stop_event and stop_event.is_set():
                                    answered = True
                                    break
                                if answer_event and answer_event.is_set():
                                    answered = True
                                    break
                                chunk = hold_ulaw[off:off + FRAME_SIZE]
                                if len(chunk) < FRAME_SIZE:
                                    chunk += bytes([0xFF] * (FRAME_SIZE - len(chunk)))
                                pkt = build_rtp_packet(chunk, seq_h, ts_h, ssrc_h, 0)
                                rtp_sock.sendto(pkt, remote_rtp)
                                seq_h = (seq_h + 1) & 0xFFFF
                                ts_h += FRAME_SIZE
                                off += FRAME_SIZE
                                time.sleep(0.02)
                            if not answered and not (answer_event and answer_event.is_set()):
                                continue

                    while not audio_in_q.empty():
                        audio_in_q.get_nowait()

                    stop = threading.Event()
                    bridge_thread = threading.Thread(
                        target=_ws_rtp_bridge,
                        args=(rtp_sock, remote_rtp, stop, audio_out_cb,
                              audio_in_q),
                        kwargs={"audio_monitor_in_cb": audio_cb,
                                "audio_monitor_out_cb": audio_out_monitor_cb,
                                "audio_monitor_cb": audio_monitor_cb},
                        daemon=True,
                    )
                    bridge_thread.start()

                    deadline = time.time() + 3600
                    last_rtp = time.time()
                    while time.time() < deadline and not stop.is_set():
                        if stop_event and stop_event.is_set():
                            print("  [direct] bridge cancelled by user")
                            stop.set()
                            break
                        try:
                            data, _ = sip.sock.recvfrom(4096)
                            text = data.decode("utf-8", errors="replace")
                            if text.startswith("BYE "):
                                print(f"  [direct] target hung up (BYE)")
                                stop.set()
                                break
                        except (socket.timeout, OSError):
                            pass
                        if time.time() - last_rtp > 15:
                            print(f"  [direct] no RTP for 15s — call dropped")
                            stop.set()
                            break
                        time.sleep(0.05)

                    stop.set()
                    bridge_thread.join(timeout=2)
                    try:
                        sip.send_bye(ctx)
                    except Exception:
                        pass
                    rtp_sock.close()
                    return "bridged"
                else:
                    sip.send_bye(ctx)
                    rtp_sock.close()
                    return "answered"

            rtp_sock.close()
            if code == -1:
                return "cancelled"
            if code in (487, 503) and attempt < retries:
                print(f"  [~] attempt {attempt}/{retries} failed ({code}), retrying...")
                time.sleep(retry_delay)
                continue
            if code == 486:
                return "busy"
            if code == 603:
                return "declined"
            if code in (480, 404):
                return "unavailable"
            return False

        except Exception as e:
            print(f"  [direct] error: {e}")
            import traceback; traceback.print_exc()
            if attempt < retries:
                time.sleep(retry_delay)
                continue
            return False
        finally:
            sip.close()

    return False


# ── main call loop ─────────────────────────────────────────────

def do_call(server, port, username, password, caller_id, number,
            ulaw_data, pause_sec, local_ip, sip_port, retries=5, retry_delay=3,
            response_ulaw=None, audio_cb=None, audio_out_cb=None, stop_event=None):
    """Place one call with retries on flaky trunk.
    Returns 'answered', 'screening', 'disconnected', 'busy', 'declined',
    'unavailable', 'cancelled', or False."""
    for attempt in range(1, retries + 1):
        rtp_port = random.randint(10000, 20000) & 0xFFFE

        sip = SIPCall(server, port, username, password, caller_id, local_ip, sip_port)

        try:
            rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rtp_sock.bind((local_ip, rtp_port))
            rtp_sock.settimeout(1)

            code, ctx, remote_rtp = sip.invite(number, rtp_port, rtp_sock, cancel_event=stop_event)

            if stop_event and stop_event.is_set():
                rtp_sock.close()
                return "cancelled"

            if code == 200 and remote_rtp:
                digits = []
                disconnect_evt = threading.Event()
                voicemail_evt = threading.Event()
                screening_flag = [False]
                dtmf_stop = threading.Event()
                dtmf_thread = threading.Thread(
                    target=dtmf_listener,
                    args=(rtp_sock, dtmf_stop, digits),
                    kwargs={"audio_cb": audio_cb, "disconnect_evt": disconnect_evt,
                            "screening_flag": screening_flag,
                            "voicemail_evt": voicemail_evt},
                    daemon=True,
                )
                dtmf_thread.start()

                if ulaw_data:
                    rtp_state = stream_rtp(rtp_sock, remote_rtp, ulaw_data,
                                           pause_sec, digits_list=digits,
                                           audio_cb=audio_out_cb,
                                           disconnect_evt=disconnect_evt,
                                           stop_event=stop_event,
                                           voicemail_evt=voicemail_evt)
                else:
                    print("  [+] no message, holding 5s ...")
                    time.sleep(5)
                    rtp_state = None

                if stop_event and stop_event.is_set():
                    print("  [!] call cancelled by user")
                    dtmf_stop.set()
                    dtmf_thread.join(timeout=1)
                    try: sip.send_bye(ctx)
                    except Exception: pass
                    rtp_sock.close()
                    return "cancelled"

                if voicemail_evt.is_set():
                    print("  [!] voicemail detected — hanging up")
                    dtmf_stop.set()
                    dtmf_thread.join(timeout=1)
                    try: sip.send_bye(ctx)
                    except Exception: pass
                    rtp_sock.close()
                    return "voicemail"

                if disconnect_evt.is_set():
                    print("  [!] call disconnected mid-stream")
                    dtmf_stop.set()
                    dtmf_thread.join(timeout=1)
                    try: sip.send_bye(ctx)
                    except Exception: pass
                    rtp_sock.close()
                    return "disconnected"

                if screening_flag[0]:
                    print("  [!] automated screening detected")

                if digits:
                    print(f"  [DTMF] digits received: {''.join(digits)}")
                    if response_ulaw and rtp_state:
                        seq, ts, ssrc = rtp_state
                        stream_rtp_continue(rtp_sock, remote_rtp,
                                            response_ulaw, seq, ts, ssrc,
                                            audio_cb=audio_out_cb)
                else:
                    print(f"  [DTMF] no digits detected")

                dtmf_stop.set()
                dtmf_thread.join(timeout=1)

                sip.send_bye(ctx)
                rtp_sock.close()
                if screening_flag[0] and not digits:
                    return "screening"
                return "answered"

            rtp_sock.close()

            if code == -1:
                return "cancelled"
            if code in (487, 503) and attempt < retries:
                print(f"  [~] attempt {attempt}/{retries} failed ({code}), retrying in {retry_delay}s ...")
                time.sleep(retry_delay)
                continue
            if code == 486:
                return "busy"
            if code == 603:
                return "declined"
            if code in (480, 404):
                return "unavailable"
            return False

        except Exception as e:
            print(f"  [!] error: {e}")
            import traceback; traceback.print_exc()
            if attempt < retries:
                print(f"  [~] retrying in {retry_delay}s ...")
                time.sleep(retry_delay)
                continue
            return False
        finally:
            sip.close()

    return False


def main():
    parser = argparse.ArgumentParser(description="SIP lead caller — raw sockets + TTS")
    parser.add_argument("--server", required=True, help="SIP server (e.g. sip.suii.us)")
    parser.add_argument("--port", type=int, default=5060, help="SIP port (default 5060)")
    parser.add_argument("--user", required=True, help="SIP username")
    parser.add_argument("--password", required=True, help="SIP password")
    parser.add_argument("--caller-id", default="18002893557", dest="caller_id",
                        help="caller ID / display name (default 18002893557)")
    parser.add_argument("--leads", help="path to leads file (.txt or .csv)")
    parser.add_argument("--number", help="single number to call (instead of --leads)")
    parser.add_argument("--message", default="", help="TTS message to play (empty = silent call)")
    parser.add_argument("--response", default="", help="TTS message to play when DTMF digit detected")
    parser.add_argument("--pause", type=int, default=3,
                        help="seconds to wait after pickup before message (default 3)")
    parser.add_argument("--voice", default="en-US-AriaNeural",
                        help="edge-tts voice (default en-US-AriaNeural)")
    parser.add_argument("--delay", type=float, default=3.0,
                        help="seconds between calls (default 3)")
    parser.add_argument("--retries", type=int, default=5,
                        help="retry attempts per call on trunk failure (default 5)")
    parser.add_argument("--retry-delay", type=float, default=3.0, dest="retry_delay",
                        help="seconds between retries (default 3)")
    parser.add_argument("--sip-port", type=int, default=5080, dest="sip_port",
                        help="local SIP port (default 5080, avoids MicroSIP on 5060)")
    args = parser.parse_args()

    if args.number:
        numbers = [normalize_number(args.number)]
    elif args.leads:
        numbers = load_leads(args.leads)
    else:
        parser.error("need --number or --leads")

    if not numbers:
        sys.exit("[!] no numbers to call")

    local_ip = get_local_ip()
    print(f"[*] local IP: {local_ip}")
    print(f"[*] SIP: {args.user}@{args.server}:{args.port}")
    print(f"[*] caller ID: {args.caller_id}")
    print(f"[*] numbers: {len(numbers)}")

    ulaw_data = b""
    if args.message:
        print(f"[*] message: {args.message}")
        print(f"[*] voice: {args.voice}")
        tts_mp3 = Path("_tts_message.mp3")
        generate_tts(args.message, args.voice, tts_mp3)
        ulaw_data = mp3_to_ulaw(tts_mp3)
        tts_mp3.unlink(missing_ok=True)

    response_ulaw = b""
    if args.response:
        print(f"[*] response: {args.response}")
        resp_mp3 = Path("_tts_response.mp3")
        generate_tts(args.response, args.voice, resp_mp3)
        response_ulaw = mp3_to_ulaw(resp_mp3)
        resp_mp3.unlink(missing_ok=True)

    for i, number in enumerate(numbers, 1):
        print(f"\n{'='*50}")
        print(f"[{i}/{len(numbers)}] calling {number}")
        print(f"{'='*50}")

        ok = do_call(
            args.server, args.port, args.user, args.password,
            args.caller_id, number, ulaw_data, args.pause,
            local_ip, args.sip_port, args.retries, args.retry_delay,
            response_ulaw=response_ulaw or None,
        )

        if ok:
            print(f"  [+] call complete")
        else:
            print(f"  [-] call failed")

        if i < len(numbers):
            print(f"[*] waiting {args.delay}s before next call ...")
            time.sleep(args.delay)

    print(f"\n[*] all {len(numbers)} calls done.")


if __name__ == "__main__":
    main()
