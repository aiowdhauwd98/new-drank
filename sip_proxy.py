"""
sip_proxy.py — transparent UDP SIP proxy that logs all traffic.
MicroSIP connects to localhost:5061, proxy forwards to sip.suii.us:5060.
Logs every SIP message in both directions so we can see what PJSIP sends.
"""
import socket
import sys
import threading
import time

LOCAL_PORT = 5061
REMOTE_HOST = "sip.suii.us"
REMOTE_PORT = 5060

def log_msg(direction, addr, data):
    text = data.decode("utf-8", errors="replace")
    first_line = text.split("\r\n")[0] if "\r\n" in text else text[:80]
    ts = time.strftime("%H:%M:%S")
    print(f"\n{'='*70}")
    print(f"[{ts}] {direction} {addr[0]}:{addr[1]}")
    print(f"{'='*70}")
    print(text)
    print(f"{'='*70}")
    sys.stdout.flush()

def run():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", LOCAL_PORT))

    remote_addr = (socket.gethostbyname(REMOTE_HOST), REMOTE_PORT)
    client_addr = None

    print(f"[*] SIP proxy listening on :{LOCAL_PORT}")
    print(f"[*] forwarding to {REMOTE_HOST}:{REMOTE_PORT} ({remote_addr[0]})")
    print(f"[*] configure MicroSIP: server=127.0.0.1, port={LOCAL_PORT}")
    print()

    while True:
        data, addr = sock.recvfrom(65535)
        if not data:
            continue

        if addr[0] == remote_addr[0] and addr[1] == remote_addr[1]:
            # from server → forward to client
            log_msg("SERVER ->", addr, data)
            if client_addr:
                sock.sendto(data, client_addr)
        else:
            # from client → forward to server
            client_addr = addr
            log_msg("CLIENT ->", addr, data)
            sock.sendto(data, remote_addr)

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\n[*] stopped")
