"""
lead_caller.py — Automated lead caller via Call Spoofing API
Loads a lead list, calls each number from a caller ID you pick,
waits 3 seconds after pickup, then plays your TTS message.
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

BASE = "https://api.callspoofing.org/v1"


def headers(api_key: str) -> dict:
    return {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def load_leads(path: str) -> list[str]:
    p = Path(path)
    numbers = []

    if p.suffix.lower() == ".csv":
        with open(p, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                num = row[0].strip()
                if num and num[0] in "0123456789+":
                    numbers.append(num)
    else:
        for line in p.read_text(encoding="utf-8").splitlines():
            num = line.strip()
            if num and num[0] in "0123456789+":
                numbers.append(num)

    return numbers


def build_flow(message: str, pause_sec: int = 3, voice: str = None) -> list:
    say_step: dict = {"text": message}
    if voice:
        say_step["voice"] = voice
    return [
        {"pause": pause_sec},
        {"say": say_step},
    ]


def check_balance(api_key: str):
    r = requests.get(f"{BASE}/account", headers=headers(api_key), timeout=15)
    if r.status_code == 200:
        return r.json()
    print(f"[!] account check failed: {r.status_code} {r.text}")
    return None


def call_single(api_key: str, to: str, caller_id: str, flow: list,
                record: bool = False, ring_timeout: int = 45) -> dict | None:
    body = {
        "to": to,
        "from": caller_id,
        "flow": flow,
        "ring_timeout": ring_timeout,
        "record": record,
    }
    r = requests.post(f"{BASE}/calls", headers=headers(api_key),
                       json=body, timeout=30)
    if r.status_code in (200, 201):
        return r.json()
    print(f"  [!] call to {to} failed: {r.status_code} {r.text}")
    return None


def call_batch(api_key: str, numbers: list[str], caller_id: str, flow: list,
               calls_at_once: int = 5, record: bool = False,
               ring_timeout: int = 45, name: str = "lead outreach") -> dict | None:
    body = {
        "name": name,
        "numbers": numbers,
        "from": caller_id,
        "flow": flow,
        "calls_at_once": calls_at_once,
        "ring_timeout": ring_timeout,
        "record": record,
    }
    r = requests.post(f"{BASE}/batches", headers=headers(api_key),
                       json=body, timeout=30)
    if r.status_code in (200, 201):
        return r.json()
    print(f"[!] batch failed: {r.status_code} {r.text}")
    return None


def get_call_status(api_key: str, call_id: str) -> dict | None:
    r = requests.get(f"{BASE}/calls/{call_id}", headers=headers(api_key), timeout=15)
    if r.status_code == 200:
        return r.json()
    return None


def get_batch_status(api_key: str, batch_id: str) -> dict | None:
    r = requests.get(f"{BASE}/batches/{batch_id}", headers=headers(api_key), timeout=15)
    if r.status_code == 200:
        return r.json()
    return None


def poll_batch(api_key: str, batch_id: str, interval: int = 10):
    print(f"\n[*] polling batch {batch_id} every {interval}s ...")
    while True:
        status = get_batch_status(api_key, batch_id)
        if not status:
            print("  [!] couldn't fetch batch status")
            break

        s = status.get("status", "unknown")
        total = status.get("total", "?")
        completed = status.get("completed", "?")
        answered = status.get("answered", "?")
        failed = status.get("failed", "?")

        print(f"  status={s}  total={total}  completed={completed}  "
              f"answered={answered}  failed={failed}")

        if s in ("completed", "cancelled", "failed"):
            break
        time.sleep(interval)

    print("[*] batch done.")


def main():
    parser = argparse.ArgumentParser(description="call leads via callspoofing.org")
    parser.add_argument("--key", required=True, help="API key (vac_live_...)")
    parser.add_argument("--leads", required=True, help="path to leads file (.txt or .csv)")
    parser.add_argument("--from-number", required=True, dest="caller_id",
                        help="caller ID to show (your spoofed number)")
    parser.add_argument("--message", required=True, help="TTS message to play after pickup")
    parser.add_argument("--pause", type=int, default=3, help="seconds to wait after pickup (default 3)")
    parser.add_argument("--voice", default=None,
                        help="TTS voice id (default: edge:en-US-AriaNeural)")
    parser.add_argument("--mode", choices=["single", "batch"], default="batch",
                        help="single = one-by-one with delay; batch = bulk API call")
    parser.add_argument("--concurrency", type=int, default=5,
                        help="concurrent calls in batch mode (1-200, default 5)")
    parser.add_argument("--delay", type=float, default=2.0,
                        help="seconds between calls in single mode (default 2)")
    parser.add_argument("--ring-timeout", type=int, default=45, dest="ring_timeout",
                        help="how long to ring before giving up (5-120, default 45)")
    parser.add_argument("--record", action="store_true", help="record each call")
    parser.add_argument("--poll", action="store_true", help="poll batch status until done")
    parser.add_argument("--sandbox", action="store_true",
                        help="call sandbox:press1 instead of real numbers (free test)")
    args = parser.parse_args()

    numbers = load_leads(args.leads)
    if not numbers:
        sys.exit("[!] no numbers found in leads file")

    print(f"[*] loaded {len(numbers)} leads from {args.leads}")
    print(f"[*] caller id: {args.caller_id}")
    print(f"[*] message: {args.message}")
    print(f"[*] pause after pickup: {args.pause}s")
    print(f"[*] mode: {args.mode}")

    if args.sandbox:
        numbers = ["sandbox:press1"] * len(numbers)
        print("[*] sandbox mode — all calls go to sandbox:press1 (free)")

    acct = check_balance(args.key)
    if acct:
        bal = acct.get("balance", acct.get("credit", "?"))
        print(f"[*] account balance: {bal}")

    flow = build_flow(args.message, args.pause, args.voice)
    print(f"[*] flow: {json.dumps(flow, indent=2)}")

    if args.mode == "batch":
        print(f"\n[*] sending batch of {len(numbers)} numbers, {args.concurrency} at a time ...")
        result = call_batch(
            args.key, numbers, args.caller_id, flow,
            calls_at_once=args.concurrency,
            record=args.record,
            ring_timeout=args.ring_timeout,
        )
        if result:
            batch_id = result.get("id", "")
            print(f"[+] batch created: {batch_id}")
            print(f"    status: {result.get('status', '?')}")
            if args.poll and batch_id:
                poll_batch(args.key, batch_id)
        else:
            sys.exit("[!] batch creation failed")

    else:
        print(f"\n[*] calling {len(numbers)} leads one by one ...")
        for i, number in enumerate(numbers, 1):
            print(f"\n[{i}/{len(numbers)}] calling {number} ...")
            result = call_single(
                args.key, number, args.caller_id, flow,
                record=args.record,
                ring_timeout=args.ring_timeout,
            )
            if result:
                call_id = result.get("id", "")
                status = result.get("status", "?")
                print(f"  [+] {call_id}  status={status}")
            if i < len(numbers):
                time.sleep(args.delay)

        print(f"\n[*] all {len(numbers)} calls dispatched.")


if __name__ == "__main__":
    main()
