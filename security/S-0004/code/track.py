# /// script
# requires-python = ">=3.10"
# dependencies = ["bleak>=0.22"]
# ///
"""
S-0004 PoC: passive Halo presence/tracking logger.

Logs every advertisement sighting of the Halo static-address family. On vulnerable
firmware the address never rotates; on patched firmware it must change at the
renewal cadence (~1500 s) with RPA type.

    uv run track.py --prefix FF:59:94 --minutes 15 --log sightings.jsonl
    uv run track.py --name Halo --minutes 60

Exit 1 (vulnerable) if a single address is seen for the full window without ever
changing; exit 0 when rotation is observed.
"""
import argparse
import asyncio
import json
import time

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", default=None,
                    help="address prefix filter, e.g. FF:59:94 or FE:59:94")
    ap.add_argument("--name", default=None, help="local-name prefix filter")
    ap.add_argument("--minutes", type=float, default=15)
    ap.add_argument("--log", default="sightings.jsonl")
    args = ap.parse_args()

    if not args.prefix and not args.name:
        raise SystemExit("give --prefix or --name")

    deadline = time.time() + args.minutes * 60
    first_seen: dict[str, float] = {}
    events: list[dict] = []
    logf = open(args.log, "a")

    def cb(dev: BLEDevice, adv: AdvertisementData) -> None:
        addr = dev.address.upper()
        if args.prefix and not addr.startswith(args.prefix.upper()):
            return
        if args.name and not (adv.local_name or "").startswith(args.name):
            return
        now = time.time()
        first_seen.setdefault(addr, now)
        ev = {
            "t": round(now, 3),
            "addr": addr,
            "name": adv.local_name,
            "rssi": adv.rssi,
        }
        events.append(ev)
        logf.write(json.dumps(ev) + "\n")
        logf.flush()
        print(f"[{time.strftime('%H:%M:%S', time.localtime(now))}] "
              f"{addr} name={ev['name']!r} rssi={adv.rssi}")

    async def run() -> None:
        scanner = BleakScanner(detection_callback=cb)
        await scanner.start()
        while time.time() < deadline:
            await asyncio.sleep(1)
        await scanner.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass

    addrs = sorted(first_seen)
    print("\n=== summary ===")
    print(f"distinct Halo addresses seen: {len(addrs)}")
    for a in addrs:
        print(f"  {a}  first seen {time.strftime('%H:%M:%S', time.localtime(first_seen[a]))}")

    if len(addrs) == 1:
        print("\n[VULNERABLE] single constant address for the whole session — "
              "no rotation, device is persistently trackable")
        print("(re-run across power cycles / days for full proof)")
        return 1
    if len(addrs) > 1:
        print("\n[PATCHED?] multiple advertiser addresses observed — rotation active; "
              "confirm cadence ≈ renew_dur (1500 s) in the log")
        return 0
    print("\n[-] nothing seen — check filters / is the unit powered?")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
