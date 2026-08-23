# How to exploit S-0004 — prove lifetime device trackability with 15 minutes of scanning

Goal: demonstrate that the Halo's advertiser address never rotates, so any passive
observer can persistently re-identify the unit.

## Preconditions

- Laptop with any BLE adapter + Python (bleak). No pairing involved at all.
- The glasses nearby, powered, not necessarily connected to anything.

## Steps

```bash
cd security/S-0004/code
uv run track.py --prefix FF:59:94 --minutes 15 --log sightings.jsonl
```

(also run the same for `FE:59:94` — non-MCUBOOT builds. The script accepts a name
prefix filter too, `--name "Halo"`.)

This passively records every advertisement from the Halo address family with RSSI and
timestamp.

## Expected (vulnerable)

- A single constant address appears in every sighting for the whole session.
- Power-cycle the glasses mid-session (tap button, wait for advertising restart):
  the **same** address returns.
- Leave the script running over lunch / come back tomorrow (repeat run): same
  address again. That is exploit-complete for "persistent device identifier":
  a deployed network of observers can follow the wearer.
- Bonus correlation: the last 3 address bytes reappear inside the EUI-64/IRK
  candidates of S-0003 — cross-proof that privacy and key derivation share one
  root cause.

## Expected (patched)

- Address changes at the configured `renew_dur` (~1500 s) — you will see a new
  random address appear roughly every 25 minutes while the old one disappears.
- New addresses have RPA type bits set (Bluetooth address-type check; the script
  prints address type when the adapter reports it).
- A **bonded** phone still auto-reconnects (proves rotation didn't break the product).

## Notes

- This is the one ticket in the set that needs zero access to remediate and is
  fully observable from the street: it documents a privacy property, not a code
  execution path. It pairs with S-0003 for full impact (static address + derived
  IRK = even a future RPA switch would be trackable unless both are fixed).
- If the fix is implemented, expect the companion app and iOS ANCS to be unaffected:
  both reconnect by bond, not by MAC. Validate once on hardware anyway (gap in the
  threat model: unknown whether the production app caches MACs).
