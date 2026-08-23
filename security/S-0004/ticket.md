# S-0004 — Permanent static identity address → lifetime device tracking

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Component** | `modules/halo/src/ble_connection.c` |
| **CWE** | CWE-200 (exposure of sensitive information — persistent device identifier) |
| **Reporter** | Internal security review |

## Summary

Every Halo advertises from a **fixed static random address that never changes** for
the lifetime of the unit. `GAP_ROLE_LE_PERIPHERAL` is configured with
`GAPM_PRIV_CFG_PRIV_ADDR_BIT` and a 1500 s renewal duration, but the advertising
activity is created with `GAPM_STATIC_ADDR`, so the configured privacy is **never
exercised** — the renewal timer rotates nothing. The device is trivially and
permanently trackable by any passive observer, and the address directly feeds S-0003
(IRK recovery).

## Root cause

- `ble_connection.c:38-43` — `FRAME_STATIC_ADDRESS` fixes the top
  address bytes (`0xFF5994` / `0xFE5994`).
- `ble_connection.c:326-329` — identity address set once from EUI48, never regenerated.
- `ble_connection.c:434` — `gapm_le_create_adv_legacy(0, GAPM_STATIC_ADDR, ...)`:
  the advertising activity uses the static address type, bypassing the RPA machinery.
- `ble_connection.c:308-309` — `privacy_cfg = GAPM_PRIV_CFG_PRIV_ADDR_BIT` and
  `renew_dur = 1500` are dead config given the above (in Alif v1.2, address renewal
  applies to activities created with a private/RPA own-address type, not
  `GAPM_STATIC_ADDR`).

## Impact

- An observer with commodity hardware (phone with nRF Connect; a $15 nRF52 dongle)
  can log FF:59:94:* sightings and re-identify the same glasses days/years apart —
  presence tracking of the wearer.
- The address leaks 3 bytes of the SE EUI extension (S-0003 raw material).
- Nonstarter for LE Audio use cases that already moved the ecosystem to RPA
  expectations.

## Fix

1. Create the advertising activity with an RPA own-address type
   (`GAPM_GEN_RSLV_ADDR`, or the v1.2 equivalent for RPA-or-static), so the configured
   `renew_dur = 1500` actually rotates the address every 1500 s.
2. Doing (1) makes RPA resolvability load-bearing, so **land S-0003 first** (the IRK
   must be a real per-device secret, or rotation buys nothing).
3. Bonded peers keep finding the device: they resolve the RPA with the IRK they
   received during pairing. Validate with the existing multi-OS bond tests in
   `PAIRING.md` §6 (items 2-3).
4. Keep `se_system_get_eui_extension`-based static identity only as a **fallback**
   when privacy is compiled out.

Trade-off to document in `PAIRING.md`: the Halo companion app must lift any
"connect to last MAC" shortcut and rely on name/service filtering + bond resolution
(iOS/Android handle this natively for bonded devices).

## Verify the fix

- `track.py` (code/): run 2× 30 min sessions before and after the fix in the same
  spot; before: one constant address; after: address changes at ~1500 s cadence and
  no legacy address reappears.
- Phone already bonded to the glasses must still auto-reconnect across a rotation
  (proves peer-side IRK resolution path works).
- Confirm on a production unit (not dev kit): `btmon`/`nRF sniffer` shows AdvA with
  RPA type bits.

## References

- Review finding M3
- `ble_connection.c:38-43, 308-312, 326-329, 434`
- `PAIRING.md` C5 (RPA reality) — the peer side is already handled; this ticket is
  the device side
