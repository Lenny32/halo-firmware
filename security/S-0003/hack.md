# How to exploit S-0003 — recover the Halo IRK from its public advertising address

Goal: take the (public, never-rotating) Halo static address from a passive
advertisement capture, brute-force the 2 hidden EUI-64 bytes, and verify the recovered
IRK against anything that proves key correctness. No pairing, no connection required.

## Preconditions

- One BLE sniffer capture or any `bluetoothctl scan on` output showing the Halo
  advertisement and its static address. The address is constant per unit (S-0004), so
  any sighting at any time works.
- Python 3.10+.

## Background math (why 2^16)

Firmware facts (see `ticket.md` for line refs):

- Static address = `FF:59:94 : eui_ext[0] : eui_ext[1] : eui_ext[2]`
  (bytes reversed on air; `0xFF5994` OUI-like constant, MCUBOOT build).
- EUI-64 = `2C:F7:F1 : eui_ext[3] : eui_ext[4] : eui_ext[0] : eui_ext[1] : eui_ext[2]`
  — the SE extension is 5 bytes; **3 of them are already in the address**. Unknown:
  2 bytes.
- IRK = EUI-64 (8 bytes forward) ++ EUI-64 (8 bytes reversed) = 16 bytes.

→ Iterate `eui_ext[3], eui_ext[4]` over 65536 values, compute the candidate IRK for
each, and rank/verify.

## How to verify a candidate IRK without connecting

Any one of:

1. **Cross-check with a bonded peer's logs** (you own a test phone in this scenario):
   pair a phone, then on the Halo console enable debug or read what the peer stored
   (nRF Connect → bonded device info shows the peer's IRK on some hosts;
   `btmon` on a Linux "victim" shows `Identity Resolving Key` in plain text during
   pairing — this is the strongest check: capture once, compare).
2. **Self-resolution probe**: if any firmware build ever enables RPA advertising,
   resolve an observed RPA per Bluetooth Vol 3 Part H: RPA = `hash || prand`,
   `hash = ah(IRK, prand)`. `derive_irk.py` includes the `ah()` (AES-CMAC based per
   spec, implemented with the AES in ECB over prand||0-padding) so you can test
   candidate IRKs against a captured RPA.
3. **Log greed** (debug builds): `ble_security.c:407` prints the full EUI-64 at
   `LOG_DBG` → zero-effort confirmation of the derivation (and a separate leak).

## Run it

```bash
cd security/S-0003/code
uv run derive_irk.py C0:59:94:AA:BB:CC           # use the unit's own static address
```

Expected output (vulnerable firmware):

```
[*] Static address C0:59:94:AA:BB:CC -> ext bytes on air: AA BB CC
[*] 65536 candidate IRKs for EUI ext bytes [ .. .. AA BB CC]
[*] Wrote candidates.bin (1 MiB) — verify any of:
      - against peer-side IRK observed in btmon during pairing
      - against a captured Halo RPA with --resolve
[*] sample: ext=00:00 -> IRK 2cf7f1aabbcc0000 0000ccbbaaf12c
```

Then, with one captured pairing (`sudo btmon -w pairing.snoop` while bonding your
test phone), grep the trace for the Identity Resolving Key the Halo distributed and:

```bash
uv run derive_irk.py C0:59:94:AA:BB:CC --confirm 2CF7F11027AABBCCCCBBAA2710F1F72C
# -> [+] CONFIRMED: hidden ext bytes 10 27 ; IRK recovered from 2 public bytes of entropy
```

65000 candidates, pure CPU, finishes in seconds.

Also verify the compile-time IRK is present (vulnerable):

```bash
grep -n "0xA1, 0xB2, 0xC3" ../../modules/halo/src/ble_connection.c
# -> gapm_cfg.irk.key — same on every unit, in the public repo
```

## Expected (patched)

- `derive_irk.py` reports: address bytes do not correspond to any EUI-64-derived IRK
  (confirmation fails for all 65536 candidates).
- No `0xA1 ...` constant and no EUI `LOG_DBG` in source.
- IRK changes on factory reset; two units have uncorrelated IRKs.
