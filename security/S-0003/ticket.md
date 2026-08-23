# S-0003 — Local IRK brute-forceable from public data (+ hardcoded compile-time IRK)

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Component** | `modules/halo/src/ble_security.c`, `modules/halo/src/ble_connection.c` |
| **CWE** | CWE-321 (use of hard-coded cryptographic key), CWE-330 (insufficiently random values) |
| **Reporter** | Internal security review |

## Summary

The device's Identity Resolving Key is not random and not secret:

1. The IRK distributed to bonded peers is **derived reversibly from the EUI-64**
   (forward + reversed), and 3 of the 5 non-OUI EUI extension bytes are already exposed
   in the permanently advertised static address → an observer needs only 2^16 guesses
   to recover the full IRK from passive advertisement capture.
2. Indepent of (1), `gapm_cfg.irk` is a **hardcoded constant in the public repo** —
   identical on every Halo ever shipped. If the stack path uses this key for RPA
   generation, every device's private addresses are resolvable by anyone who has
   cloned the repo.
3. The full EUI-64 (= complete IRK material) is printed at `LOG_DBG` during security
   init (`ble_security.c:407`).

An IRK is meant to be a 128-bit secret shared between bond partners. A known IRK lets
anyone resolve and track this device when it (or a peer implementation of it) uses
resolvable private addresses, and confirms bond presence noninteractively.

## Root cause

- `ble_security.c:400-405` — IRK = EUI-64 forward + EUI-64 reversed.
  EUI-64 = `2C:F7:F1` (public OUI, hardcoded in the same function) + 5-byte SE
  extension. Entropy: 40 bits at absolute best.
- `ble_connection.c:53-71` — `alif_eui48_read()` puts 3 of those 5 extension bytes
  into the static device address (`FRAME_STATIC_ADDRESS` OUI bytes + extension[0:3]):
  the address is in every advertisement PDU, forever (S-0004). Remaining entropy an
  observer must guess: **2 bytes → 65 536 candidates**, trivially enumerable offline.
- `ble_connection.c:311-312` — `gapm_cfg.irk.key = {0xA1,0xB2,...}` compile-time
  constant, same for all devices, in a public repo (CWE-321 textbook).
- `ble_security.c:410-417` — on SE failure, another hardcoded fallback IRK
  `0123456789ABCDEFFFEDCBA987654321`.
- `ble_security.c:407-408` — `LOG_DBG` logs the full EUI-64; on debug builds the
  UART/log buffer disclosure alone is zero-effort key recovery.

## Impact

- Passive confirmation that a specific Halo is present (resolve its RPA against the
  derived IRK candidate set).
- Defeats any future switch to RPA advertising (S-0004 fix) unless this is fixed first:
  rotating addresses buy nothing when the IRK is public.
- Bond-fingerprinting: correlate that a given RPA belongs to a device bonded to a
  given peer class.

## Fix

1. Generate the IRK **once** from a real TRNG (Alif `se_service_get_rnd_num` 16 bytes,
   or the Zephyr entropy driver), persist it in settings (`/lfs/ble/irk`) on first
   boot, load it on later boots. Never derive identity keys from identity values.
2. Feed that same persisted key into both consumers: `sec_ctx.irk` (peer distribution,
   `halo_ble_sec_provide_irk`) and `gapm_cfg.irk` (controller privacy path,
   `ble_connection.c:311`).
3. Delete the EUI-64 `LOG_DBG` line and the two hardcoded constants.
4. Existing bonds keep working: peer-distributed IRKs change, so this needs a
   migration note — on first boot after the fix, key the new IRK and accept that peers
   see a "new" resolving identity (they keep LTK bonds; IRK redistribution happens on
   re-pair only — document that RPA-based re-identification of the *device* by peers
   is not a Halo requirement, so no migration logic is needed).

## Verify the fix

- `strings`/source check: no 16-byte key constants left in `ble_connection.c` /
  `ble_security.c`; no EUI log.
- Run `derive_irk.py` from `code/` against a patched unit: it must report "no
  derivation" (address bytes ≠ EUI extension) and the unit's IRK must differ across
  factory reset + regenerate (or a debug unit-test hook).
- Two units fresh out of the box must have distinct, uncorrelated IRKs.

## References

- Review findings M1, M2
- `ble_security.c:389-417`, `ble_connection.c:53-71` and `:311-312`
