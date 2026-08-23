# S-0001 — Pairing has zero MITM protection (Just Works); Numeric Compare auto-accepted

| Field | Value |
|---|---|
| **Severity** | High |
| **Component** | `modules/halo/src/ble_connection.c`, `modules/halo/src/ble_security.c` |
| **CWE** | CWE-300 (Man-in-the-Middle), CWE-1291 (public key of pairing not authenticated) |
| **Reporter** | Internal security review |

## Summary

Halo pairs with LE Secure Connections **Just Works** and auto-accepts every pairing
request and (if it ever fired) every Numeric Comparison. There is no authenticated
association between phone and glasses, so an active MITM within radio range during the
60-second pairing window can terminate *both* sides of the pairing and leave with a
permanent bond on the glasses. That bond unlocks the entire privileged GATT surface
(Lua REPL → arbitrary code execution on the device; SMP → OTA writes).

## Root cause

- `ble_connection.c:1148-1150` — `on_gapc_pairing_req()` calls
  `halo_ble_sec_pair_accept(conidx)` unconditionally. No user confirmation exists
  anywhere in the pairing path.
- `ble_security.c:481-486` — `halo_ble_sec_pair_accept()` sets
  `pairing_info.iocap = GAP_IO_CAP_NO_INPUT_NO_OUTPUT`. With both sides NoInputNoOutput,
  the SC association model degrades to **Just Works: no MITM protection** by spec.
- `ble_connection.c:1292-1297` — `on_gapc_sec_numeric_compare_req()` answers
  `gapc_pairing_numeric_compare_rsp(conidx, true)`. Dead code today (Numeric Comparison
  is never selected under NoInputNoOutput), but if the IO capability is ever raised to
  enable MITM protection, this auto-`true` silently defeats it.
- Pairing surface timing: `ble_security.c:301-316` (`pairable()`) — the device accepts
  unknown peers whenever the pairing window is open (5 s button hold, 60 s) **or zero
  bonds exist** (out-of-box = perpetual pairing mode). Both states are exactly when a
  user pairs, and both are fully MITM-able.

## Impact

Attacker in BLE range while a victim pairs their phone to their glasses:

1. Terminates the victim's pairing on attacker hardware (phone ⟷ fake-Halo).
2. Simultaneously pairs with the real glasses (attacker ⟷ Halo).
3. Relays all traffic; victim notices nothing — the app "just works".
4. Attacker keeps a **permanent bond** on the glasses; from then on can connect whenever
   in range, run arbitrary Lua via the REPL, and push SMP/OTA traffic, until factory
   reset or LRU eviction.

Constraints: needs RF proximity during pairing (window press or first-ever pairing), and
two BLE radios (or one radio + one nRF dongle). No credentials or prior access needed.

## Fix

1. **Use the display.** Halo has a HUD — it is not a NoInputNoOutput device in spirit.
   Set `pairing_info.iocap = GAP_IO_CAP_DISPLAY_ONLY` and implement the TK/passkey
   display callback: show the 6-digit SC passkey on the glasses' display; the user types
   it into the phone. That upgrades the association model to **Passkey Entry → MITM
   protected**, with zero new hardware.
   - If the ROM stack's passkey-display callback exists in v1.2 headers, wire it to the
     display; verify on dev kit, then a production unit (dev-kit-only verification is
     not enough for display paths — see SETUP.md).
2. If Passkey Display is incompatible with a shipping host app, fallback: post-pair
   app-layer confirmation — app shows a nonce rendered on the HUD; REPL/OTA stay locked
   until the app echoes it back encrypted.
3. **Regardless of (1)/(2):** make `on_gapc_sec_numeric_compare_req()` non-silent:
   log the value and reject/ignore unless a real UI confirms it. Never auto-`true`.
4. Keep `pairable()` as-is (window + zero-bond) — it is the right discovery gate; the
   defect is the unauthenticated association inside it, not the gate.

## Verify the fix

- Re-run `hack.md` scenario A: the MITM relay must now fail — passkey entry on the
  victim phone renders the relay useless (attacker can't read the HUD).
- Scenario B must print `PAIRING PROTECTED` / fail to bond.
- Confirm Numeric Compare path, if reachable, requires explicit confirmation (check
  `btmon` shows reject when harness auto-answers).

## References

- Selection point of this review: `ble_connection.c:1148`
- `PAIRING.md` C7 (IO capability constraint) — needs updating when fixed
- BLUETOOTH CORE SPEC Vol 3, Part H §2.3.5.6 (association models)
