# S-0002 — Bond slot takeover via spoofed-identity re-pair

| Field | Value |
|---|---|
| **Severity** | High |
| **Component** | `modules/halo/src/ble_security.c` |
| **CWE** | CWE-345 (insufficient verification of identity), CWE-306 (missing authentication for critical function) |
| **Reporter** | Internal security review |

## Summary

Which bond slot a connection belongs to is decided by a **plain address memcmp** at
connection time. A "known" peer is then allowed to re-pair at any moment, and the new
keys **overwrite that slot in place**. An attacker who clones a bonded peer's public or
static identity address can therefore connect, trigger a fresh (unauthenticated, see
S-0001) pairing instead of answering the LTK encryption request, and get their own keys
persisted **over the victim's bond**. Result: permanent privileged access as the victim
+ victim lockout.

## Root cause

- `ble_security.c:246-255` — `find_slot_by_addr()` identifies a returning bonded peer by
  `memcmp` of the connection address against stored `peer_addr`. A BLE identity address
  is **not a secret**: it is observable over the air in every CONNECT_IND, and
  spoofing it is a one-word adapter setting.
- `ble_security.c:1044-1121` (`halo_ble_sec_on_connection_req`) — a matching address
  yields `active_slot = slot` before any cryptographic proof exists
  (`known_device_connected()`, line 934).
- `ble_security.c:766-821` (`halo_ble_sec_on_keys_received`) — with
  `active_slot >= 0`, received keys are written into the live slot and **persisted
  immediately** (line 816-818). The only gate is the address match.
- `ble_security.c:601-650` (`halo_ble_sec_on_paired`) — with `pending_active == false`
  the commit path "refreshes" the active slot with the attacker's pairing parameters
  (line 626-633).
- `ble_connection.c:1145-1150` — the fresh pairing that carries this is auto-accepted
  (`on_gapc_pairing_req`), and Just Works (S-0001) means no user sees anything.
- Documented-but-accepted design intent: `PAIRING.md` §3.6 ("a known device may always
  re-pair itself", for iOS "Forget This Device" self-heal). The vulnerability is that
  "known" is defined by an unauthenticated value. §7 acknowledges identical public
  addresses as a *collision* risk, not as a *third-party spoof* risk; the consequence
  of the latter is REPL-level access, not confusion.

## Scope / who is reachable

- **Vulnerable**: bonds whose stored identity is a **public or static-random address**
  (typical of macOS/Linux dev hosts, some Androids, anything that did not distribute an
  IRK or whose identity equals its connectable address). For those, `find_slot_by_addr`
  needs only the address value.
- **Not reachable this way**: bonds matched via **RPA resolution**
  (`find_slot_by_irk()`, line 258). iOS/macOS-with-IRK peers resolve through their IRK,
  which the attacker does not have. (They become reachable if S-0003/S-0005 leak the
  IRK.) The practical victim set is therefore the dev/laptop class — which is precisely
  the class most useful to impersonate (the REPL is the developer surface).

## Impact

- Attacker acquires a working bond (encrypted link → REPL → code execution; SMP/OTA)
  as the spoofed slot.
- The spoofed victim's next connection fails encryption (attack keys != their keys);
  per `on_encrypt_failed()` (`ble_security.c:700-728`) the bond is deliberately *kept*
  and the peer is disconnected → the victim can never reconnect until they themselves
  force a re-pair, which then evicts the attacker's keys only if they do it and notice.
  Silent, persistent takeover.

## Fix

Pick one; the first two are cheap and combine well:

1. **Gate re-pair on cryptographic identity, not address.** Only honor
   `on_keys_received`/`on_paired` slot refresh when the slot was matched via
   **IRK resolution** (RPA path). For raw-address-matched slots, a re-pairing attempt
   must either (a) require the pairing window, or (b) be rejected outright.
2. **No re-pair while encryption is unsettled.** If `known_device_connected()` has an
   outstanding encryption request, reject `on_gapc_pairing_req`
   (`halo_ble_sec_pair_reject`) until the encryption attempt resolved (success or
   failure + disconnect). This kills the race class entirely.
3. **Never persist key refresh for an existing bond on an unauthenticated pairing
   level.** Check `pairing_level` at commit: if the slot exists and the new pairing was
   not authenticated (and not performed inside the pairing window), drop it.
4. Document the changed behavior in `PAIRING.md` §3.6: forget-heal for public-address
   peers then needs the 5 s window (acceptable; iOS/macOS RPA peers unaffected).

## Verify the fix

- Re-run `hack.md`: after the patch, `takeover.py` must fail at the pairing step
  ("pairing rejected / connection dropped") on every attempt, and the victim phone must
  still reconnect normally afterwards (bond untouched in `/lfs/settings`).
- Regression: forget-heal for a public-address peer must still work **with the window
  open** (hold button 5 s, then re-pair the forgotten dev host).

## References

- Review finding H2; `ble_security.c:700-728` comment block (old spoof-DoS analysis —
  this ticket is the successor attack the current code does not cover)
- `PAIRING.md` §3.5, §3.6, §7
