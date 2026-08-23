# S-0006 — Hardening bundle: four low-severity defects (source-level)

| Field | Value |
|---|---|
| **Severity** | Low (each) |
| **Component** | `modules/halo/src/ble_connection.c`, `modules/halo/src/ble_security.c` |
| **Reporter** | Internal security review |

Bundle ticket: none of these is independently exploitable today, each weakens a
security-relevant invariant. Fix them alongside the higher tickets and gate on the
regression script in `code/`.

## L1 — `pairing_lvl` forged to AUTHENTICATED for unauthenticated pairing

`ble_security.c:911` — `halo_ble_sec_provide_ltk()` hardcodes
`b->keys.pairing_lvl = GAP_PAIRING_BOND_AUTH` for a Just Works bond, which is
**unauthenticated** by definition (S-0001). Nothing consumes `pairing_lvl` for
authorization today, so this is latent: the first future feature that trusts it
(e.g. "if pairing_lvl >= AUTH, skip the pairing window") silently upgrades a
Just Works bond to trusted. **Fix**: use `GAP_PAIRING_BOND_UNAUTH` and, when
S-0001 lands with Passkey Display, set AUTH only after an authenticated association
actually completed.

## L2 — Numeric Compare auto-accept is a landmine

`ble_connection.c:1296` — `gapc_pairing_numeric_compare_rsp(conidx, true)`. Dead code
under `GAP_IO_CAP_NO_INPUT_NO_OUTPUT` (NC is never selected), but the moment the IO
capability is raised to fix S-0001, Numeric Comparison may get selected by a peer —
and this handler will auto-confirm it, silently defeating the MITM protection the
IO-cap change was supposed to add. **Fix alongside S-0001, in the same commit**:
replace the unconditional `true` with an explicit UI confirmation or a loud
reject-and-log so the regression is audible in testing.

## L3 — SE-failure fallback produces duplicate identity addresses

`ble_connection.c:64-71` — when the SE returns zeros, address bytes 3..5 become
`0x11:0x22:0x33` **on every affected unit**: identical static identity addresses in
the field → address collisions in peers' bond tables and unreliable identity
everywhere (iOS refuses some operations on duplicate addresses; bond slots keyed by
address, see S-0002, get cross-correlated). Also `ble_security.c:412-417` installs a
hardcoded fallback IRK on the same failure path (covered by S-0003 root cause; keep
them together). **Fix**: on SE failure, derive the address from the RNG path used by
`se_service_get_rnd_num` (already in the file) with `|= 0xC0`, log loudly, and land
the S-0003 random-IRK fix so no fallback constant remains.

## L4 — `#ifdef MCU_BOOT` is (almost certainly) dead code

`ble_connection.c:331-333` — `#ifdef MCU_BOOT` tweaks `private_identity.addr[4] = 58`.
Everywhere else in the tree the macro is `CONFIG_MCUBOOT` (`ble_connection.c:39`,
`ble_security.c:983`). If `MCU_BOOT` is never defined as a bare identifier, this
block never compiles — the MCUBOOT build's identity-address tweak silently isn't
applied, and the *intended* debug/prod address split doesn't exist. Mis-gated
security-adjacent code is how `#ifdef`s rot. **Fix**: rename to `CONFIG_MCUBOOT`
to match intent, or delete the block if the 0xFE/0xFF `FRAME_STATIC_ADDRESS` split
(ble_connection.c:39-43) already covers the intent.

## Regression gate

`code/check_hardening.sh` greps the tree for each anti-pattern and exits non-zero
while any is present. Run before/after patching; wire into CI or the release
checklist. Covers: NC auto-true, `GAP_PAIRING_BOND_AUTH` literal, `0x11, 0x22, 0x33`
fallback (as bytes in address init), `#ifdef MCU_BOOT`.

(Pair-verify on hardware for L1/L2 is folded into the S-0001 verification steps:
patched firmware pairing must show the corrected association level in `btmon`.)
