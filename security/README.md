# Halo BLE security tickets

Security review of the BLE pairing/bonding stack (`modules/halo/src/ble_connection.c`,
`modules/halo/src/ble_security.c`). One folder per ticket: `ticket.md` (Jira-style: how to
fix), `hack.md` (how to exploit/verify on real hardware), `code/` (tooling).

**Keep this folder out of public release builds/docs.** It contains working exploit
instructions.

## Why the whole device reduces to these tickets

The privileged GATT surface (Lua REPL write characteristic, SMP/OTA) is gated at
`SEC_LVL(WP, UNAUTH)` — an *encrypted but unauthenticated* link is enough, because the
device's IO capability (`GAP_IO_CAP_NO_INPUT_NO_OUTPUT`, no keyboard) forces LE Secure
Connections **Just Works**, and `ble_lua.c` documents that as the hard ceiling. Therefore:

> Device security == bond-table integrity + control over *who may pair*.

Every ticket below attacks one of those two things.

## Tickets

| ID | Title | Severity | Attack type | One-liner |
|----|-------|----------|-------------|-----------|
| [S-0001](S-0001/) | Pairing has zero MITM protection (Just Works); Numeric Compare auto-accepted | **High** | Active MITM | Pairing window = 60 s of free MITM-able bonding; device owns a display that could show a passkey |
| [S-0002](S-0002/) | Bond slot takeover via spoofed-identity re-pair | **High** | Spoof + re-pair | Identity = raw address memcmp; spoof a bonded peer's public address, re-pair, overwrite its keys |
| [S-0003](S-0003/) | Local IRK brute-forceable from public advertising address (+ hardcoded second IRK) | Medium | Passive math | IRK = EUI fwd+rev; 3 of 5 unknown bytes already in the adv address → 2^16 candidates |
| [S-0004](S-0004/) | Permanent static identity address → lifetime device tracking | Medium | Passive | `GAPM_STATIC_ADDR`, never rotates; `privacy_cfg` configured but unused |
| [S-0005](S-0005/) | Bond keys in plaintext, readable over Lua REPL | **High** (post-bond theft) | REPL file read | `frame.file.open('settings','r')` has no path restriction → dump `/lfs/settings` → all peers' LTK/IRK |
| [S-0006](S-0006/) | Hardening bundle: 4 low findings | Low | n/a | `pairing_lvl` mislabeled AUTH; NC auto-true landmine; SE-fail fallback `11:22:33`; `#ifdef MCU_BOOT` dead code |

## Test rig

- The Halo glasses under test, charged, flashing allowed (dev build with logs helps but is
  not required; production attack surface is what matters).
- Linux host (bare metal preferred; VM USB passthrough is flaky for BLE).
- Bluetooth adapter(s): 1 required, **2 for S-0001** (full MITM relay).
- Python 3.10+ with `uv` (scripts carry inline deps; `uv run script.py`).
- A phone you control for the "victim peer" role. Prefer an Android with **public address**
  for S-0002 (see that ticket); iPhone works as victim for S-0001/S-0004/S-0005.
- Optional: `btmon` (BlueZ) for over-the-air confirmation.

## Suggested order when the glasses arrive

1. Pair your phone normally (baseline bond exists).
2. S-0005 first (easiest win, proves the whole trust model): already-bonded phone works as
   attacker. If `/lfs/settings` dumps, the ticket reproduces.
3. S-0001 (needs the pairing window: hold the button 5 s).
4. S-0002 (needs a public-address peer address to spoof).
5. S-0003 / S-0004 (passive, any time).
6. S-0006 last: run after patches land to confirm they landed.

## Fix verification

Each `ticket.md` has a "Verify the fix" section. After patching: rebuild, flash OTA
(build/flash skills), re-run the ticket's `hack.md` steps — every one must now fail —
then run `S-0006/code/check_hardening.sh` from the repo root as a regression gate for the
source-level anti-patterns.
