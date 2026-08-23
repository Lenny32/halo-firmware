# S-0005 — Bond keys in plaintext, readable over the Lua REPL

| Field | Value |
|---|---|
| **Severity** | High |
| **Component** | `modules/halo/src/lua_file.c`, `modules/halo/src/file_manager.c`, `modules/halo/src/ble_security.c` |
| **CWE** | CWE-312 (cleartext storage of sensitive information), CWE-552 (files accessible to external parties) |
| **Reporter** | Internal security review |

## Summary

All bond material (per-slot LTK / IRK / CSRK) is persisted **unencrypted** in the
Zephyr settings file `/lfs/settings`. The Lua file API exposed on the BLE REPL —
available to *any* bonded peer — can open **any path under `/lfs`**, with no
restriction, path traversal guard, or blocklist. Result: a single moment of
privileged access (any bonded device, anything reached via S-0001/S-0002, or any
compromised legitimate host) exfiltrates the LTKs of **all five** bonded peers —
including keys belonging to devices that were used once long ago.

With a peer's LTK, the attacker can passively decrypt that peer's future connections
to the glasses and/or impersonate the peer device (identity + key = full clone for
bonds matched by address, see S-0002 scope analysis).

## Root cause

- `ble_security.c:102-133` — `bond_slot_persist()` stores `b->keys` (the raw
  `gapc_pairing_keys_t`) via `halo_settings_set()` → plaintext base64 in
  `/lfs/settings` (`CONFIG_SETTINGS_FILE_PATH="/lfs/settings"`, prj.conf:87).
- `lua_file.c:47-55` — `get_full_path()` simply concatenates mount point + user
  string. No normalization, no `..` rejection, no blocklist.
  `frame.file.open("settings", "r")` therefore opens the settings file; worse,
  `frame.file.open("../../../ble/settings", ...)`-style traversal is not rejected
  either (currently moot since `/lfs` is the mount root, but the guard belongs there
  regardless).
- `lua_file.c:71-…` — `file:read(n)` binary mode round-trips arbitrary bytes
  (designed for PCM) — perfect exfiltration channel in 64-byte REPL prints.
- Design comment in `file_manager.c:349-350` — the settings file is deliberately
  *preserved* even by "remove all user files", so key material outlives user-facing
  wipes short of factory reset.

## Impact

- **Confidentiality**: passive decryption of any bonded peer's link (capture
  CONNECT_IND + LL_ENC_REQ/…, feed stored LTK into a sniffer e.g. crackle-style).
- **Integrity/authenticity**: the extracted identity address + (for address-matched
  bonds) LTK clone a peer; combined with S-0002 the attacker stops being
  race-dependent — they now pass the legitimate encryption handshake.
- **Persistence amplification**: keys for evicted-or-rarely-used peers remain until
  slot eviction, so one exfiltration covers the whole social graph of the glasses.

## Fix

Two independent layers; do both.

1. **Close the read path (access control).**
   - In `lua_file.c` `get_full_path()`: reject `..` components, reject an explicit
     blocklist (`settings`, anything under the settings prefix) and anything that
     fails `fs_realpath`-style normalization outside `/lfs/user/…` — or cleaner:
     introduce a `lua_file` chroot subdirectory and route all Lua file I/O there.
   - The REPL is a feature for all bonded peers by design; treat key material as
     outside its reach.
2. **Confidentiality at rest (crypto).**
   - Encrypt `gapc_pairing_keys_t` before `halo_settings_set`, with a device-unique
     key obtained from the SE service at init (`se_service_get_rnd_num`-seeded key
     persisted once in SE-backed storage, or an SE-wrapped blob if the Alif SE API
     exposes one). AES-128-CTR/HMAC or AES-GCM; nonce stored alongside.
   - This also covers UART log depth (S-0003) and lost-device physical readout.

Migration: on first boot after the fix, detect plaintext slots (`valid_key_bf`
sanity + magic), re-encrypt in place, log once. Size this into `sec_ctx` magic
versioning (C6) deliberately.

## Verify the fix

- `hack.md` step 3 must return `cannot open file 'settings'` (or the file returns
  ciphertext — verify by grepping the dump for the known LTK pattern from a
  just-paired peer in `btmon`; must be absent).
- Existing bonds must still reconnect after the migration OTA (PAIRING.md §6 item 1).
- `file.listdir("")` must not expose restricted paths to REPL enumeration either.

## References

- Review finding M4 (upgraded: verified primitives make this High)
- `ble_security.c:102-133`, `lua_file.c:47-55,180-230`, `prj.conf:85-87`
