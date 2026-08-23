# How to exploit S-0005 — dump all bond keys over the Lua REPL

Goal: with any bonded connection to the glasses, read the plaintext Zephyr settings
file `/lfs/settings` through the Lua file API and extract every stored bond key
(LTK, IRK, CSRK, peer addresses).

## Preconditions

- Any bonded BLE host that can talk to the Lua REPL: your own phone after pairing,
  the S-0001 MITM bond, or the S-0002 hijacked slot. **No pairing window needed** —
  legitimate bonds are permanently REPL-authorized by design.
- Python + `brilliant-ble` (the repo's own tooling library, also used by
  `applications/halo/tools/verify.py`).

## Why it works

Verified firmware facts:

1. `frame.file.open(filename, mode)` prefixes `/lfs/` with **no path sanitation** —
   `get_full_path()` is a bare `snprintf("%s/%s")` (`lua_file.c`). No blocklist, no
   `..` filter.
2. The Zephyr settings file lives at `/lfs/settings`
   (`CONFIG_SETTINGS_FILE_PATH`, `applications/halo/prj.conf:87`) and contains
   base64-serialized blobs for `/lfs/ble/bond<i>_{keys,data,addr,meta}` written by
   `bond_slot_persist()` (plaintext key material in binary blobs).
3. REPL `print()` is returned over BLE notifications — a ready-made exfil channel.
4. `file:read(n)` with a number does raw binary reads (no newline dependency), so a
   full binary file round-trips as hex inside printed lines.

(About `..`: Lua string passes through `snprintf` into the FS layer; `settings`
alone is sufficient because the settings file sits at the mount root — no traversal
needed for this exploit, the missing guard is still worth fixing per ticket.)

## Steps

```bash
cd security/S-0005/code
uv run dump_settings.py --name "Halo"
```

The script:

1. Connects, sends the break signal (stops a running `main.lua` loop), then runs a
   one-liner REPL command (CL34Nl: newline terminates commands on-device):
   `f=frame.file.open('settings','r') ... f:read(n) hex->print ... f:close()`
2. Collects BLE print notifications, un-hexes, writes `settings_dump.bin`.
3. Parses the Zephyr settings-file format (`key=value\n`, values base64) and prints
   every `ble/bond*` entry, decoding the binary `gapc_pairing_keys_t`/`bond data`
   blobs by offsets documented in the Alif v1.2 header layout (keys struct:
   `valid_key_bf(1) | pairing_lvl(1) | LTK(16) | randnb(8), ediv(2),size(1) ... IRK(16)...`;
   the parser extracts LTK/IRK/CSRK and prints peer identity addresses from
   `bond<i>_addr`). If your header rev differs, adjust `OFF` at the top of the script.
4. Resets the Lua VM (`send_reset_signal`) so `main.lua` resumes on the glasses.

## Expected (vulnerable)

```
[+] Connected to Halo 9A
[+] settings file: 1384 bytes received
[+] parsed 12 settings entries
[!] /lfs/ble/bond0_keys: LTK=4f3a... IRK(csrk present)
[!] peer addr slot0: 7C:50:79:12:34:56
[VULNERABLE] plaintext bond keys exfiltrated over the REPL
```

Replay value: with a peer's extracted LTK + identity address you can (a) decrypt
that peer's future Halo connections passively (feed keys to a sniffer), and
(b) clone the peer against the glasses without S-0002's race — the legitimate LTK
answers `gapc_le_request_security` directly.

## Expected (patched)

Step (1) returns `nil` / `cannot open file 'settings'` (blocklist) or the dump
contains ciphertext (at-rest encryption) — the parser then finds no recognizable
bond structures and `btmon`-verified LTKs must not appear in the dump.

## Cleanup

`settings_dump.bin` now contains all bond keys of the glasses: treat it as a secret,
delete it after the test (`shred -u settings_dump.bin`), and re-pair/factory-reset
the glasses if you demonstrated cloning.
