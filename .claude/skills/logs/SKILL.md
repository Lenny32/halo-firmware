---
name: logs
description: Fetch persisted /lfs log files from a Halo device over BLE (frame.log Lua API). Use for post-flash diagnostics, crash investigation, or checking what the app logged.
---

# Fetch Halo device logs

> **Currently disabled on `main`**: the FS log backend is switched off
> (`CONFIG_LOG_BACKEND_FS=n` in `applications/halo/prj.conf`, since `8222e97`)
> because its `/lfs` writes stalled audio sessions and cost 2×16 KB of `/lfs`.
> On such builds `frame.log` does not exist and this skill fails at the first
> Lua call. To use it, build with `CONFIG_LOG_BACKEND_FS=y` (re-enable the
> commented block in `prj.conf`) and flash that image first.

Self-contained script — run with `uv run` from any directory (deps resolve
from PyPI via inline metadata):

```
uv run alif/.claude/skills/logs/fetch_logs.py --name "Halo AB"
```

Prints the device's `/lfs` log file list, streams out each file's contents,
then resets the Lua VM so the device resumes its app.

## Notes

- The script sends a **break signal** after connecting (a running `main.lua`
  loop would otherwise swallow REPL commands) and a **Lua-VM reset** when done
  — the device ends up back in its normal app.
- Streaming is chunked over the REPL (`--chunk`, default 180 bytes per read),
  so large logs take a while.
- Always pass `--name`; same device etiquette as the `flash` skill: prefer
  the Halo Dev Kit; touch real units only with explicit user go-ahead.

## Console UART (wired dev kit)

A wired dev kit's console UART (115200 8N1) carries the Zephyr log output
live, with no BLE link or FS log backend needed, so it keeps logging across
resets. Leave it running in the background while reproducing a problem:

```
uv run alif/.claude/skills/logs/uart_console.py --out console.log
```

It timestamps each line and autodetects the console port as the USB serial
port that is not the SE-UART named in `$SETOOLS_DIR/isp_config_data.cfg`
(pass `--port` otherwise). The console is silent until the firmware logs
something. To reset the dev kit, see the `flash` skill (`reset_devkit.sh`).
