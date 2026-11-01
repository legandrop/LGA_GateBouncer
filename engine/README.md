# Driverless firewall engine

`GateBouncerEngine.exe` is the firewall that GateBouncer uses today. It needs **no kernel driver**: it uses the
Windows Filtering Platform management API (`fwpuclnt.dll`) from an elevated user-mode service, the same approach as
other driverless Windows firewalls.

## How it works

- At startup the engine adds its own WFP provider and sublayer and rebuilds every filter from the saved rules.
- **Ask mode** adds a low-weight outbound Block filter at the ALE connect layers (IPv4 and IPv6). Loopback and Windows
  services running as SYSTEM, LocalService or NetworkService are permitted, so DNS, DHCP and updates keep working.
- Each application rule is a filter on the executable path (`FWPM_CONDITION_ALE_APP_ID`): Allow outweighs the default
  block, and an explicit Block outweighs everything else in the sublayer, including the Windows services permit.
- The engine subscribes to WFP drop events. A drop caused by the default block becomes a **pending request** for that
  executable; a drop caused by a Block rule is recorded as activity.
- **Allow and Block apply to the next attempt.** Without a driver, a connection cannot be held while you decide: the
  attempt that produced the request has already failed. Most applications retry on their own.

Filters are persistent. If the service stops or crashes, unknown applications stay blocked and saved rules keep
working. Uninstalling removes every GateBouncer filter.

## Install and recovery

From an administrator command prompt, in the folder that holds `GateBouncerEngine.exe` and `GateBouncer.exe`:

```bat
GateBouncerEngine.exe --install
GateBouncerEngine.exe --uninstall
GateBouncerEngine.exe --remove-filters
```

`--install` registers and starts the `LGAGateBouncer` service (LocalSystem, automatic start, depends on BFE). The
service runs as SYSTEM and trusts the window next to it, so `--install` refuses a folder that a standard user can
change, or replace through one of the folders above it; copy both programs to a folder such as `C:\Program Files\LGA GateBouncer` first, or pass
`--allow-unprotected-folder` to accept that risk. `--uninstall` does nothing unless the service stops.
`--remove-filters` is the emergency switch: it removes every GateBouncer filter in one step and leaves the network as if
GateBouncer were not installed until the service starts again. Rules are saved in
`%ProgramData%\LGA GateBouncer\rules.tsv`; the engine refuses that folder if anyone other than SYSTEM or
administrators can change it.

Startup rebuilds every filter in a single WFP transaction: if anything fails, the previous filters stay as they were.
A rule whose executable is missing (uninstalled, updated to a new folder, unmounted drive) is kept but skipped, so
that path asks again.

## Local channel

The desktop window talks to the engine over the named pipe `\\.\pipe\LGA.GateBouncer.Engine`: one UTF-8 request
line, tab-separated fields, and a reply terminated by `END`. Interactive users can read status, pending requests,
rules and activity, but cannot create instances of the pipe. Only the installed `GateBouncer.exe` next to the engine,
or an elevated process, can change rules (`DECIDE`, `REMOVE`, `MODE`). That check uses the client's executable path:
it keeps other programs from changing rules by accident, but it is not a boundary against malicious software already
running under your account, which could start the window and inject code into it.

## Tests

`--console --dynamic` runs the engine in a dynamic WFP session: everything it adds disappears when it exits. With
`--scope <exe>` only that executable asks before connecting, so the rest of the computer is never affected.
`GateBouncerEngineSelfTest.exe` checks the full cycle on a copy of an HTTP client, also in a dynamic session.

## Limits

- The first attempt of an unknown application fails; there is no waiting connection.
- Rules match the executable path, not its content or publisher. Inbound connections are left to Windows Defender
  Firewall.
- Another WFP provider with a hard permit can override a block. An administrator, or software running as
  administrator, can remove the filters.
- Ask mode for every application has not yet been validated on a clean machine.

Build with `compilar.bat --no-run` (Visual Studio 2022 or its Build Tools and the Windows SDK).
