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
- **Rules by signature.** Besides the exact path, a rule can cover an app in any folder (same signer and file name) or
  every app from a signer. WFP only matches paths, so these rules live in the engine: when an executable without a
  path rule is blocked, the engine checks its embedded Authenticode signature (offline, no revocation lookup) and, if
  a signature rule matches, adds the filter for that path. The first attempt is still lost; the next one uses the rule.
  These paths are saved with the rule and verified again at every engine start.
- **Temporary rules.** A decision can last from one minute to a week, or until the engine restarts. The engine checks
  expiry every ten seconds; an expired rule is removed (with the paths it covered) and the application asks again.
  Until-restart rules are never written to the rules file.
- **The window's own requests.** The installed `GateBouncer.exe` may connect to TCP port 443 only, for AI
  explanations, without a request of its own. Nothing else about it is exempt.

Filters are persistent. If the service stops or crashes, unknown applications stay blocked and saved rules keep
working. Uninstalling removes every GateBouncer filter.

## Install and recovery

From an administrator command prompt, in the folder that holds `GateBouncerEngine.exe` and `GateBouncer.exe`:

```bat
GateBouncerEngine.exe --install
GateBouncerEngine.exe --update <folder>
GateBouncerEngine.exe --uninstall
GateBouncerEngine.exe --remove-filters
```

`--update <folder>` applies a newer build to an existing installation: it stops the service, copies the folder into
the installed one (files that did not change are left alone; a file in use, such as the open window, is renamed to
`.old` and replaced), and starts the service again. Saved rules are kept. Restart the window afterwards to use its new
version. While the service is stopped, the persistent filters keep blocking unknown applications.
`--send <fields>...` sends one request over the local channel and prints the answer, for scripts and administration
(for example `--send STATUS`, or from an administrator prompt `--send REMOVE <path>`).

`--install` registers and starts the `LGAGateBouncer` service (LocalSystem, automatic start, depends on BFE) and
registers `GateBouncer.exe --start-minimized` to start at sign-in for every user, because the service has no desktop
and only the window can show requests. `--uninstall` removes that entry too. The
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
or an elevated process, can change rules (`DECIDE`, `REMOVE`, `MODE`). `DECIDE` takes the reach of the rule (`path`,
`app` or `publisher`), the executable and optionally how long it lasts (`always`, `restart` or a number of seconds,
from 60 to 604800); the engine reads the signer from the file itself and never trusts a signer sent by the client.
`RULES` reports each rule's expiry (0 permanent, -1 until restart, otherwise Unix time). That check uses the client's
executable path:
it keeps other programs from changing rules by accident, but it is not a boundary against malicious software already
running under your account, which could start the window and inject code into it.

## Tests

`--console --dynamic` runs the engine in a dynamic WFP session: everything it adds disappears when it exits. With
`--scope <exe>` only that executable asks before connecting, so the rest of the computer is never affected.
With the service installed and running, a console engine shares its filters, so test it on a machine without the
service; `--pipe <name>` gives the console engine its own channel name.
`GateBouncerEngineSelfTest.exe` checks the full cycle on a copy of an HTTP client, also in a dynamic session.
`--signer <exe>` prints the signer that signature rules use for that file; it needs no administrator rights.

## Limits

- The first attempt of an unknown application fails; there is no waiting connection.
- Path rules match the executable path, not its content. A path covered by a signature rule is checked every minute:
  if the file changed (NTFS change time, file ID or size), its signature is verified again and the filter is withdrawn
  when it no longer matches. Every ten minutes all covered files are verified again regardless. Between checks a
  replaced file keeps the filter, and a connection opened in that time stays open. Software already running under
  your account can also start the window and decide for you (see Local channel). Inbound connections are left to
  Windows Defender Firewall.
- Only embedded signatures count. Windows tools signed only through a catalog (such as `powershell.exe`) are treated as
  unsigned, and signers whose name starts with Microsoft do not accept a whole-publisher rule, because it would
  include Windows tools that download files.
- Another WFP provider with a hard permit can override a block. An administrator, or software running as
  administrator, can remove the filters.
- Ask mode for every application has not yet been validated on a clean machine.

Build with `compilar.bat --no-run` (Visual Studio 2022 or its Build Tools and the Windows SDK).
