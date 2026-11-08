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
  A Block never applies to loopback (`FWP_CONDITION_FLAG_IS_LOOPBACK` excluded): an application that talks to itself
  on `127.0.0.1`, such as Nuke's Frame Server, keeps working while its internet access is blocked.
- The engine subscribes to WFP drop events. A drop caused by the default block becomes a **pending request** for that
  executable; a drop caused by a Block rule is recorded as activity.
- **Allow and Block apply to the next attempt.** Without a driver, a connection cannot be held while you decide: the
  attempt that produced the request has already failed. Most applications retry on their own.
- **Rules by signature.** Besides the exact path, a rule can cover an app in any folder (same signer and file name) or
  every app from a signer. WFP only matches paths, so these rules live in the engine: when an executable without a
  path rule is blocked, the engine checks its signature (offline, no revocation lookup; see Limits) and, if
  a signature rule matches, adds the filter for that path. The first attempt is still lost; the next one uses the rule.
  These paths are saved with the rule and verified again at every engine start.
- **Folder rules.** A rule can also cover every executable inside a folder and its subfolders, or only the ones with one
  file name, for unsigned programs that are rebuilt in new folders (a worktree per branch). They work like signature
  rules: an executable with no rule of its own is checked when it is blocked and, if a folder rule holds it, gets the
  filter for its path. Folder rules come last: a path, app or publisher rule decides first, and between two folder rules
  the deeper folder wins (in the same folder, the one that names the executable; then Block). The folder and each
  executable are compared by their final path (`GetFinalPathNameByHandleW`, with the volume by its GUID): a junction
  or symlink inside the folder that leads outside does not extend the trust, a reported path that goes through a link
  is not covered, a folder later replaced by a link stops matching, and the rule stays bound to the volume where it was
  created. The engine refuses a drive root or a whole volume (also one mounted in a folder), network, removable and
  optical drives, and system or user folders (the Windows folder, Program Files, ProgramData, the profiles folder, each
  profile of local, domain and Entra ID accounts, AppData, Desktop, Documents, Downloads, Temp and each drive's Recycle
  Bin, also when moved), any folder inside Windows, Downloads or Temp, and any folder that contains one of them; a
  Downloads or Temp that is a whole drive makes the whole drive refused. The service only opens drive-letter paths on
  local fixed disks while checking: never a network path or a pipe, even if a user's folder settings point there.
  Covered paths are rechecked like signature ones: a file that left the folder loses its filter, while a rebuilt file
  in the same place keeps it. When a rule that comes first is saved later (a signature rule that matches, a deeper
  folder rule, or the same folder naming the executable), it takes over the files a folder rule had covered right away,
  with its own action; for a signature rule the signature is verified again on the file first. Destination rules for
  the same app release the file, so that its next attempt is decided per destination. A folder on a volume mounted in
  another folder is refused, because WFP reports its programs without a drive letter. Saved as `folder` lines in
  `rules.tsv` (version 3; an older engine skips them and keeps a `.bad` copy); a line for a whole volume is refused
  when loading.
- **Local network without asking** (on by default): an outbound permit filter for private ranges (10/8, 172.16/12,
  192.168/16), link-local, multicast and broadcast, 100.64/10 (Tailscale) and fc00::/7, with the same weight as the
  Windows services permit, so an explicit Block rule still wins. Saved as `lan allow|ask` in `rules.tsv`.
- **Destination names.** The engine listens to the Microsoft-Windows-DNS-Client ETW provider (query completed events)
  and remembers which name each executable resolved to which addresses, in memory only. A pending request carries the
  name its application looked up for the blocked address. Windows delivers these events up to a second late, so a name
  missing when the attempt is blocked is filled in when the request is read. Applications that connect to an address
  directly or resolve names themselves (for example DNS over HTTPS) get no name. If the ETW session cannot start, the
  engine runs without names and reports it in `lastError`.
- **Destination rules.** Any rule (path, app or publisher) can carry a destination: an exact server name,
  `*.domain` (the domain and its subdomains; at least two labels, so `*.com` is rejected) or an IP address. An
  application with destination rules has no whole-application filter: each new destination is blocked and asked
  separately (one pending request per address). WFP matches addresses, not names, so the engine adds a filter for that
  application and that remote address ("destination permit": Allow weight 12, Block weight 15) when the application
  resolves a matching name (the DNS listener) or when a blocked attempt matches. A permit from a signature rule that
  allows is granted only after verifying the file's signature again, and is rechecked like a covered path. When one
  address serves an allowed and a blocked name, the Block stays. Permits unused for a week are removed. Deciding the
  whole application replaces its destination rules, and the other way round. Saved as `dest` and `grant` lines in
  `rules.tsv`.
- **Waiting for the name before asking.** The blocked attempt usually reaches the engine before the name lookup that
  preceded it (Windows delivers DNS events up to a second late). Without the name, a name rule such as
  `*.example.com` cannot match, and asking right away would create a request that the name resolves a moment later: the
  notice would open and close by itself and Requests would stay empty. So when an application in destination mode is
  blocked at an address with no known name and no IP rule, the engine holds that attempt for up to two seconds and
  decides when the name arrives: a matching rule grants the permit ("Allowed by rule … · next attempt connects" in the
  history), otherwise it asks, already with the server name. Without a name after two seconds (direct address,
  DNS over HTTPS) it asks as before. A request that a late name resolves anyway is also recorded as allowed by rule.
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
or an elevated process, can change rules (`DECIDE`, `FOLDER`, `REMOVE`, `MODE`, `LAN allow|ask`). `PENDING` rows end with the
destination name (empty when unknown); `STATUS` reports `lan` and a `names` line with DNS listener counters.
`DECIDE` takes the reach of the rule (`path`,
`app` or `publisher`), the executable and optionally how long it lasts (`always`, `restart` or a number of seconds,
from 60 to 604800) and a destination; the engine reads the signer from the file itself and never trusts a signer sent by the client.
`RULES` reports each rule's expiry (0 permanent, -1 until restart, otherwise Unix time), destination and path.
Protocol version 4 (`HELLO`) adds a last `PENDING` field, `app` or `destination`, for applications in destination mode.
Version 5 adds `FOLDER <allow|block> <folder> <file name, or * for every program> [duration]`, which validates and
resolves the folder itself, and `folder` rows in `RULES` (the folder as path, the file name or empty as name). The
permission check uses the client's
executable path:
it keeps other programs from changing rules by accident, but it is not a boundary against malicious software already
running under your account, which could start the window and inject code into it.

## Tests

`--console --dynamic` runs the engine in a dynamic WFP session: everything it adds disappears when it exits. With
`--scope <exe>` only that executable asks before connecting, so the rest of the computer is never affected.
With the service installed and running, a console engine shares its filters, so test it on a machine without the
service; `--pipe <name>` gives the console engine its own channel name.
`GateBouncerEngineSelfTest.exe` checks the full cycle on a copy of an HTTP client, also in a dynamic session.
`GateBouncerEngineUnitTest.exe [<work folder>]` checks engine logic that needs neither WFP nor the network
(destination matching, the wait for a destination name, and folder rules with real folders and junctions it creates in
the work folder and removes one by one); it needs no administrator rights and is safe with the service running.
`--signer <exe>` prints the signer that signature rules use for that file, and `--folder <folder> [<exe>]` says whether
a folder can be trusted and whether that executable is inside it; neither needs administrator rights.

## Limits

- The first attempt of an unknown application fails; there is no waiting connection. With destination rules, the
  first attempt to a new address of an allowed name can also fail when Windows reports the name lookup after the
  connection (up to a second); the engine then grants that address without asking and the next attempt connects. An
  application that gives up after one failed attempt per address has to be run again.
- Destination rules match names the application resolved through Windows. An application that resolves names itself
  (DNS over HTTPS) or connects straight to an address only matches IP destinations. Services that share an address
  (content delivery networks) share the decision for that address.
- Path rules match the executable path, not its content. A path covered by a signature rule is checked every minute:
  if the file changed (NTFS change time, file ID or size), its signature is verified again and the filter is withdrawn
  when it no longer matches. Every ten minutes all covered files are verified again regardless. Between checks a
  replaced file keeps the filter, and a connection opened in that time stays open. Software already running under
  your account can also start the window and decide for you (see Local channel). Inbound connections are left to
  Windows Defender Firewall.
- A folder rule trusts whatever can be written into that folder: any program saved there by you or by software running
  under your account gets the same access. Folders under `C:\` that users create can usually be written by every user
  of the computer. Renaming the trusted folder, even only its capitals, stops the rule from covering anything (it asks
  again) until it is created for the new name.
- Signature and folder rules reach a new path when its first attempt is blocked. With **Ask** turned off nothing is
  blocked by default, so they keep the paths they already cover, but a new copy or build is not covered until Ask is
  on again, and a path left by a removed rule has no filter of its own.
- Three kinds of signature count, all checked offline: the signature embedded in the file; a Windows catalog that
  lists the file (most Windows tools, such as `powershell.exe`, are signed this way); and, for Microsoft Store and
  other packaged apps under `C:\Program Files\WindowsApps`, the package publisher from the package's
  `AppxManifest.xml`. Windows verifies a package signature at installation and only the system writes to that folder,
  so **This app, any version** survives package updates. Signers whose name starts with Microsoft do not accept a
  whole-publisher rule, because it would include Windows tools that download files.
- Another WFP provider with a hard permit can override a block. An administrator, or software running as
  administrator, can remove the filters.

Build with `compilar.bat --no-run` (Visual Studio 2022 or its Build Tools and the Windows SDK).
