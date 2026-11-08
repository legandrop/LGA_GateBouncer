# LGA GateBouncer

LGA GateBouncer is a native Windows per-application firewall under development. When an application without a rule
tries to connect, GateBouncer blocks it and asks you; **Allow** or **Block** becomes a permanent rule for that
executable. It has no bandwidth control.

The firewall engine needs no kernel driver: it uses the Windows Filtering Platform from an elevated service. Because a
driverless firewall cannot hold a connection while it waits, the attempt that produced a request has already been
blocked, and your decision applies to the application's next attempt. Most applications retry on their own. See the
[engine documentation](engine/README.md) for how it works, how to install or remove it, and its limits.

See the one-page [Roadmap](Roadmap.md) for verified and pending work, and the [documentation index](docs/index.md).

## The window

The window reads the engine and has five sections; the sidebar shows the state of each one at a glance.

- **Protection** says whether GateBouncer is protecting the PC, lists the applications waiting for you with Block and
  Allow, and sums up your rules and what was blocked recently. Block and Allow there use the choices the notice would
  preselect; open the request to choose another.
- **Requests** lists blocked applications waiting for a decision, each with its signature, folder, attempts, the server
  it wanted, the program that started it and the AI explanation, next to the same **Apply to**, **For** and
  **Destination** choices as the notice.
- A new request also shows a notice in the bottom-right corner of the screen, even when the window is hidden in the
  tray. It stays until you choose Allow or Block, and it does not take focus. Closing it keeps the application blocked
  and pending.
- The notice shows where the application tried to connect: the server name it looked up just before (when Windows
  resolved it), the address and port, and whether that is the **Internet**, your **Local network** or **Tailscale**.
  No name means the application connected straight to an address or resolved it on its own.
- Connections to the local network (other computers, printers and storage at home or at the office, and Tailscale
  devices) are allowed without asking by default. A Block rule for an application still applies there. You can turn
  this off in Settings.
- The notice's **Apply to** list sets the rule's reach: **This app, any version** (same signed publisher and file name,
  in any folder, so updates don't ask again), **This file only** (the exact path), or **All apps from** the publisher.
  A program inside a Git repository, also in one of its worktrees, adds **This app in** the repository: the same file
  name anywhere inside it, signed or not, so every later build there (a build folder, a deploy folder, a worktree per
  branch) connects without asking. For an unsigned program in a repository it is the preselected choice; any other
  application without a valid signature can only get a rule for the exact file. The notice spells out the whole
  folder before you decide.
- **Trusted folders.** A folder rule covers the programs with one file name in a folder and its subfolders, or every
  program there, including programs built or copied there later. The notice offers one program in its repository; a
  rule for every program in a folder is added by hand in Apps. It is checked against where each file really is: a
  junction or link inside the folder that points elsewhere does not carry the trust out, and a path that goes through
  a link is not covered. A whole drive, network and removable drives, and system or user folders (Windows, Program
  Files, ProgramData, Users, each profile, AppData, Desktop, Documents, Downloads, Temp and the Recycle Bin) cannot be
  trusted, nor a folder inside Windows, Downloads or Temp, nor a folder that holds any of them. A rule for a file, an
  app or a publisher comes first; between two folder rules the deeper folder wins, and a rule saved later that comes
  first takes over the programs a folder had already covered. Anything that can write to a trusted folder gets the
  same access, so trust only folders where you build or install programs yourself.
- The notice's **Destination** list limits a rule to where the application tried to go: **Only** that server, **Only
  \*.domain** (the server's domain and its subdomains) or, without a name, **Only** that address. An application with
  destination rules asks again for every new destination, so you can allow a tool to reach your own services and
  block everything else it tries. A new address of a server you already allowed does not ask: its first attempt may
  fail, and the next one connects. **Any destination** decides for the whole application and replaces its destination
  rules.
- The notice can be dragged anywhere and widened from its left or right edge; it remembers where you left it. It always
  stays above the taskbar, even when an explanation makes it taller.
- The notice's **For** list makes the decision temporary: 1, 5, 10, 15 or 30 minutes, 1 hour, or until the engine
  restarts. When it expires the rule is removed and the application asks again.
- **Ask AI** on the notice (or automatically, if you choose so in Settings) asks an AI model (Anthropic's Claude or NVIDIA's catalog, with your own API
  key) what the application is, why it connects and what you gain or lose by allowing it. The answer only helps you decide: it never allows or blocks
  anything and it can be wrong. See [AI explanations](docs/Explanations.md) for exactly what is sent.
- **Apps** lists every application with a rule: for one file, for an app in any version, for a whole publisher, for a
  trusted folder, or per server. Filters show Allow, Block, per-server, temporary and folder rules, and the applications
  running in your session without a rule. An app's page shows its rule, or each of its server rules, and lets you
  remove them. **Folders** lists the folder rules and **Trust a folder…** adds one for any folder, for one program name
  or for every program; the page of a rule for one file inside a repository offers to cover all its builds.
- Apps and Activity are tables: drag a column edge to widen it (the window remembers it), and only the rows scroll.
- **Activity** shows blocked attempts and decisions recorded by the engine since it started; repeated attempts by the
  same application to the same address are counted on one line. Allowed connections are not recorded.
- **Settings** switches between asking for unknown applications and letting them connect, sets whether the local
  network asks, and holds the AI explanation setup: the key, consent to send the details, the model, the language and
  whether notices ask automatically.
- **Import from NetLimiter** (in Settings) reads NetLimiter's settings file (`nl_settings.xml`) and turns its firewall
  rules for single applications into GateBouncer rules. Rules limited to addresses, ports, zones or schedules, Ask
  rules and incoming-only rules are listed with the reason and not imported.

When a tray is available, closing hides the window in the notification area. Installing the engine registers the
window to start at sign-in, minimized to the tray; opening it again brings the running window to the front.

## Build on Windows

The desktop application uses Qt 6.8.2 (MinGW 64-bit), MinGW 13.1, Ninja and CMake 3.21 or later. `compilar.bat`
checks the Qt, compiler and Ninja locations declared at the top of the script.

```bat
compilar.bat --no-run
engine\compilar.bat --no-run
```

The first builds `GateBouncer.exe` and the other desktop components without starting them; set `GATEBOUNCER_BUILD_DIR`
to choose another build directory. The second builds `GateBouncerEngine.exe` with Visual Studio 2022 (or its Build
Tools) and the Windows SDK; set `GATEBOUNCER_ENGINE_BUILD_DIR` to choose its build directory. Qt runtime libraries and
the Windows platform plugin are required to run the window. `instalador.bat --no-run` builds both programs and an
installer package with Inno Setup 6 (it runs nothing). Without the package, copy both programs and the Qt runtime to a
protected folder and run `GateBouncerEngine.exe --install`; later versions are applied with
`GateBouncerEngine.exe --update <folder>` (see the [engine documentation](engine/README.md)).

## Earlier driver-based design

The `service`, `driver` and `controller` folders hold an earlier design built around a kernel callout driver that held
each connection until you decided. Loading a new kernel driver on current Windows requires a Microsoft-signed package,
so that design is paused. Its documentation remains in [service](service/README.md) and [driver](driver/README.md).

See [Simulation behavior](docs/Simulation.md) and [Third-party notices](docs/ThirdPartyNotices.md).
