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

In **Live** mode, the Processes, Pending, Activity and Rules views read the engine:

- **Processes** lists running applications and every application with a rule or a request, with its policy.
- **Pending** lists blocked applications waiting for a decision. A new request also shows a notice in the bottom-right
  corner of the screen, even when the window is hidden in the tray. It stays until you choose Allow or Block, and it
  does not take focus. Closing it keeps the application blocked and pending.
- The notice's **Apply to** list sets the rule's reach: **This app, any version** (same signed publisher and file name,
  in any folder, so updates don't ask again), **This file only** (the exact path), or **All apps from** the publisher.
  Applications without a valid signature can only get a rule for the exact file.
- The notice's **For** list makes the decision temporary: 1, 5, 10, 15 or 30 minutes, 1 hour, or until the engine
  restarts. When it expires the rule is removed and the application asks again.
- **What is this? Ask AI** on the notice asks NVIDIA, with your own NVIDIA API key, what the application is, why it
  connects and what you gain or lose by allowing it. The answer only helps you decide: it never allows or blocks
  anything and it can be wrong. See [AI explanations](docs/Explanations.md) for exactly what is sent.
- **Activity** shows blocked attempts and rule changes recorded by the engine. Allowed connections are not recorded.
- **Rules** lists saved Allow and Block rules, including rules for an app in any version or for a whole publisher, and
  how long a temporary rule has left. You can change or remove a rule.
- **Import** reads NetLimiter's settings file (`nl_settings.xml`) and turns its firewall rules for single applications
  into GateBouncer rules. Rules limited to addresses, ports, zones or schedules, Ask rules and incoming-only rules are
  listed with the reason and not imported.
- **Settings** switches between asking for unknown applications and letting them connect, and holds the AI
  explanation setup: the key, what is sent, the model, the language and whether notices ask automatically.

A separate **Simulation** mode shows the views with synthetic data that stays in session memory.

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
the Windows platform plugin are required to run the window. There is no installer package yet: copy both programs and
the Qt runtime to a protected folder and run `GateBouncerEngine.exe --install`; later versions are applied with
`GateBouncerEngine.exe --update <folder>` (see the [engine documentation](engine/README.md)).

## Earlier driver-based design

The `service`, `driver` and `controller` folders hold an earlier design built around a kernel callout driver that held
each connection until you decided. Loading a new kernel driver on current Windows requires a Microsoft-signed package,
so that design is paused. Its documentation remains in [service](service/README.md) and [driver](driver/README.md).

See [Simulation behavior](docs/Simulation.md) and [Third-party notices](docs/ThirdPartyNotices.md).
