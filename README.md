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
- **Activity** shows blocked attempts and rule changes recorded by the engine. Allowed connections are not recorded.
- **Rules** lists saved Allow and Block rules, including rules for an app in any version or for a whole publisher. You
  can change or remove a rule, and switch between asking for unknown applications and allowing them.

Import offers explicitly selected Structural XML and NetLimiter QName source profiles. It analyzes the chosen file in
the background and saves reviewed candidates locally, always inactive; imported candidates do not become engine rules
yet. See [Inactive import review](docs/Import.md).

A separate **Simulation** mode shows the six views with synthetic data that stays in session memory. Settings also holds
the optional NVIDIA explanation configuration, which is not connected to the engine's requests yet. An explanation
never grants access or verifies an application's safety.

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
the Windows platform plugin are required to run the window. There is no installer yet.

## Earlier driver-based design

The `service`, `driver` and `controller` folders hold an earlier design built around a kernel callout driver that held
each connection until you decided. Loading a new kernel driver on current Windows requires a Microsoft-signed package,
so that design is paused. Its documentation remains in [service](service/README.md) and [driver](driver/README.md).

See [Simulation behavior](docs/Simulation.md) and [Third-party notices](docs/ThirdPartyNotices.md).
