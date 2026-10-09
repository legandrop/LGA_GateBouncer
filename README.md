# LGA GateBouncer

LGA GateBouncer is a native Windows desktop application under development for reviewing application access policies. The desktop build **does not provide validated protection**. The experimental policy service requires a separately prepared deployment; building the application does not install or activate it.

Live mode lists running processes with the available local metadata and lets you search, filter and sort them. Import offers explicitly selected Structural XML and NetLimiter QName source profiles. It analyzes the chosen file in the background, retains known source facts and unknown constraints, and saves reviewed candidates locally, always inactive. Saved facts and review choices survive reopening. Original Deny and Block actions remain distinct from your review choice. Import compatibility and conversion to an enforced policy are not validated. See [Inactive import review](docs/Import.md) for the workflow and limits.

Settings lets you explicitly select authenticated engine status or the separate decision-record source. The latter displays bounded pending and rule snapshots, with observed attempts and coverage gaps when that source is available. Attempts, authorization and traffic are distinct; a missing source or an empty list does not prove that no connections occurred. The ordinary desktop window cannot allow or block a service request. It can queue a request reference for a separately enabled administrator reviewer. Queueing or requesting that reviewer to start does not confirm a policy change or protection.

Direction-aware service records distinguish outbound attempts, inbound attempts and local listen observations. Permanent path review offers Outbound, Inbound and an explicit Both selection. Outbound Allow is limited to unicast destinations; Both broadens the rule to inbound access as well. Queuing a request and changing a selection grant no permission. The direction-aware backend remains disabled pending operating-system coverage validation.

The six views — Processes, Pending, Activity, Rules, Import and Settings — also offer a separate Simulation mode. Its synthetic fixtures, sample decisions and reversible cleanup stay in session memory. Closing the application discards these demo changes.

The NVIDIA explanation workflow in this desktop build uses local sample responses. No API key can be entered, no credentials are read or saved, and no external request is made. An explanation never decides whether to allow an application or verifies its safety.

When a tray is available, closing hides the window in the notification area. If the tray is unavailable, closing exits after active local work finishes. Quit also waits for that work to finish. The desktop startup preference concerns this window, separately from deployment and startup of the policy service. These controls do not establish that a service is running or that filtering is active.

## Build on Windows

The existing development configuration uses Qt 6.8.2 (MinGW 64-bit), MinGW 13.1, Ninja and CMake 3.21 or later. `compilar.bat` checks the Qt, compiler and Ninja locations declared at the top of the script; edit those locations if your SDK is installed elsewhere. CMake must be available on `PATH`.

```bat
compilar.bat --no-run
```

The script builds `build\GateBouncer.exe` and separate decision-review components, without starting them. Set `GATEBOUNCER_BUILD_DIR` to choose another build directory. Qt runtime libraries and its Windows platform plugin are required to run the resulting executable; this repository does not include a runtime distribution or installer. Elevated review additionally requires a protected, verified deployment, rather than binaries copied into an arbitrary directory.

The experimental policy service uses a separate MSVC build and serialized IPC. See its [build and scope](service/README.md). Tests and compilation do not establish enforcement, boot coverage or coexistence with another firewall.

See [Simulation behavior](docs/Simulation.md) for the meaning of sample data and [Third-party notices](docs/ThirdPartyNotices.md) for font and framework information.
