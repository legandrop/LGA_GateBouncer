# LGA GateBouncer

LGA GateBouncer is a native Windows desktop application under development for reviewing application access policies. The current build **does not protect your computer or filter traffic**. Firewall enforcement, service deployment and coverage validation are still in development.

Live mode lists running processes with the available local metadata and lets you search, filter and sort them. Import analyzes a file you choose and saves reviewed candidates locally, always inactive. Saved reviews survive reopening. Network history and engine status remain explicitly unavailable when their sources cannot be authenticated; an empty list does not prove that no connections occurred.

The six views — Processes, Pending, Activity, Rules, Import and Settings — also offer a separate Simulation mode. Its synthetic fixtures, sample decisions and reversible cleanup stay in session memory. Closing the application discards these demo changes.

The NVIDIA explanation workflow uses local sample responses. No API key can be entered, no credentials are read or saved, and no external request is made. An explanation never decides whether to allow an application or verifies its safety.

## Build on Windows

The existing development configuration uses Qt 6.8.2 (MinGW 64-bit), MinGW 13.1, Ninja and CMake 3.21 or later. `compilar.bat` checks the Qt, compiler and Ninja locations declared at the top of the script; edit those locations if your SDK is installed elsewhere. CMake must be available on `PATH`.

```bat
compilar.bat --no-run
```

The script builds `build\GateBouncer.exe` and never starts the application. Set `GATEBOUNCER_BUILD_DIR` to choose another build directory. Qt runtime libraries and its Windows platform plugin are required to run the resulting executable; this repository does not include a runtime distribution or installer.

See [Simulation behavior](docs/Simulation.md) for the meaning of the displayed data and [Third-party notices](docs/ThirdPartyNotices.md) for font and framework information.
