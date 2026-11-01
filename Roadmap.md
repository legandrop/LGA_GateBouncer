# Roadmap

**No release yet.** Updated November 1, 2026.

**First usable version:** block unknown outbound connections and ask Allow/Block, keep permanent rules per application,
and provide searchable applications, activity and rule cleanup. Include safe NetLimiter import review and optional
NVIDIA explanations. Unknown imports stay inactive; advice never authorizes traffic. No bandwidth control.

The engine is driverless (Windows Filtering Platform from an elevated service). A decision applies to the
application's next attempt; the attempt that produced the request has already been blocked.

Checkboxes mean **verified on Windows**, not only implemented.

- [x] **Block, notify, Allow/Block.** Verified on Windows 11 with a test application in a dynamic WFP session: the
  unknown attempt is blocked, the drop event names the executable, the request appears in the window, Allow lets the
  next attempt connect, Block blocks it again, and removing the rule makes it ask again.
- [x] **Rules that survive updates.** Verified on Windows 11 in a dynamic WFP session with copies of a signed
  application in two folders: **This app, any version** and **All apps from** a publisher allow the copy in the other
  folder after its first blocked attempt, and keep working after the engine restarts. Unsigned applications only
  accept a rule for the exact file; Microsoft signers do not accept a whole-publisher rule.
- [ ] **Desktop notice.** Implemented: a notice that stays in the corner of the screen until you decide, shown by the
  window running in the tray, which the engine install registers at sign-in. Done when it is used day to day with the
  installed service.
- [ ] **Ask mode for every application.** Implemented: default block with loopback and Windows services permitted.
  Done when it runs as the installed service on a clean machine without breaking DNS, DHCP or updates.
- [ ] **Permanent rules across restarts.** Implemented: persistent filters rebuilt from the saved rules at startup.
  Done when rules survive a service restart and a reboot on an installed system.
- [ ] **Install, uninstall and recovery.** Implemented: `--install`, `--uninstall` and the `--remove-filters`
  emergency switch. Done when they pass on a clean machine. No installer yet.
- [ ] **Coexistence.** Done when tests with Windows Defender Firewall and NetLimiter show the expected result.
- [ ] **NetLimiter migration.** Inactive import review exists; converting reviewed candidates into engine rules is
  pending. Nil SID, zones, tags and equal weights remain unresolved.
- [ ] **NVIDIA assistance.** Exists in Simulation and Settings; not yet connected to engine requests.
- [ ] **Scoped decisions.** Once, per-process and timed decisions were designed for the paused driver; a driverless
  equivalent (temporary rules that expire) is pending.

**Next result:** install the engine as a service on a clean Windows machine and use it day to day.
[Component details](docs/index.md).
