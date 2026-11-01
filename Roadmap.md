# Roadmap

**No release yet.** Updated November 1, 2026.

**First usable version:** block unknown outbound connections and ask Allow/Block, keep permanent or temporary rules per
application, provide searchable applications, activity and rule cleanup, import NetLimiter rules, and offer optional
AI explanations with your own NVIDIA key. Advice never authorizes traffic. No bandwidth control.

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
- [x] **Desktop notice.** Verified on Windows 11 with the installed service: a notice stays in the corner until you
  decide, and Allow with **This app, any version** let a blocked application connect on its next attempt.
- [x] **Temporary decisions.** Verified on Windows 11 with the installed service and a test application: a one-minute
  Allow connected, expired on time and the application asked again; an until-restart rule is not saved.
- [ ] **Ask mode for every application.** In daily use on one Windows 11 computer with DNS, DHCP and updates working.
  Done when it also runs on a clean machine.
- [ ] **Permanent rules across restarts.** Rules survive a service restart (verified with `--update`). Done when they
  also survive a reboot on an installed system.
- [ ] **Install, update, uninstall and recovery.** `--install`, `--update`, `--uninstall` and the `--remove-filters`
  emergency switch work on one computer. Done when they pass on a clean machine. No installer package yet.
- [ ] **Coexistence.** Done when tests with Windows Defender Firewall and NetLimiter show the expected result.
- [ ] **NetLimiter import.** Implemented: NetLimiter firewall rules for single applications become GateBouncer rules;
  rules with destination, port, zone or schedule conditions are listed and not imported. Done when it is checked
  against a real NetLimiter settings file.
- [ ] **AI explanations.** Implemented: notice button, key kept with DPAPI, HTTPS-only exception for the window, plain
  text answers that never decide. Done when real answers from the chosen model have been compared on real requests.

**Next result:** use the installed engine day to day, reboot it, and run the clean-machine checks.
[Component details](docs/index.md).
