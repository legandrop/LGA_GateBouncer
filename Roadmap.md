# Roadmap

**No release yet.** Updated November 2, 2026.

**First usable version:** block unknown outbound connections and ask Allow/Block, keep permanent or temporary rules per
application or per destination, provide searchable applications, activity and rule cleanup, import NetLimiter rules,
and offer optional AI explanations with your own Anthropic or NVIDIA key. Advice never authorizes traffic. No
bandwidth control.

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
- [x] **Destination on the notice and local network without asking.** Verified on Windows 11 with the installed
  service and a test application: a request carries the server name the application looked up, a direct connection to
  an address has no name, Tailscale and the router connect without asking, they ask when that option is off, and a
  Block rule still wins on the local network.
- [x] **Ask mode for every application.** In daily use on one Windows 11 computer with DNS, DHCP and updates working.
  Verified on a clean Windows 11 (Windows Sandbox) after installing: unknown applications were blocked and asked, the
  notice appeared, and an Allow let only that application connect.
- [x] **Permanent rules across restarts.** Verified on Windows 11 with the installed service: after a reboot the service
  started on its own, the window came back once in the tray, every rule was loaded, an unknown application was blocked
  and asked, and a destination rule still let its application reach only its server. Filters are persistent, so
  Windows enforces them from the moment its filtering service starts, before any user signs in.
- [x] **Destination rules.** Verified on Windows 11 with the installed service: an application limited to its own
  servers reached them, and a new server asked separately.
- [x] **Install, update, uninstall and recovery.** `--install`, `--update`, `--uninstall` and the `--remove-filters`
  emergency switch work on one computer. The installer package (`instalador.bat --no-run`) was verified on a clean
  Windows 11 (Windows Sandbox): install, update over an open window with rules kept, uninstall cancelled at the
  confirmation (the firewall stays on), silent and interactive uninstall with no filters left behind, and reinstall
  recovering the saved rules.
- [ ] **Window with five sections.** Implemented: Protection, Requests, Apps, Activity and Settings, with the state of
  each section in the sidebar and requests decided from the window with the same choices as the notice. Done when it
  is checked with the installed service.
- [ ] **Known applications.** The notice can show a reviewed decision for a known application right away, without
  asking an AI model. Done when the first reviewed catalog ships.
- [ ] **Coexistence.** Done when tests with Windows Defender Firewall and NetLimiter show the expected result.
- [ ] **NetLimiter import.** Implemented: NetLimiter firewall rules for single applications become GateBouncer rules;
  rules with destination, port, zone or schedule conditions are listed and not imported. Done when it is checked
  against a real NetLimiter settings file.
- [x] **AI explanations.** Verified on Windows 11: Anthropic and NVIDIA models were compared on real requests; the
  default, `claude-haiku-5-5`, answers in about four seconds. The request includes the server name the application
  looked up and the program that started it. A slow answer never holds the decision.

**Next result:** ship the first reviewed catalog.
[Component details](docs/index.md).
