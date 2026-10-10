# Roadmap

**No validated firewall release.** Updated October 10, 2026.

**First usable version:** hold unknown outbound connections for explicit Allow/Block, support permanent and scoped rules, and provide searchable processes, distinct history dates and reversible rule cleanup. Include safe NetLimiter import review and optional NVIDIA explanations with cited file/IP evidence. Unknown imports stay inactive; advice never authorizes traffic. Installation, coverage and recovery must pass before release. No bandwidth control.

Checkboxes mean **verified acceptance tests**, not code or successful builds. **Implemented** means source exists; **partial** means remaining implementation or coverage gaps. Windows validation is blocked; simulation and local tests do not complete these checks.

- [ ] **Processes, search, history and cleanup — implemented; unverified live.** Done when real observations keep attempt, authorization and traffic distinct, search finds the process, and selected old rules can be removed/restored without treating missing observations as inactivity.
- [ ] **Connection notice and Allow/Block — implemented; blocked on Windows.** Done when an original connection produces the notice, dismissing leaves it unresolved, and independent traffic observation verifies both decisions and another firewall's effect.
- [ ] **Permanent rules — implemented; blocked on Windows.** Done when saved Allow/Block survives service restart and matches future connections; changed identities and recovery cannot resurrect stale permissions.
- [ ] **Once, instance and duration — implemented subset; unverified.** Done when real TCP/UDP tests verify exact scope, expiry, process exit and late responses. Unsupported callbacks remain limits.
- [ ] **Coverage and failure recovery — partial; Windows tests blocked.** Done after IPv4/IPv6, TCP/UDP, SYSTEM/services, AppContainers, boot, service/BFE failure, indirect egress and sustained-load tests. UDP generation/capacity gaps remain open.
- [ ] **NetLimiter migration — partial; semantics unresolved.** Done when an original export preserves action, scope and precedence, and unsupported constraints stay visible/inactive. Nil SID, zones, tags and equal weights remain unresolved.
- [ ] **NVIDIA assistance — partial; provider workflow unverified.** Done when secure key setup, consent, research, cited IP/service/purpose evidence, uncertainty and cancellation work in the original notice, with applicable provider rights confirmed.
- [ ] **Install, update and uninstall — implemented source; distribution incomplete.** Done when a genuine signed package installs/loads and maintenance/recovery passes in isolated Windows. No release installer is available.

**Current stage:** acceptance criteria defined; integral Windows validation blocked. **Next result:** real connection → notice → Allow/Block → persistent rule, observed independently. Deployment/start validation, signed-package and Windows-environment prerequisites remain outstanding. Linux does not validate Windows filtering.

No release-time estimate is justified until those external blockers are resolved and the integral test runs. [Component details](docs/index.md).
