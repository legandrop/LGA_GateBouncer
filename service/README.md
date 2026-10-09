# Experimental Windows policy service

This separate MSVC target contains native policy storage, authenticated local IPC, bounded decision records and a WFP user mode backend. It is an experimental laboratory component with **no validated protection profile**. The desktop application is a separate Qt/MinGW build; the processes exchange serialized bytes, never C++ objects or a runtime ABI.

Build with the existing Windows SDK, MSVC and Ninja toolchain. Set `GATEBOUNCER_SERVICE_BUILD_DIR` to an exclusive build directory, then run `compilar.bat --no-run` from this directory. Building does not run the executable, install a service or change filtering policy. Running without arguments does not activate a backend. This component has no installer.

## Deployment and channels

Activation requires an explicitly prepared disposable Windows guest, an auto-start own-process service named `LGAGateBouncerLab` with its service SID enabled, protected binaries and policy directory, and protected configuration under `HKLM\SOFTWARE\LGA\GateBouncerLab`. The component checks `EnableWfp=1`, `ViewSid` and `ViewSessionId`; it does not create that deployment or configuration. The service entry point requires both `--service` and `--guest-wfp`. These checks are laboratory prerequisites, not proof that a computer is protected.

View and Control use separate local named pipes, `LGA.GateBouncer.View.v1` and `LGA.GateBouncer.Control.v1`. Wire v1.0 and v1.1 remain status-only compatibility channels. Wire v1.2 provides bounded direction-aware pending/rule snapshots and attempt/gap observations on View; it provides decision, rule and command-status operations on Control. Each channel verifies its peer and each command rechecks authority. Control requires the elevated administrator role; ordinary View clients have no policy mutation authority.

The current review profile requires one unambiguous active user session. Missing, changed or ambiguous identity invalidates the profile and review references. This restriction does not implement review for other accounts, services running as SYSTEM or all process identities.

The separate `GateBouncerDecisionBootstrap.exe` verifies a protected deployment before loading the Qt review stage. The ordinary desktop can explicitly request administrator enablement, then queue only a request reference on `LGA.GateBouncer.ReviewOpen.v1`. It cannot send Allow/Block through that queue. Queue acknowledgments do not confirm a decision, focus change or filtering effect. Protected binaries, Qt dependencies, configuration and operating-system authentication remain deployment and validation prerequisites.

## Current policy scope

The backend creates its own provider and sublayer, persistent and boot-time Block baselines, and soft permanent path rules at IPv4/IPv6 ALE connect, receive-accept and listen layers. Resource-assignment filters separately deny raw endpoints and promiscuous modes. The direction-aware profile distinguishes **Outbound**, **Inbound** and explicitly chosen **Both** permanent path rules. Outbound Allow includes a unicast-destination restriction; Inbound includes receive-accept and listen scope. Both widens inbound access and removes that outbound unicast restriction only after explicit review. Operating-system coverage validation is still required, so the direction-aware mutation capability remains closed. Allow requires a new attempt where the original attempt was already blocked. No bandwidth control is included.

Selectors originate from native drops attributed to the component's fixed local laboratory tools. The optional sibling `GateBouncerProbe.exe` belongs to a separately prepared guest harness; this target does not supply or run it. Clients cannot register a path, PID, hash or native APP_ID blob as authority. If collection or registration is unavailable, the selector remains unavailable. APP_ID identifies a path, not file content, a process instance or the original caller of a broker. Arbitrary application collection and principal-specific identity scopes are still required. A listen observation keeps its original traffic direction unknown; the suggested review direction is separate.

Observed attempts and gaps do not establish authorization or traffic. Pages and queues are bounded snapshots with their own identity and revisions; stale records cannot become a current decision merely by being displayed. Temporary permissions, Once, process-instance rules, content pinning and a kernel driver are not implemented.

## Storage and recovery

The direction-aware policy store caps rules at 4,096, the policy projection at 16 MiB and its combined snapshot at 32 MiB. It checks System/Administrators ownership and protected DACLs on opened directories, snapshots and temporary files. Ancestor handles remain open without delete sharing; ordinary principals must not be able to substitute objects or change their security. TrustedInstaller ownership is accepted for ancestors only. Unsafe existing objects are rejected, rather than repaired. Binary and registry deployment security are separate prerequisites.

A single direction-aware snapshot binds policy, desired revision and command outcomes. Prepared is persisted before a WFP transaction. Applied requires successful commit, exact readback and a durable final snapshot; a final store failure after readback reports AppliedUnrecorded in memory; the active snapshot may remain Prepared or have uncertain durability and requires recovery. Historical outcome does not establish a currently effective policy: a response without current proof reports RecoveryRequired. An uncertain command retains its identity for status queries; reconnecting does not automatically submit it again. Corrupt or mismatched state does not restore old permissions. Status rechecks the backend instead of presenting a cached effective policy as current.

The boot identifier uses a protected volatile registry key retained across service restarts; the service epoch changes on every start. A resumed kernel, including Fast Startup, retains that kernel boot identity until a new kernel boot. The single-snapshot direction-aware storage format supports migration from the previous local policy and journal; loading or migrating never applies a baseline or replays a command. Legacy permanent Both rules remain explicit, and BlockRetry is unavailable for that legacy state.

## Validation limits

The principal GBS4 runtime additionally retains a private dynamic observation session
and constructs a compact immutable catalog through exact readback before admitting a
source. It preserves the complete session identity and strong lifetimes through callback
drain and uncertain cleanup. Loading this snapshot never applies or replays rules;
its current policy proof remains unknown and mutation is unavailable. The catalog
supports 4,096 rules and up to 24,604 slots, charging 40 MiB per retained generation,
with two generations at most. Separate per-source queues and operating-system resources
are outside that catalog budget. This source integration has not been validated by
executing the service against actual Windows traffic.

The native runtime, server, journal/effect adapters and Qt reviewer are implemented, with laboratory activation gates. Compilation, codec/store tests and local doubles do not establish WFP enforcement, pre-user startup coverage, SYSTEM/service-SID authentication, effective pipe permissions, elevated input handling or coexistence with another firewall.

Weights do not guarantee precedence over another firewall provider; a third-party hard permit can affect declarative arbitration. Coverage for all applications/accounts, multicast/broadcast, boot and failure recovery, indirect egress, temporal scopes and protected distribution remains unvalidated. There is no guarantee against an administrator or kernel component.
