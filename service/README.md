# Experimental Windows policy service

This separate MSVC target contains native policy storage, authenticated local IPC, bounded decision records and a WFP user mode backend. It is an experimental laboratory component with **no validated protection profile**. The desktop application is a separate Qt/MinGW build; the processes exchange serialized bytes, never C++ objects or a runtime ABI.

Build with the existing Windows SDK, MSVC and Ninja toolchain. Set `GATEBOUNCER_SERVICE_BUILD_DIR` to an exclusive build directory, then run `compilar.bat --no-run` from this directory. This builds the service and the native `GateBouncer.exe` bootstrap. The separate Qt/MinGW build produces `GateBouncerGuiStage.dll`, the decision stage/bootstrap and the assistance helper. Building does not run the executable, install a service or change filtering policy. Running without arguments does not activate a backend. There is no distributed installer.

## Deployment and channels

Activation requires an explicitly authorized disposable Windows guest. A preexisting protected `HKLM\SOFTWARE\LGA\GateBouncerLab` key with `EnableWfp=1` is an administrative laboratory gate; it does not attest virtualization, containment or protection. Guest preparation and enrollment remain separate prerequisites.

The service source includes an explicit administrative preparation command:

```
GateBouncerService.exe --prepare-guest-deployment <protected-source> <new-package> <new-store> <account-sid>
```

It requires an elevated administrator token without UIAccess, protected local ancestors and an exact protected staging directory. The source directory contains only the fixed files returned by `deploymentFiles(Service)`: the service, native ordinary bootstrap, GUI stage, decision bootstrap/stage, assistance helper, Qt Core/Gui/Widgets and their three MinGW runtime DLLs, `plugins/platforms/qwindows.dll`, three Inter fonts and `qt.conf`. The configuration bytes are exactly `[Paths]\nPrefix=.\nPlugins=plugins\n`. Preparation retains the inputs, creates new protected package/store objects, copies with CreateNew and flush/readback, generates the bounded GBD1 inventory, creates a new SCM registration and creates `DeploymentVIII` configuration. It never starts the service. Existing destinations, SCM objects or configuration reject preparation; partial failure is preserved and cannot be retried over the same objects. Update, repair and uninstall are not implemented.

SCM admission requires the exact quoted package service command with `--service --guest-wfp`, LocalSystem, OWN_PROCESS, AUTO_START, an unrestricted enabled service SID and a protected System/Administrators-owned service DACL. Ordinary users may query but cannot mutate, start or stop it. The service retains package handles and registry/SCM query handles, and rechecks the admitted PackageRoot, OrdinaryImage, StoreRoot, ViewSid and ProvisionPrincipal tuple before use. Missing ordinary images, unknown files, altered identity/security or changed configuration revoke admission. The GBD1 hash establishes integrity under the administrative ACL; it is not a publisher signature.

The ordinary `GateBouncer.exe` has an asInvoker manifest, static native runtime and System32-only initial dependent loads. Before loading the Qt stage, it accepts only a normal launch or the exact `--start-minimized` flag; unknown arguments, Qt options, duplicates and trailing values are rejected. It reconstructs the admitted arguments, verifies and retains the package, sanitizes the Qt environment and establishes restricted DLL directories. The stage also rejects other arguments before constructing the application. The native bootstrap and the deployment owner stay alive throughout the GUI. Startup registration retains and revalidates that same package through registry readback.

View and Control use separate local named pipes, `LGA.GateBouncer.View.v1` and `LGA.GateBouncer.Control.v1`. Wire v1.0 and v1.1 remain status-only compatibility channels. Wire v1.2 provides bounded direction-aware pending/rule snapshots and attempt/gap observations on View; it provides decision, rule and command-status operations on Control. Each channel verifies its peer and each command rechecks authority. Control requires the elevated administrator role; ordinary View clients have no policy mutation authority.

The current review profile requires one unambiguous active user session. Missing, changed or ambiguous identity invalidates the profile and review references. This restriction does not implement review for other accounts, services running as SYSTEM or all process identities.

The separate `GateBouncerDecisionBootstrap.exe` verifies a protected deployment before loading the Qt review stage. The ordinary desktop can explicitly request administrator enablement, then queue only a request reference on `LGA.GateBouncer.ReviewOpen.v1`. It cannot send Allow/Block through that queue. Queue acknowledgments do not confirm a decision, focus change or filtering effect. Protected binaries, Qt dependencies, configuration and operating-system authentication remain deployment and validation prerequisites.

Wire v1.3 View admits the fixed `GateBouncerAssistant.exe` from the same protected package as a read-only peer. It exposes only status, observed pages and an exact observed record. Every page/record read reconciles the current retained Source; a private full path additionally requires the same retained event, proof, principal, source and revision. Page projections preserve the same displayed metadata. All draft, review, decision, revoke, outcome and subscription messages are denied on that connection. Its capabilities never include FuturePolicyControl and its IVProfile remains zero.

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
drain and uncertain cleanup. Loading an existing snapshot never applies or replays rules.
The explicit initial provision flag only admits a genuinely missing store under the same
writer lease, with no backup, journal, temporary or unknown remnants. It first persists
an empty sequence-one GBS4 bootstrap as RecoveryRequired with unknown effective state.
A private single-attempt transaction then requires absent own provider, sublayer and
filters, materializes the existing Recipe's 28 baseline slots, commits, performs complete
readback and freezes the catalog before starting Source. Any failure preserves recovery
state and cannot replay Initial; Add return values cannot produce a catalog receipt.
This enables retained permanent-future admission through the existing writer, without
socket-held, Once or currently effective proof. The catalog
supports 4,096 rules and up to 24,604 slots, charging 40 MiB per retained generation,
with two generations at most. Separate per-source queues and operating-system resources
are outside that catalog budget. This source integration has not been validated by
executing the service against actual Windows traffic.

The native runtime, server, journal/effect adapters and Qt reviewer are implemented, with laboratory activation gates. Compilation, codec/store tests and local doubles do not establish WFP enforcement, pre-user startup coverage, SYSTEM/service-SID authentication, effective pipe permissions, elevated input handling or coexistence with another firewall.

Weights do not guarantee precedence over another firewall provider; a third-party hard permit can affect declarative arbitration. Coverage for all applications/accounts, multicast/broadcast, boot and failure recovery, indirect egress, temporal scopes and protected distribution remains unvalidated. There is no guarantee against an administrator or kernel component.
