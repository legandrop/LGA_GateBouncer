# Experimental Windows policy service

This separate MSVC target contains native policy storage, authenticated local IPC, bounded decision records and a WFP user mode backend. Its separate product and laboratory deployment paths have **no validated protection profile**. The desktop application is a separate Qt/MinGW build; the processes exchange serialized bytes, never C++ objects or a runtime ABI.

Build with the existing Windows SDK, MSVC and Ninja toolchain. Set `GATEBOUNCER_SERVICE_BUILD_DIR` to an exclusive build directory, then run `compilar.bat --no-run` from this directory. This builds the service and the native `GateBouncer.exe` bootstrap. The separate Qt/MinGW build produces `GateBouncerGuiStage.dll`, the decision stage/bootstrap and the assistance helper. Building does not run the executable, install a service or change filtering policy. Running without arguments does not activate a backend. There is no distributed installer.

## Deployment and channels

Execution validation requires an explicitly authorized disposable Windows guest. Product and laboratory deployment are separate source paths: product preparation uses `--prepare-deployment` and dispatch uses `--service`; laboratory preparation uses `--prepare-guest-deployment` and dispatch uses `--service --guest-wfp`. Only the laboratory path uses the protected `HKLM\SOFTWARE\LGA\GateBouncerLab` key with `EnableWfp=1`. That gate does not attest virtualization, containment or protection. Product admission does not use it as authorization. See [Windows transport bundle](../docs/WindowsBundle.md) for signing and deployment prerequisites.

The service source includes an explicit administrative preparation command:

```
GateBouncerService.exe --prepare-deployment <protected-source> <new-package> <new-store> <account-sid>
GateBouncerService.exe --prepare-guest-deployment <protected-source> <new-package> <new-store> <account-sid>
```

Preparation requires an elevated administrator token without UIAccess, protected local ancestors and an exact protected source directory. New staging uses the closed 26-file product or explicitly selected 23-file laboratory set, including separate MSVC service and MinGW GUI runtimes; legacy 21/18-file inventories remain limited to their admitted maintenance/read paths. Configuration bytes are exactly `[Paths]\nPrefix=.\nPlugins=plugins\n`. Preparation retains the inputs, creates protected package/store objects, copies with CreateNew and flush/readback, writes and reads back its bounded inventory and configuration, and creates a stopped SCM registration. It never starts the user service. Existing destinations or foreign configuration reject preparation; partial failure is preserved. Guarded update, finalization, uninstall and retained-data reinstall paths are implemented in source. General unattended repair and a release installer are not implemented. Windows installation, Code Integrity, loaded-image and protection validation remain pending; see [deployment and maintenance details](../docs/WindowsBundle.md).

SCM admission requires the exact quoted package service command for the admitted deployment mode, LocalSystem, OWN_PROCESS, the expected startup state and enabled service SID, and a protected System/Administrators-owned service DACL. Ordinary users may query but cannot mutate, start or stop it. Preparation and maintenance retain stopped/disabled intermediate states before publishing automatic startup. The service retains package and registry/SCM query handles, and rechecks its admitted PackageRoot, OrdinaryImage, StoreRoot, ViewSid and ProvisionPrincipal tuple before use. Missing ordinary images, unknown files, altered identity/security or changed configuration revoke admission. The GBD1 hash establishes integrity under the administrative ACL; it is not a publisher signature.

The ordinary `GateBouncer.exe` has an asInvoker manifest, static native runtime and System32-only initial dependent loads. Before loading the Qt stage, it accepts only a normal launch or the exact `--start-minimized` flag; unknown arguments, Qt options, duplicates and trailing values are rejected. It reconstructs the admitted arguments, verifies and retains the package, sanitizes the Qt environment and establishes restricted DLL directories. The stage also rejects other arguments before constructing the application. The native bootstrap and the deployment owner stay alive throughout the GUI. Startup registration retains and revalidates that same package through registry readback.

View and Control use separate local named pipes, `LGA.GateBouncer.View.v1` and `LGA.GateBouncer.Control.v1`. Wire v1.0 and v1.1 remain status-only compatibility channels. The legacy direction-aware v1.2 Control path requires the elevated administrator role. The principal runtime additionally implements current-account prepare/commit decisions through its authenticated caller and retained source/catalog checks. Each channel verifies its peer and each command rechecks authority; an ordinary View connection is not policy mutation authority.

The ordinary review actor requires one unambiguous active user session. Missing, changed or ambiguous identity invalidates the profile and review references. A separately authenticated administrative principal review can retain a different target account; reviewer identity and target identity remain distinct. These source paths do not establish coverage for all accounts, SYSTEM services or every process identity.

The separate `GateBouncerDecisionBootstrap.exe` verifies a protected deployment before loading the Qt review stage. The ordinary desktop can review its own authenticated current request through prepare/commit, or explicitly request administrator enablement and queue a request reference on `LGA.GateBouncer.ReviewOpen.v1`. That queue cannot send Allow/Block. Queue acknowledgments do not confirm a decision, focus change or filtering effect. Protected binaries, Qt dependencies, configuration and operating-system authentication remain deployment and validation prerequisites.

The fixed `GateBouncerAssistant.exe` is admitted from the same protected package as a read-only peer. The own-account reader supports its bounded status/observation/context operations and event subscription. The separate principal Role2 explanation reader has a narrower exact-record/status whitelist and no list, stream or mutation authority. Each admitted read reconciles its current retained context; private file facts additionally require the same original event, principal, source and revision. Neither reader can prepare or commit a decision, revoke a rule or obtain FuturePolicyControl. Read access does not authorize the subject's traffic.

## Policy implementations and limits

The legacy NativeDirections backend creates its own provider and sublayer, persistent and boot-time Block baselines, and soft permanent path rules at IPv4/IPv6 ALE connect, receive-accept and listen layers. Resource-assignment filters separately deny raw endpoints and promiscuous modes. Its direction-aware profile distinguishes **Outbound**, **Inbound** and explicitly chosen **Both** permanent path rules. Outbound Allow includes a unicast-destination restriction; Inbound includes receive-accept and listen scope. Both widens inbound access and removes that outbound unicast restriction only after explicit review. This legacy mutation capability remains closed by its operating-system coverage gate. That gate does not describe every principal-runtime decision path. Allow requires a new attempt where the original attempt was already blocked. No bandwidth control is included.

Legacy selectors originate from native drops attributed to fixed laboratory tools; the optional sibling `GateBouncerProbe.exe` belongs to a separately prepared guest harness. The principal runtime instead retains original request causes, application/account identity and a current source/catalog. Clients cannot register a path, PID, hash or native APP_ID blob as authority. Missing or changed original evidence rejects admission. APP_ID alone identifies a path, not file content, a process instance or the original caller of a broker. Native collection and principal-specific source paths exist, but arbitrary-process and operating-system coverage remain unvalidated. A listen observation keeps its original traffic direction unknown; the suggested review direction is separate.

Observed attempts and gaps do not establish authorization or traffic. Pages and queues are bounded snapshots with their own identity and revisions; stale records cannot become a current decision merely by being displayed. A kernel driver and durable Once, process-instance and timed decision paths are implemented for a bounded TCP/UDP subset. They require original retained process/token/endpoint evidence and exclude unsupported callbacks; see [driver scope and limits](../driver/README.md). A principal permanent decision can deny the old held operation while changing policy for future attempts. File witnesses bind permanent-rule admission and recovery; they are not a general content-pinning or malware guarantee. Driver classification readback does not prove packet delivery or a loaded, accepted driver.

## Storage and recovery

The legacy direction-aware policy store caps rules at 4,096, the policy projection at 16 MiB and its combined snapshot at 32 MiB. It checks System/Administrators ownership and protected DACLs on opened directories, snapshots and temporary files. Ancestor handles remain open without delete sharing; ordinary principals must not be able to substitute objects or change their security. TrustedInstaller ownership is accepted for ancestors only. Unsafe existing objects are rejected, rather than repaired. Binary and registry deployment security are separate prerequisites.

A single direction-aware snapshot binds policy, desired revision and command outcomes. Prepared is persisted before a WFP transaction. Applied requires successful commit, exact readback and a durable final snapshot; a final store failure after readback reports AppliedUnrecorded in memory; the active snapshot may remain Prepared or have uncertain durability and requires recovery. Historical outcome does not establish a currently effective policy: a response without current proof reports RecoveryRequired. An uncertain command retains its identity for status queries; reconnecting does not automatically submit it again. Corrupt or mismatched state does not restore old permissions. Status rechecks the backend instead of presenting a cached effective policy as current.

The boot identifier uses a protected volatile registry key retained across service restarts; the service epoch changes on every start. A resumed kernel, including Fast Startup, retains that kernel boot identity until a new kernel boot. The single-snapshot direction-aware storage format supports migration from the previous local policy and journal; loading or migrating never applies a baseline or replays a command. Legacy permanent Both rules remain explicit, and BlockRetry is unavailable for that legacy state.

## Validation limits

The principal GBS4 runtime additionally retains a private dynamic observation session
and constructs a compact immutable catalog through exact readback before admitting a
source. It preserves the complete session identity and strong lifetimes through callback
drain and uncertain cleanup. Decoding an existing snapshot never applies or replays rules.
The explicit initial provision flag only admits a genuinely missing store under the same
writer lease, with no backup, journal, temporary or unknown remnants. It first persists
an empty sequence-one GBS4 bootstrap as RecoveryRequired with unknown effective state.
A private single-attempt transaction then requires absent own provider, sublayer and
filters, materializes the existing Recipe's 28 baseline slots, commits, performs complete
readback and freezes the catalog before starting Source. Any failure preserves recovery
state and cannot replay Initial; Add return values cannot produce a catalog receipt.
This initial bootstrap prepares the catalog for later permanent-future admission;
it does not grant a held operation, Once or currently effective proof. The catalog
supports 4,096 rules and up to 24,604 slots, charging 40 MiB per retained generation,
with two generations at most. Separate per-source queues and operating-system resources
are outside that catalog budget. This source integration has not been validated by
executing the service against actual Windows traffic.

The native runtime, server, journal/effect adapters and Qt reviewer are implemented, with separate product and laboratory deployment gates. Compilation, codec/store tests and local doubles do not establish WFP enforcement, pre-user startup coverage, SYSTEM/service-SID authentication, effective pipe permissions, elevated input handling or coexistence with another firewall.

Weights do not guarantee precedence over another firewall provider; a third-party hard permit can affect declarative arbitration. Coverage for all applications/accounts, multicast/broadcast, boot and failure recovery, indirect egress, temporal scopes and protected distribution remains unvalidated. There is no guarantee against an administrator or kernel component.

Decode and migration alone never apply policy. A separate principal startup recovery path can restore witnessed Always rules from the original protected store and current deployment, after complete WFP absence/readback checks; it does not resurrect Once, instance or duration outcomes. Source-admission failure does not remove a preexisting Allow or prove effective blocking. See [startup and maintenance limits](../docs/WindowsBundle.md) and the [acceptance roadmap](../Roadmap.md).
