# Windows policy service foundation

This separate MSVC target contains a bounded IPC codec, a native policy store,
and a WFP user mode backend. It is an experimental laboratory component. The
desktop application remains a separate Qt/MinGW build; the two processes share
serialized bytes, never C++ objects or a runtime ABI.

Build with the existing Windows SDK, MSVC and Ninja toolchain. Set
`GATEBOUNCER_SERVICE_BUILD_DIR` to an exclusive build directory, then run
`compilar.bat --no-run` from this directory. Building does not run the executable,
install a service, or change filtering policy. Running with no arguments also
does not activate a backend. There is no installer in this component.

The service name is `LGAGateBouncerLab`. View and Control use separate local
named pipes, `LGA.GateBouncer.View.v1` and `LGA.GateBouncer.Control.v1`.
View accepts the configured user and session for status only. Control requires
an elevated administrator token for each command. Clients verify the running
SCM process, its LocalSystem identity and its enabled service SID. A process
with the same ordinary user identity has no policy mutation authority.

Activation requires an explicitly prepared disposable guest, an auto-start own
process service with its service SID enabled, protected binaries and policy
directory, and the administrative guest marker under
`HKLM\SOFTWARE\LGA\GateBouncerLab`. The component checks `EnableWfp=1`,
`ViewSid` and `ViewSessionId`; it does not create that deployment or marker.
The service entry point requires both `--service` and `--guest-wfp`. These
requirements are laboratory gates, not proof that a computer is protected.

The backend generates its own provider and sublayer, persistent and boot-time
Block baselines, and soft permanent path rules at IPv4/IPv6 ALE connect,
receive-accept and listen layers. Resource-assignment filters separately deny
raw endpoints and the three promiscuous modes. Each path rule has both inbound
and outbound scope at those ALE layers; Allow requires a new attempt where the
original attempt was already blocked. No bandwidth control is included.

CreateRule accepts an opaque selector registered by the service from a real
drop attributed to one of its own fixed local laboratory tools. It accepts no
path, PID, hash or native blob supplied by a client. The optional sibling
`GateBouncerProbe.exe` belongs to the separately prepared guest harness; this
target does not supply or run it. If collection or registration is unavailable,
the selector remains unavailable. A native APP_ID identifies a path, not file
content, a process instance or the original caller of a broker.

The store caps rules at 4,096 and snapshots at 16 MiB. A desired revision is
stored only in objects owned by System or Administrators, with a protected
System/Administrators DACL checked on the opened directory, snapshot and
temporary file handles. Ancestor handles remain open without delete sharing;
their owner and effective ACEs must also prevent ordinary substitution or
security changes. Windows TrustedInstaller ownership is accepted for ancestors
only. Existing unsafe objects are rejected; the component does not repair their
security. Binary, dependency and administrative registry deployment security
remains a separate prerequisite checked by the guest harness.

A desired revision is
durable before a WFP transaction. Applied requires successful commit, exact
readback and a durable final snapshot. A final store failure after readback
reports AppliedUnrecorded. Corrupt or mismatched state enters recovery and
does not restore old permissions. Status rechecks the backend rather than
presenting cached effective policy as current. The boot identifier is retained
in a volatile registry key across service restarts; the service epoch changes
on every start. A Windows resumed kernel, including Fast Startup, retains that
kernel boot identity until a new kernel boot.

Only Hello, HelloAck, GetStatus, Status, CreateRule, RevokeRule, MutationAck and
ProtocolError are enabled in wire v1.0. Rule pages, pending reviews, traffic
events, temporary permissions, content pinning and a kernel driver are not
implemented. The component never announces a validated protection profile.
Compilation and pure codec/store tests do not establish WFP enforcement,
startup coverage, pipe ACL behavior, coexistence, or resistance to an
administrator or kernel component. A third-party hard permit can affect
declarative arbitration; weights do not guarantee precedence over another
firewall provider.
