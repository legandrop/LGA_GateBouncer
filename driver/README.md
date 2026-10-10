# Scoped TCP classifier

The WDM driver retains initial outbound TCP operations at ALE connect for IPv4
and IPv6. An authenticated service can deliver a reviewed Once, process-instance
or timed process-instance decision after recording it durably. CompleteOperation
causes reauthorization; only the matching operation and classify-completion
reason consume that decision. Readback records the driver's classification
decision, rather than claiming that traffic passed every firewall provider.

The device admits LocalSystem with the enabled LGAGateBouncerLab service SID,
one retained caller process and one file object. Initial acquisition requires
PASSIVE_LEVEL, the current endpoint-owner process and its primary token. It pins
EPROCESS and token objects and copies creation time, OS APP_ID, account SID,
endpoint, compartment and tuple. Saved PID values never reacquire authority.
AppContainer, missing owner evidence and elevated-IRQL acquisition fail closed.

Once applies to one retained connection. Instance and timed decisions authorize
new matching TCP connections of that same pinned process and token; they do not
authorize another initial process instance. Duration is at most fifteen minutes
and a newer Applied instance decision determines future connections of that
same instance. Existing scoped connections keep their original root and deadline.
Duration uses kernel interrupt time, including sleep time. Every scoped stream-packet
classification checks the deadline in both directions, including control packets.
Expiry remains enforced while the service is hung. Exit, token replacement,
source loss, reset or file cleanup revoke the scopes. Existing connections retain
deny guards until matching OS endpoint closure. Flow deletion alone cannot turn
a scoped connection into an unguarded one.

Stream guards require the exact OS endpoint, family, compartment and tuple.
Flow association additionally requires the OS flow ID, process metadata, APP_ID
and the same referenced endpoint token. Ineligible flow evidence revokes the
connection and aborts its OS flow; it never manufactures a permit from a tuple.
Missing or ambiguous scoped metadata denies traffic. A connection without a
scope continues to the existing policy. Connect and packet filters therefore
use CALLOUT_UNKNOWN. Scoped Block clears ACTION_WRITE and can veto a preceding
Permit; scoped Permit keeps rights so other firewall decisions still apply.

The service records temporal commands in a separate protected journal. Prepared
is flushed and compared before the single device decision. It completes the
durable receipt only after exact command readback reports Applied. Uncertain
delivery is queried rather than replayed. Loading history never rearms a scope.
New temporal history uses a protected file per command and a separate monotonic
revision counter. A mutex and the writer lease serialize counter reservation
before Prepared; a crash between them leaves a revision gap. History from the
earlier journal remains read-only. Durable results can leave the memory cache
and be queried by their exact command and current admitted actor; this never
resends a decision. A missing counter with command files or backups fails closed.
A missing counter, command or legacy journal with its own backup also requires
recovery. Storage failures retain uncertainty rather than replaying effects.
Command identifiers and command-status queries share one namespace across
temporal and permanent decisions. New committed decisions and uncached status
queries require that temporal namespace to be readable. Uncertain storage can
therefore reject a new permanent Allow or Block, or a revocation, before the
principal writer runs. Existing permanent rules can remain active; such a
failure does not mean traffic is blocked or the previous policy changed.
Recovery of that namespace, reliable revocation during recovery, and separation
of command namespaces remain open work.
The principal permanent rule writer also accepts a held operation. It first
records Prepared, then seals a command-bound negative guard for that exact
operation before changing the principal rule. A registered connect guard at
weight 1000 denies the cancelled operation even if a future Allow rule at
weight 100 would otherwise bypass the temporal classifier. Its receipt proves
the retained guard, rather than an acknowledgement of CompleteOperation.
Future attempts follow the new principal rule; the old held attempt remains
denied. The upper guard never permits or consumes a temporal decision: the
principal Block at weight 200 keeps precedence and the temporal classifier at
weight 50 remains the sole publisher of Applied.

DriverEntry creates an inert device. START occurs only after the service reads
the real baseline policy inventory. START retains registered callouts and WFP
objects for the driver lifetime. There is no DriverUnload; removal and partial
START recovery currently require a guest reboot. The retained dynamic session
manages object lifetime rather than the duration of a permission.

Build this standalone CMake project with MSVC x64 and explicit WDK/SDK roots.
It produces an unsigned .sys without installing, loading or signing it. There
is no production signing, INF, unattended repair or deployment admission yet.
When the device is absent, the service retains its legacy netevent producer.

This source does not establish platform-wide protection. UDP, QUIC, ICMP,
inbound initial authorization, boot coverage, socket transfer, provider precedence
and driver lifecycle require separate guest validation. Token replacement is
detected by a kernel worker at a 100 ms interval, not instantaneously. The kernel
registry supports at most 64 simultaneous retained operations, grants and
tombstones. Saturation rejects a new operation without revoking other grants.
A superseded root retires only after closure, completion drain and flow deletion,
with no dependent entries or writer pin. Live tombstones are never evicted by
age or capacity. Permanent outcomes still have a separate memory limit of 128.
No host deployment or
causal traffic validation is implied by building the source.
