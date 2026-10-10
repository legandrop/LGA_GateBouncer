# Scoped TCP/UDP classifier

The WDM driver retains initial outbound TCP operations at ALE connect and
eligible inbound TCP SYN operations at ALE receive/accept for IPv4 and IPv6.
An authenticated service can deliver a reviewed Once, process-instance
or timed process-instance decision after recording it durably. CompleteOperation
causes reauthorization; only the matching operation and classify-completion
reason consume that decision. Readback records the driver's classification
decision, rather than claiming that traffic passed every firewall provider.

Inbound acquisition requires PASSIVE_LEVEL with the metadata process ID equal
to the current attached EPROCESS ID and the metadata endpoint token equal to
that process's immediately referenced primary token. Other callbacks deny the
new operation. Listener records retain their own endpoint and identity as
negative evidence; they never lend authority to an accepted child or transferred
socket. The direction of the retained ALE layer reaches the authenticated single
observation response and must match temporal consent. Instance roots and their
replacement stay separate for inbound and outbound TCP.

Receive/accept completion does not produce connect reauthorization. Before
pending, the driver copies one NBL with one net buffer into its own bounded
nonpaged storage and MDL. Its temporary shallow clone is freed before the
callback returns. It accepts only an exact unfragmented TCP SYN with matching
addresses, ports and header lengths, at most 65535 bytes. IPv6 extension headers,
IPsec, raw endpoints, packet chains and unavailable owner evidence are excluded.
After durable consent, that same owned NBL completes the operation and is
injected from a DPC. An opaque monotonic cause identifies the pinned registry
entry; unrecognized or stale injection contexts deny. Only its exact scope
classification can record Applied. Applied records authorization, not delivery:
an injection failure before or after that classification revokes current
authority without rewriting a historical Applied receipt. Storage, NBL and MDL
are released once after completion; closure cannot retire an entry with queued
work, a packet, an injection pin, or a dependent flow.

The device admits LocalSystem with one unambiguous enabled product
(`LGAGateBouncer`) or laboratory (`LGAGateBouncerLab`) service SID,
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
It produces an unsigned .sys without installing, loading or signing it. That
artifact cannot satisfy product package admission. `GateBouncerClassifier.inf`
defines the primitive amd64 product package, Driver Store destination `%13%`,
and the separate `LGAGateBouncerClassifier` kernel service with demand startup.
It does not request service startup. Its version identifies a development
driver package, not a released product version. The final unchanged INF/SYS
and genuine externally signed catalog must be supplied together; this target
neither creates a catalog nor signs its output.

The transport assembler includes supplied INF/SYS/CAT inputs in the new closed
26-file product source set. The legacy 21-file inventory remains limited to
its admitted maintenance/read paths. Administrative admission verifies original SYS/INF
handles against the retained CAT under offline Windows driver policy. This
does not install the package, admit a loaded image or establish Code Integrity
acceptance. Guarded Windows Driver Store installation, retained original-file
and registration checks, update and retirement are implemented in the deployment
source; their actual Windows execution and loaded-image/Code Integrity validation
remain pending. See [Windows transport bundle](../docs/WindowsBundle.md).
There is no unattended repair in this target.
When the device is absent, the service retains its legacy netevent producer.

UDP supports an initial ALE generation per socket and remote peer on IPv4/IPv6.
Its real FLOW_ESTABLISHED handle is associated with a DATAGRAM_DATA context;
each packet in either direction requires that context, handle, endpoint,
compartment and tuple to match. Instance and timed grants also retain the exact
application instance, authorization direction and transport protocol. QUIC uses
the same UDP transport enforcement, without inspecting QUIC application data.
Inbound UDP retains an owned packet with an exact eight-byte UDP header and
length; fragments, IPv6 extension headers and jumbograms are excluded.

UDP flow deletion after idle does not close its socket. An outbound initial
authorization can create a new cause for the same open socket and peer only
when every previous generation has a drained, idle flow and the same original
process, token and application identity. It also requires an OS-provided,
nonzero flow handle that has never appeared in the retained registry. The new
cause retains that handle; reauthorization and establishment must match it.
Callbacks for an older flow keep their original cause and are denied after
idle. A callback without a distinguishable generation is denied. Flow-handle
availability at initial authorization is not guaranteed by this source;
regeneration outside this metadata subset remains unsupported. The initial UDP
entry remains as a negative tombstone for the driver lifetime, including after
endpoint closure, RESET, session loss or cleanup. It is neither revived nor
removed to make capacity. A distinguishable same-peer generation can retire
only after its exact DATAGRAM layer/callout/cause deletion, endpoint closure,
termination of its retained original process and complete drain of completion,
association, injection, packet and child pins. Its original flow handle must
match both authorization and association. Retirement also requires the closed,
revoked initial tombstone of the same endpoint, tuple, original process and
token to remain in the registry. That tombstone keeps late flowless callbacks
denied; the retired cause is never reassigned. The UDP slot stays reserved until
its physical resources have been freed outside the spinlock.
Different peers and distinguishable same-peer generations can receive their
own causes while registry capacity remains. This recovers drained generation
slots, not initial endpoint tombstones. It does not establish sustained browser
operation for hours or support beyond the 64 retained slots. Endpoint closure
and flow-context deletion do not provide a documented rundown of all later ALE
indications without a flow handle; those endpoints cannot be recycled safely by
this source. Applied acknowledges the exact authorization, not packet
delivery or successful flow association. Flow association without an immediate
PASSIVE token proof is denied, including callbacks reached at DISPATCH_LEVEL.
The driver buffers a supported first outbound UDP datagram before pending its
authorization. An exact successful reauthorization queues its owned copy for
transport-send reinjection; the flushed original does not require application
retransmission for that path. The copy, MDL, control data and injection pin remain
owned through the actual completion callback. The subset is one NBL with one
NB, at most 65535 bytes and at most 1024 bytes of control data; raw packets,
unsupported segmentation/checksum metadata and missing IPv6 scope are denied.
An injection result alone never creates a traffic counter: counters require the
actual, bound DATAGRAM_DATA callback. This source does not establish that QUIC
will recover or that the original send is delivered by the OS.

This source does not establish platform-wide protection. UDP/QUIC OS delivery,
same-peer metadata availability and regeneration, sustained capacity, ICMP,
inbound callbacks outside the admitted PASSIVE owner subset, boot coverage,
socket transfer, provider precedence
and driver lifecycle require separate guest validation. Token replacement is
detected by a kernel worker at a 100 ms interval, not instantaneously. The kernel
registry supports at most 64 simultaneous retained operations, grants and
tombstones. Saturation rejects a new operation without revoking other grants.
A superseded root retires only after closure, completion drain and flow deletion,
with no dependent entries or writer pin. Live tombstones are never evicted by
age or capacity. Permanent outcomes still have a separate memory limit of 128.
No host deployment or
causal traffic validation is implied by building the source.
