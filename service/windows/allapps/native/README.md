# Native application metadata

This leaf uses the Microsoft SDK `FWPM_NET_EVENT3` / `FWPM_NET_EVENT_CALLBACK2` /
`FwpmNetEventSubscribe2` profile on Windows 10 version 1607 or newer.
It requires MSVC and a compatible Microsoft Windows SDK. The standalone CMake target
rebuilds application identity and the bounded consumer with the same compiler ABI.
The subscription entry point is resolved from the system library; a missing entry point
is unsupported. No older event profile is substituted.

Only the runtime owner can create a source, engine lease, immutable catalog or recovery
receipt. The principal runtime retains a privately acquired dynamic engine session,
its full 128-bit context and an immutable catalog before starting observation.
Acquisition verifies the session through read-only enumeration. This integration
has not been validated by running the service against operating-system traffic.
Each source retains its lease, module and callback context until Start, workers,
cancellation and callbacks have drained. An ambiguous failure retains those resources
and prevents restart. A stalled RPC has no bounded cancellation guarantee.

Callbacks copy selected metadata into eight fixed workspaces and the bounded consumer
queue. Packet bytes are never copied. Presence flags, exact app blobs and exact SIDs
remain distinct from missing fields. Capacity or unreadable memory creates a gap;
only an exact recovery receipt can clear its current revision. Stop is irreversible.

The private binding retains the full runtime epoch and source generation. Its scalar
consumer index comes from `AllocateLocallyUniqueId`; all 64 bits are preserved and
failure, zero and the maximum sentinel are rejected. Its documented uniqueness horizon
ends at a system restart. Object identity also prevents transfer between source contexts,
even if scalar stamps are made equal. Public metadata cannot create a native proof.

Read-only reconciliation compares accessible provider filters across eight declared
policy layers and a separate global inventory against one immutable expected catalog.
The compact principal catalog supports 4,096 rules, up to 24,604 slots and application
blobs up to 65,536 bytes. Its metadata admits up to 32 fields per declared layer.
Budget reservation precedes file reads, parsing and allocation: each retained
generation charges 32 MiB of storage plus 8 MiB of auxiliary capacity, with at most
two generations. Physical aliases retain that charge until their last reference.
This 80 MiB catalog budget is not a limit on total process memory. Each NativeSource
has its own separate queue of at most 256 records and 8 MiB of charged record storage.
Overflow remains visible as degraded coverage; it is never evidence of a healthy source.
The event decoder retains its separate four-layer authorization observation scope.
Exceeding capacity rejects admission; it does not establish coverage of all applications.
Enumeration cannot prove absence of filters hidden by access control. Current shapes
carry read-accessible coverage and unproven temporal continuity, so historical events
remain Unknown. No pending request, firewall permission or observed traffic is produced.

A causal pending-request path, user decisions and an explicit policy for future
application attempts still require runtime integration and operating-system validation.
Loading a GBS4 principal snapshot does not apply or replay its policy. Its historical
outcome remains separate from current proof, and its mutation path is closed.
Current metadata does not implement notification, permission or enforcement.
