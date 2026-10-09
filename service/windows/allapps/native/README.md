# Native application metadata

This leaf uses the Microsoft SDK `FWPM_NET_EVENT3` / `FWPM_NET_EVENT_CALLBACK2` /
`FwpmNetEventSubscribe2` profile on Windows 10 version 1607 or newer.
It requires MSVC and a compatible Microsoft Windows SDK. The standalone CMake target
rebuilds application identity and the bounded consumer with the same compiler ABI.
The subscription entry point is resolved from the system library; a missing entry point
is unsupported. No older event profile is substituted.

Only the runtime owner can create a source, engine lease, immutable catalog or recovery
receipt. Integration requires a real shared session lifetime before these private
constructors can be used. This adapter alone does not supply that runtime integration.
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

Read-only reconciliation compares every accessible provider filter on the four ALE
application authorization layers against an immutable expected catalog. The initial
catalog limit is 256 entries, 32 conditions per entry and 8 MiB of retained metadata.
Exceeding capacity rejects the source; it does not establish coverage of all applications.
Enumeration cannot prove absence of filters hidden by access control. Current shapes
carry read-accessible coverage and unproven temporal continuity, so historical events
remain Unknown. No pending request, firewall permission or observed traffic is produced.

A future causal emission path and an explicit policy for future application attempts
need separate runtime integration. Current metadata does not implement either decision
path, scoped principal filters, persistence, notification or enforcement.
