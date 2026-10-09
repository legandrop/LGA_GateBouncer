# All-app metadata leaf

Offline C++17 library for bounded copies of declared NetEvent3 metadata. It does
not acquire Windows events, subscribe to WFP, create pending requests, authorize
applications, observe traffic, persist selectors, or change firewall rules.

`SourceState` owns an immutable epoch and source generation. A copy acquires its
sequence and loss revision from that source; queued events retain that stamp.
Loss revisions and health share one atomic state. Recovery acknowledges exactly
one revision and cannot clear newer loss or Stopping. Exhaustion never wraps.
Constructor counter seeds exist for offline boundary testing, not IPC inputs.

`NetEventView` requires valid readable ranges provided by its caller. Declared
lengths are checked before reads and owned data survives destruction of the view.
These checks do not validate arbitrary SDK pointers. A native adapter remains
required and is not part of this library. DROP and ALLOW use separate documented
direction tables. Unsupported versions/types fail closed. Endpoint details are
not collected in this leaf; address-presence flags are checked for consistency.

The queue admits at most 256 records and 8 MiB of charged record storage; each
record is at most 66 KiB. Charges include record size and identity vector capacity,
not allocator overhead or total RSS. Copy admission allows eight concurrent
leases. A full or contended queue and allocation failure latch Degraded. Clearing
the queue does not acknowledge loss. The source outlives every lease and queue;
Stopping blocks promotion but does not itself drain a future SDK subscription.

`evaluate` takes an offline provenance fixture and expected ownership keys.
Those records are not trusted IPC messages. A future native owner must confirm
current filters, conditions, layer mapping, temporal identity and source health.
An ambiguous filter ID, stale source, foreign filter or unrealizable package
constraint returns no target. Reconciliation snapshots alone do not prove which
filter generated an old event. Layer GUID mapping is the native owner's job.

Candidate means a structurally attributed gate-drop candidate with restrictions.
It is not an authorization capability. Explicit block drops retain Attempt
evidence; explicit allow events retain PermittedClassification evidence. Neither
produces authorization, observed-traffic evidence or connection-history dates.
Package absence means no package restriction and requires explicit scope consent
downstream. All instances and sessions of the observed principal are covered;
shared-host service identity remains unknown. The central owner must validate the
actor, current pending request, stamp and realizable app/principal/package scope
again before any decision or native operation.
