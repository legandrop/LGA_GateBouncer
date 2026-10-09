# Application identity

`gatebouncer_appidentity` transforms bounded, owned copies of WFP application and principal fields into an exact identity tuple and plain display text. It performs no event acquisition, process enumeration, file access or network operation.

The consumer must first validate the event against its own filter inventory, provider, layer, event class and current engine epoch. `EventBinding` supports freshness checks; it does not authenticate the event. `Attributed` carries no authorization and must never resolve a pending request by itself.

The admitted UTF-16LE application blob profile is experimental. Unsupported encodings, invalid UTF-16, embedded NULs, invalid SIDs and inconsistent fields return no target. Native observations must validate the profile before claiming application coverage. Original blob bytes are preserved, including an optional final NUL; no case, path or Unicode normalization is applied to identity.

The tuple is application blob + observed user SID + observed package SID when present. It covers all instances and sessions of that principal; shared hosts can include multiple services. It cannot identify a PID, process lifetime, individual hosted service, executable hash, signature or reputation.

`PackageUnspecified` means **no package restriction**, not proof of an unpackaged application. UI and engine must explicitly honor this scope before a decision is applicable. An unreadable or invalid package SID returns no target. `ExactObservedPackage` must retain and apply that constraint; a consumer must reject unsupported scopes instead of broadening them.

The future motor must build the observed user constraint as a self-relative security descriptor with `FWP_ACTRL_MATCH_FILTER`, rather than treating the SID as an `FWP_SID` condition. Package constraints use the separate package condition. This module does not build or evaluate those filters.

The private in-memory comparison key contains ASCII `GBAI`, version `uint8=1`, package mode `uint8` (`0` unspecified, `1` exact), three little-endian `uint32` lengths, then the exact app/user/package bytes. It is not a persistence or IPC format. Display values never reconstruct a target.

Display strings are bounded and escape markup characters, controls and direction marks. Render them as plain text without automatic rich text, link detection, shell actions or external requests. Paths and SIDs are local data and are not search or assistance payloads by default.

`makeWindowsSidFormatter()` validates a length-checked aligned copy and converts the SID locally, without account lookup. Build the library with the consumer's compiler; C++ objects from MSVC and MinGW are not interchangeable.
