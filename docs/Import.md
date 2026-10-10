# Inactive import review

In Live mode, open Import and choose a source profile before selecting a file. Structural XML retains a structural view with unknown semantics. NetLimiter QName profile reconstructs a bounded source subset using exact XML namespaces and known source types. The application does not select either profile automatically.

Choose migration XML opens a local file selector. Reading and analysis run in the background, with an 8 MiB input limit. Cancel analysis stops publication of that analysis; selecting another file replaces the current analysis. A rejected file preserves the previous preview. Closing waits for active local work to drain.

The preview and its details distinguish known action, direction, enabled state, weight and source constraints from unknown or incomplete fields. Original Deny (3) and Block (4) are separate source actions. Paths, source SID bytes, package and service information are source evidence, not verified Windows identities. A known subset does not establish compatibility, complete overlap analysis or an enforced rule.

An explicit nil SID remains an unknown principal scope. It is never replaced with the current account or assumed to mean all accounts. Original disabled rules stay inactive, including Ask. An enabled Ask needs a decision for the pending connection; choosing a fixed Allow or Block is a new review choice rather than an equivalent translation.

The source comparison preserves AND between filter functions and OR between their values. When the entire AND structure is known, a proven false range can exclude that filter even if another predicate remains unknown. This proves exclusion only: an unknown SID inside the range still prevents admission. Missing values, malformed namespaces or match flags, incomplete OR lists and unsupported base or package structure preserve Unknown.

Source weights retain their original values. A higher weight takes precedence, but equal or unknown competing weights require review; source ordinal and XML order do not resolve a tie. Internet and Local Network use editable zone membership, not an inferred address class. Tag definitions do not establish current application membership or an empty set. These unresolved conditions are kept together and rejected as a whole rather than omitted to create a broader application rule. See the official [filter semantics](https://netlimiter.com/docs/basic-concepts/filters), [blocker actions and weights](https://netlimiter.com/docs/basic-concepts/blocker), [zones](https://netlimiter.com/docs/basic-concepts/zones) and [tags](https://netlimiter.com/docs/basic-concepts/filters/tags).

Save all inactive candidates retains the projected evidence locally. In Rules, Review lets you choose Allow, Block or Ask for that inactive candidate. Save inactive review changes only this local review choice; it does not rewrite the original source action or apply a firewall policy. Reopening loads the saved evidence and derives its source facts again. Unknown authorization and traffic remain unknown.

An imported detail stays bound to its own preview or saved revision. An unrelated engine status change does not discard a current imported detail. Replacing or clearing its source context invalidates that detail.

Only the Version, Rules, Filters and AppInfos projection is retained for the QName profile. Unrelated root settings are excluded. Details show a bounded plain-text excerpt; the saved projection retains the source evidence within its storage limits. Unsupported or omitted constraints remain visible as incomplete or unknown instead of becoming broader permissions.

This workflow has been exercised with synthetic files and inactive local persistence. It does not establish fidelity to an installed NetLimiter export, Windows identity acquisition or filtering. Large review-store save and load operations retain a synchronous API; background parsing does not imply that every persistence operation is asynchronous. There is no installer or validated protection profile.
