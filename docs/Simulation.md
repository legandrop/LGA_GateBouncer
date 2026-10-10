# Simulation behavior

This document describes Simulation mode. Its fixed message `Simulation · no network filtering` identifies sample data on every screen and request. Names, publishers, paths, signatures, process states and destinations are fixtures, including familiar application names. They are not inspected on this computer. Live mode is separate: it reads the local process catalog and saves inactive reviews, while engine and network observations remain unavailable unless their sources are authenticated.

## Requests and decisions

Reviewing a pending request opens an in-window, nonmodal notice. Its application scope and duration selections remain in memory when you expand details, navigate, close the notice or press Escape. Those actions do not resolve the request. Allow and Block save explicit sample decisions.

The requested destination is separate from the rule scope: **all outbound destinations and protocols**. Process scope, permanent permissions, timed permissions and restart behavior are simulated descriptions. There is no enforcement or timer that revokes an actual network permission.

Saving or activating a rule records a decision, without creating an authorized attempt or observed traffic. Ask removes the matching sample rule; it does not invent a new network attempt. Sample requests do not originate from the live engine. See the [service implementation and validation limits](../service/README.md) for the separate live paths.

## History

Last attempt, last authorized attempt and observed traffic have separate fixture sources. Authorization alone is not proof of connectivity. Not observed means no matching sample event is present, rather than a claim that an application never connected.

The sample clock is fixed at October 8, 2026, 10:42:40 UTC−03. Relative ages and absolute timestamps use this clock. History coverage is synthetic; it does not describe monitoring of the machine.

## Rules and import

Import loads a built-in sample containing 12 rows. Seven Ready mappings can be saved as inactive candidates; three Needs review and two Unsupported mappings remain excluded, with their reasons visible. No personal XML export is opened. Saving a candidate and explicitly activating it are separate steps.

Cleanup previews rules with old sample attempts and requires explicit selection. It backs up the full synthetic state in memory before removal. Restore recovers policies, rules, pending requests, review selections, events and import state from that snapshot. No executable is removed, and absence of observed traffic is not used as a cleanup criterion.

## Explanations and unavailable state

Settings can enable a sample configured state and consent to the proposed sharing. Automatic explanations default to enabled after consent and can be turned off for manual requests. Expected purpose, insufficient information and errors are synthetic outcomes. Cancellation, closing a notice, a resolved request, configuration removal, revoked consent, reset or loss of the simulated service invalidates a pending response. Responses are plain text and never change policies or network events.

In Simulation, the API key field stays empty and read only; sample explanations do not use a provider. The separate live helper has configuration and explanation source paths, with provider rights, consent, transport, payload, key storage and current-context checks. Their complete operating-system/provider workflow is not validated. Simulation does not demonstrate those checks or their behavior while a real application remains blocked. See the [overview](../README.md) and [Roadmap](../Roadmap.md).

The unavailable service scenario rejects policy changes, import, activation, cleanup and restore in both the interface and the model. The UI closed scenario keeps the preview open to illustrate a proposed state; no service continues enforcing anything.

Escape dismisses the current overlay and keeps unresolved requests pending. Tab follows controls, Enter opens a selected actionable row, and headings can sort the Processes and Activity tables. Help & about reiterates the simulation limits. Reset restores the initial fixtures; closing the application discards session state.
