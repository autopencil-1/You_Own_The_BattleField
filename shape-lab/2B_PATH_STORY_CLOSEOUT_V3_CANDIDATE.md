# Path-story gateway closeout candidate

**Status (2026-11-09):** Model-free engineering candidate only. No new behavioral
schedule, funding authorization, or model run has been created. The frozen v2
pilot, its archives, and the unchanged PentestGPT task remain separate.

## Observed v2 failure

Two v2 attempts stopped at the post-entry wall cap while a gateway request was
in flight. In slot 3, the gateway journal has 193 request starts, 193 completed
upstream `model_call` events with reported usage, and 192 downstream finishes.
The final request's full upstream response was logged after the agent stopped,
but its downstream write never finished. Slot 4 has the same pattern with 132
starts, 132 completed upstream responses, and 131 downstream finishes. The
190-second closeout wait therefore expired in both runs. Their archived usage
estimates are $9.785370680 and $8.913747080 respectively. Both attempts remain
infrastructure-invalid; they are not behavioral outcomes.

The frozen gateway emits `model_call` only after reading the entire upstream
response, then sends that response to the agent and emits `request_finished`
after the send returns. Stopping the agent at the wall cap can leave that send
blocked. Waiting longer would not reliably fix the accounting rule because
provider completion and downstream delivery are separate events.

## Prospective closeout contract

The candidate gateway in `model_gateway/server_path_story_v2.py` journals
`provider_response_complete` immediately after each `model_call`, before
downstream delivery. It bounds the downstream write to 10 seconds and records
`request_finished` or `downstream_delivery_failed`. The candidate runner in
`experiment_controller/run_2b_path_story_pilot_v3.py` requires every started
request to have an accounted provider completion or an explicit local rejection.
Missing provider completion, missing usage for a successful response, aborted
requests, and gateway errors still pause cost accounting. The candidate runner
provisionally allows a downstream failure after a fully recorded provider
response at an agent wall cap; the response delivery failure remains visible
in the attempt evidence. Behavioral validity for a future cohort has not been
frozen.

The versioned Compose overlay is `compose_2b_path_story_pilot_v3.yaml`. It uses
the new gateway image while keeping the same decoy and attacker images. The
candidate does not alter the task, path-story filesystem, or prior v2 source.

## Model-free checks and decision left open

Six local HTTP gateway tests passed with a stubbed upstream; five runner
lifecycle tests passed. Two deployed Docker preflights (B0 and B3) used a dummy
key, started no PentestGPT process, returned a local HTTP 400 for malformed
JSON, recorded a complete local request lifecycle, and made zero model calls.

The next cohort design remains open: a five-slot continuation or a fresh
eight-slot pilot would require its own frozen schedule and a funding rule that
counts the accrued v2 spend against the user's single $100 authorization.
Model-free checks do not establish behavioral equivalence between the v2 and
prospective v3 gateway protocols.
