# Allowed differences from the 5f09d38 baseline

`bash scripts/flows.sh --compare baseline` passes only when the head's differences from the
recorded `5f09d38` transcripts are exactly the lines in `ALLOWED_DIFFS.lines`. Each entry below
says why the difference is intended. Anything else is a regression (PLAN.md GATE 6, M12).

| Flow | Difference | Why | Test that pins it |
| --- | --- | --- | --- |
| 04-capability-issue | `capability issue --agent flow-agent` issues an agent-bound token (exit 0); 0.3.7 exited 4 with "secret not found". | D24: `--agent` is documented as the agent name but was looked up as an id. Now name first, then id. | `agent_token_needs_a_proof_and_relay_call_supplies_it` (lockrail-cli relay_call_flow) |
| 05-relay | After `capability revoke`, a running relay answers `capability revoked`; 0.3.7 still accepted the token and refused only on the host check. | D1: the relay reloads the vault per request, so a revocation made after start takes effect. | `relay_honours_revocation_made_after_start` (lockrail-relay) |
| 07-env-seal | `OPENAI_API_KEY` in a `.env` with a `GITHUB_TOKEN` line above is sealed as `openai-key`; 0.3.7 reported a report-only `high-entropy-token` and wrote the raw key into `.env.lockrail`. | D22: overlap resolution now prefers the finding that seals. | `report_only_match_never_shadows_a_sealing_finding` (lockrail-engine) |
| 07-env-seal | `env run` injects the sealed value (`resolved`); 0.3.7 passed the handle string to the child (`not-resolved`). | D23: the resolver matched the namespace prefix against the detector kind, so no handle ever resolved. | `env_run_injects_the_sealed_value` (lockrail-cli harness_flow) |

Flows 01, 02, 03, 06, 08 and 09 are byte-identical after normalisation. The normaliser maps
fingerprints (`fp_`/`h_`) to `<FP>`, because keyed handles (Phase 3D) use a per-home random key.
