# Claims → test matrix

mcprobe's honesty contract (PRD v1.1, R-F1): every public claim in the README is
backed by a passing automated test, or it is softened/removed. This file is the
mapping. Run the suite with `python -m pytest -q` (101 tests as of v1.1).

## Confidence taxonomy → backing tests

| Confidence | Oracle | Backed by |
| ---------- | ------ | --------- |
| **CONFIRMED** (cmd injection, OOB) | Out-of-band callback received | `test_cmdi_confirmed_on_oob_hit`, `test_engine_confirms_cmd_oob_and_names_payload` |
| **CONFIRMED** (SSRF, OOB) | Out-of-band callback received | `test_ssrf_injects_oob_url_and_confirms` |
| **CONFIRMED** (path traversal, canary) | Canary value read back from the response | `test_traversal_confirmed_on_passwd_canary`, `test_scan_confirms_nested_array_enum_traversal` |
| **CONFIRMED** (auth bypass, byte-identical) | Unauthenticated response is byte-identical to the authenticated one | `test_auth_bypass_confirmed_when_unauth_succeeds` |
| **FIRM** (cmd injection, calibrated timing) | Delay exceeds the per-tool calibrated baseline | `test_cmdi_firm_when_delay_exceeds_baseline_margin` |
| **FIRM** (info leak, baseline diff) | Secret-shaped string present in the probe response but absent from the benign baseline | `test_info_leak_firm_on_triggered_diff` |
| **FIRM** (auth bypass, volatile-tolerant) | Responses match only after stripping timestamps/ids/nonces (inferred, not raw) | `test_auth_bypass_firm_when_only_timestamp_differs` |
| **TENTATIVE** (info leak, pattern-only) | Secret-shaped match with no baseline to corroborate | `test_info_leak_tentative_pattern_only_without_baseline` |

## README claims → backing tests

| Claim | Backed by |
| ----- | --------- |
| Enumerates tools, maps params to injection points (top-level, nested, array items, behind required enums) | `test_points_nested_object_path`, `test_points_array_item_path`, `test_points_skip_enum_string`, `test_points_resolve_ref`, `test_scan_confirms_nested_array_enum_traversal` |
| Schema-valid baselines reach the handler (enum/const/format/nested/`$ref`) | `test_baseline_honors_enum`, `test_baseline_honors_const`, `test_baseline_honors_format_uri`, `test_baseline_recurses_required_nested_object`, `test_baseline_resolves_ref` |
| OOB callback confirms blind command injection | `test_cmdi_confirmed_on_oob_hit`, `test_engine_confirms_cmd_oob_and_names_payload` |
| OOB confirms SSRF | `test_ssrf_injects_oob_url_and_confirms` |
| Canary confirms path traversal | `test_traversal_confirmed_on_passwd_canary` |
| Missing authentication via unauthenticated differential (tolerant to volatile fields, not record-id) | `test_auth_bypass_confirmed_when_unauth_succeeds`, `test_auth_bypass_firm_when_only_timestamp_differs`, `test_auth_bypass_none_when_only_record_id_differs`, `test_auth_bypass_none_when_unauth_denied` |
| Payload embedded in a format-valid value reaches handlers behind validation (R-A4) | `test_injection_point_embed_prefixes_valid_value`, `test_cmdi_emits_embed_variant_for_formatted_param` |
| Structured tool output (`structuredContent`) surfaced to oracles (R-A5) | `test_call_tool_flattens_structured_content` |
| One-round-trip OOB polling (`poll_all`) (R-C3) | `test_local_oob_poll_all_returns_all_interactions` |
| Bounded concurrency: identical findings vs sequential, materially faster (R-E1) | `test_engine_concurrency_identical_findings`, `test_engine_concurrency_is_faster` |
| `--rate` request-rate throttle honored across concurrency + calibration (R-E2) | `test_engine_rate_limit_caps_request_rate` |
| CLI exposes `--concurrency`/`--rate`/`--oob-timeout`/`--oob-poll-interval` (rate must be > 0) | `test_cli_parses_scale_flags`, `test_cli_rejects_nonpositive_rate` |
| Cross-OS payloads (POSIX + cmd.exe + PowerShell) generated and confirmed via OOB | `test_cmdi_oob_payloads_cover_posix_cmd_powershell`, `test_engine_confirms_powershell_oob`, `test_engine_confirms_cmd_exe_oob` |
| Per-payload OOB tokens identify the firing separator | `test_cmdi_per_payload_tokens_identify_separator` |
| Late / remote OOB callbacks are caught (poll-until-hit, bounded timeout) | `test_engine_poll_catches_late_oob_callback`, `test_engine_defers_oob_eval_for_delayed_callback` |
| A clean target yields no finding (bounded, no false positive) | `test_engine_poll_bounded_when_no_callback` |
| Time-based oracle is calibrated, not a fixed threshold (no slow-but-safe FP) | `test_cmdi_no_time_fp_on_slow_safe_tool`, `test_slow_safe_tool_no_time_based_fp` |
| Info-leak suppressed when the secret is already in the benign baseline (no docs/validator FP) | `test_info_leak_suppressed_when_secret_in_baseline`, `test_docs_secret_tool_no_info_leak_fp` |
| Per-tool baseline calibration (latency + benign response) | `test_engine_calibrates_once_per_tool`, `test_engine_populates_baseline_response_and_latency`, `test_engine_calibration_can_be_disabled` |
| `--aggressive` gates blocking time-based probes; default is non-blocking only | `test_cmdi_default_omits_blocking_sleep_probes`, `test_cmdi_aggressive_enables_sleep_probes`, `test_engine_plumbs_aggressive_to_checks` |
| Works over stdio (exercised end-to-end) | `test_stdio_session_lists_and_calls_tools` |
| Streamable HTTP transport wired (session factory; CLI headers + auth/unauth differential) - see HTTP caveat below | `test_http_session_factory_exists`, `test_cli_parses_http_scan` |
| Reports in console / JSON / SARIF / Markdown | `test_json_report_structure`, `test_sarif_is_valid_json_with_rules`, `test_markdown_contains_title_and_severity` |
| All five v1 checks registered | `test_all_v1_checks_registered` |

## Claims softened or removed in the honesty pass

| Was | Now | Why |
| --- | --- | --- |
| "reports **only the vulnerabilities it can actively confirm**" | "reports each finding with a **confidence level earned by a concrete oracle**" | The info-leak oracle emits **FIRM**/**TENTATIVE**, not only CONFIRMED; the taxonomy makes that explicit. |
| "**Confirmed-only findings.** ... exploitable issues, not 'potential' ones." | "**Graded, calibrated confidence** (CONFIRMED / FIRM / TENTATIVE)." | Same reason - "confirmed-only" was an overclaim. False-positive *suppression* (the real, tested property) is stated instead. |
| "validated ... against **public vulnerable MCP labs**" | "validated by an automated test suite against bundled fixture servers" | No automated public-lab run exists in CI. Re-add only when a public-lab run is reproducible and documented. |

## Known limitations (honest caveats)

- **Windows payloads are validated for generation and OOB-confirmation wiring, not
  executed against a real cmd.exe / PowerShell host in CI.** Real-shell validation is
  a follow-up.
- **Real interactsh OOB is documented, not CI-tested.** The automated suite uses
  fake OOB providers; a real remote-callback run is the job of
  [interactsh-runbook.md](interactsh-runbook.md), not CI.
- **Time-based probes run serially under concurrency.** To keep their latency
  measurement uncontended, `--aggressive` time-based probes are not parallelised, so
  an aggressive scan pays the full per-probe sleep latency sequentially.
- **Time-based command-injection detection is `--aggressive`-only.** A default scan
  of a target vulnerable *only* to blind/time-based injection (no OOB reachability)
  reports nothing; the CLI prints a note to that effect so an empty report is not
  misread as "secure."
- **Info-leak baseline diff is by matched-pattern identity, not matched substring.**
  A real leak of the same shape as a benign baseline placeholder can be missed.
- **HTTP transport is implemented and wired** (session factory, repeatable headers,
  and the auth/unauth differential for `auth_bypass`) **but the automated suite
  exercises only the session factory, not a live HTTP list+call round-trip.** stdio
  is the end-to-end-tested transport; a live-HTTP e2e is a follow-up.
