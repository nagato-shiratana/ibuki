# Security Review: GRE/XFRM Blocking Management

Reviewed: 2026-10-27

## Scope and limitations

This review examined GRE/XFRM blocking policy matching, the relationship between
GRE outer and inner selectors, and recovery when tracked state differs from
kernel state. The findings below are supported by local code/model or mocked
command-execution reproductions. They do not establish exposure on a live
kernel, plaintext leakage in real traffic, or remote exploitability.

## Findings

### 1. Incomplete XFRM policy equivalence checks

- **Severity:** Medium
- **Confidence:** 8/10
- **Location:** `src/command_adapters.c:427-430, 443-465`

The policy lookup treats matching source/destination, direction, priority, and
`action block` as sufficient, without checking selector protocol, mark, or
interface ID. Matching TCP-only block policies in both directions can
therefore be treated as an all-protocol block, causing `apply_xfrm_block()` to
skip installing the broader policy. GRE or other unmatched traffic may remain
uncovered if no other deny rule applies.

The unchanged code reproduced this behavior using synthetic
`ip xfrm policy list` output. The prerequisite is matching pre-existing kernel
policy state; the reproduction did not use a live kernel or traffic.

### 2. GRE outer/inner selector mismatch

- **Severity:** Medium
- **Confidence:** 8/10
- **Locations:** `src/render_commands.c:104-112`,
  `src/command_adapters.c:423-437`, `src/apply_plan.c:178-194`

For `gre_over_ipsec`, the IPsec selector is built from the GRE outer endpoints
as `/32[gre]`, while the block policy uses the local and remote traffic
selectors. When inner and outer addresses differ, the block policy does not
match the outer GRE packet. If the protecting XFRM policy is absent and no
other drop rule covers that packet, the configured `block_non_ipsec` guard may
not prevent cleartext GRE egress.

The sample configuration uses inner selectors `10.10.1.0/24` and
`10.10.2.0/24`, and outer endpoints `172.16.1.1` and `172.16.2.1`. The code
replay and model confirmed the selector mismatch for that configuration. Real
packet-path exposure was not tested.

### 3. Tracked state can mask missing kernel policies

- **Severity:** Medium
- **Confidence:** 8/10
- **Location:** `src/command_adapters.c:411-417, 426-430, 479-488`

`apply_xfrm_block()` returns success when the tunnel ID is already in the
in-memory tracking list, without checking kernel state. If a tracked policy is
removed externally, or deletion of one direction fails, a subsequent ensure
can report success while one or both block policies are absent.

A local mocked-command replay reproduced a second-direction deletion failure
that left tracking metadata set while one policy was missing; the early return
then bypassed kernel-state checks and policy-add commands. The replay did not
modify a real kernel or demonstrate packet exposure.
