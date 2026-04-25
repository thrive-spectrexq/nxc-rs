---
name: nxc-rs-ci-stabilizer
description: Stabilize NetExec-RS CI builds by parsing clippy output, removing unused imports, resolving deprecations, and fixing configurations.
risk: safe
---

# NetExec-RS CI Stabilizer

## Overview
The `nxc-rs` project has strict CI requirements, specifically using `cargo clippy --workspace --all-targets -- -D warnings`. This skill automates the resolution of common CI failures, such as `unused_imports`, `needless_borrows`, `unexpected_cfgs`, cryptographic deprecation warnings, and ensures safety standards are maintained.

## When to Use
- When the CI pipeline is failing due to warnings.
- When the user asks to "fix failing workflow jobs", "resolve CI workflow failures", "fix clippy warnings/unused imports", or "fix deprecation warnings".
- When stabilizing the build environment.

## Instructions
1. Run `cargo clippy --workspace --all-targets -- -D warnings` to identify current issues.
2. If `unexpected_cfgs` or `unused_imports` (especially `anyhow::Context`) appear, edit the corresponding files to remove the unused imports or fix the `cfg` attributes.
3. If `needless_borrows` or similar lints appear, refactor the code according to Clippy's suggestions.
4. If deprecation warnings appear (e.g., from `cipher` 0.5+ API migrations), update the deprecated trait usages to the modernized API calls to ensure CI passes.
5. Ensure no new `unsafe` blocks or unsafe dependencies are introduced without explicit safety documentation and validation.
6. Rerun `cargo check` and `cargo clippy` to verify the build is clean.
7. Do not proceed to other tasks until the build is perfectly warning-free and CI-compliant.
