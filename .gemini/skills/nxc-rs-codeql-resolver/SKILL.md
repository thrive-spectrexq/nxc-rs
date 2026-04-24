---
name: nxc-rs-codeql-resolver
description: Systematically resolve CodeQL security alerts and pull requests in NetExec-RS.
risk: safe
---

# NetExec-RS CodeQL Resolver

## Overview
NetExec-RS utilizes CodeQL for static application security testing (SAST). This skill provides a systematic approach for reviewing, addressing, and merging CodeQL security alerts and pull requests.

## When to Use
- When addressing CodeQL alerts or PRs.
- When the user asks to "resolve CodeQL pull requests" or "fix security vulnerabilities".

## Instructions
1. Use the GitHub CLI (`gh pr list --label "security"`) or view the security alerts dashboard.
2. For each identified alert (e.g., potential memory safety issues, unhandled errors, cryptographic logic flaws), locate the corresponding source file.
3. Formulate a patch that resolves the issue without introducing new regressions or breaking API contracts.
4. Run tests and `cargo clippy --workspace` to ensure CI remains compliant.
5. Create a clean commit addressing the vulnerability and push/merge the changes safely.
