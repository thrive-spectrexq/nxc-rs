---
name: nxc-rs-unsafe-code-remediation
description: Systematically eliminate unsafe code blocks and replace them with safe Rust alternatives to harden the NetExec-RS codebase.
risk: safe
---

# NetExec-RS Unsafe Code Remediation

## Overview
NetExec-RS aims for a 100% safe Rust core, especially given its role in handling untrusted network data. This skill provides a systematic approach for finding and eliminating `unsafe` blocks, raw pointer manipulation, and risky `as` casts throughout the codebase.

## When to Use
- When the user asks to "eliminate unsafe code blocks", "resolve unsafe code violations", or "harden codebase".
- When auditing code for potential memory safety issues or unverified assumptions during type downcasting.
- During protocol handler reviews (e.g., SMB, Kerberos, LDAP) where wire data is parsed into Rust structures.

## Instructions
1. Use search tools (e.g., `grep_search`) to locate `unsafe` blocks, `as` casts, or direct raw pointer dereferences (`*mut T`, `*const T`) within the project, specifically targeting the `protocols/` or `auth/` directories.
2. For each identified instance, analyze the intent of the unsafe block:
   - If it is for downcasting trait objects, replace it with `std::any::Any` safe downcasting (`downcast_ref` or `downcast_mut`).
   - If it is for parsing wire bytes into structs, utilize safe mapping methods, `TryFrom`/`TryInto` traits, or robust parsing libraries (like `nom` or `zerocopy` if included in dependencies).
   - If it is for raw memory manipulation, refactor to use safe slices (`&[u8]`) or standard library collections.
3. Apply the changes and replace the unsafe operations with explicit error handling where assumptions might fail (e.g., replacing `.unwrap()` with `Result` propagation).
4. Build the project using `cargo check` and run `cargo test` to ensure that no functional regressions have been introduced and the build passes.
5. Provide a clear commit or summary detailing the replaced unsafe blocks and their new safe equivalents.
