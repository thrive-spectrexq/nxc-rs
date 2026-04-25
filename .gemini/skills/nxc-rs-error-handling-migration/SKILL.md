---
name: nxc-rs-error-handling-migration
description: Migrate generic anyhow errors to typed thiserror enumerations for robust protocol-level error reporting.
risk: safe
---

# NetExec-RS Error Handling Migration

## Overview
NetExec-RS relies on clear, structured error reporting for its automated attack and reconnaissance workflows. The project is migrating away from generic `anyhow::bail!` and `anyhow::Error` towards domain-specific, typed error enumerations using `thiserror`. This skill provides a systematic approach for executing this migration across the codebase.

## When to Use
- When the user asks to "migrate error handling", "replace anyhow with thiserror", or "implement protocol-specific error types".
- When establishing proper error handling structures for newly created protocols or modules.
- When fulfilling the P4 TODO related to typed error migration.

## Instructions
1. Identify the target module or protocol handler (e.g., `smb.rs`, `ldap.rs`, `kerberos.rs`) where `anyhow::Result` or `anyhow::bail!` is predominantly used.
2. Define a protocol-specific error enum (e.g., `SmbError`, `LdapError`) utilizing the `#[derive(thiserror::Error, Debug)]` macro. Ensure error variants encompass the distinct failure states (e.g., `#[error("Authentication failed: {0}")] AuthError(String)`).
3. Systematically replace function return types from `anyhow::Result<T>` to `Result<T, CustomErrorType>`.
4. Replace `anyhow::bail!("message")` calls with `return Err(CustomErrorType::Variant(...))`.
5. Ensure that error contexts correctly map lower-level standard or library errors (like `std::io::Error`) into the custom enum using `#[from]`.
6. Refactor any upper-level callers to gracefully handle or bubble up these new typed errors.
7. Verify the refactoring by running `cargo check` and ensuring no compiler errors or broken API contracts exist.
