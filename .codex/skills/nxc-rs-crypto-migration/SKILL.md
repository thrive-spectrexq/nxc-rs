---
name: nxc-rs-crypto-migration
description: Stabilize NetExec-RS cryptographic infrastructure and resolve dependency conflicts for cipher APIs.
risk: safe
---

# NetExec-RS Cryptographic Migration

## Overview
The project is transitioning to a stabilized, modular cryptographic architecture based on the `cipher` 0.5+ API. This skill ensures that dependency updates (like `hmac`, `md5`, `aes`, `cbc`, `des`) are safely implemented without breaking traits or causing CI deprecation warnings.

## When to Use
- When updating or fixing cryptographic dependencies.
- When the user asks to "stabilize cryptographic build infrastructure" or "fix crate conflicts".

## Instructions
1. Review `Cargo.toml` and `Cargo.lock` to ensure all cryptographic crates align around compatible `cipher` crate versions.
2. Update structs/traits (like `BlockCipher`, `BlockEncrypt`, `BlockDecrypt`) to use the correct API calls.
3. Suppress or fix any deprecation warnings caused by legacy cryptographic implementations to satisfy `-D warnings`.
4. Ensure the codebase correctly handles payload relaying and memory safety around sensitive data structures.
