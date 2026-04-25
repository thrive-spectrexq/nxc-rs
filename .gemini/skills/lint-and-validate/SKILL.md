---
name: lint-and-validate
description: "MANDATORY: Run appropriate validation tools after EVERY code change. Do not finish a task until the code is error-free."
risk: unknown
source: community
date_added: "2026-02-27"
---

# Lint and Validate Skill

> **MANDATORY:** Run appropriate validation tools after EVERY code change. Do not finish a task until the code is error-free.

### Procedures by Ecosystem

#### Node.js / TypeScript
1. **Lint/Fix:** `npm run lint` or `npx eslint "path" --fix`
2. **Types:** `npx tsc --noEmit`
3. **Security:** `npm audit --audit-level=high`

#### Rust
1. **Linter (Clippy):** `cargo clippy --workspace --all-targets --all-features -- -D warnings`
2. **Format (Rustfmt):** `cargo fmt --all`
3. **Build/Check:** `cargo check --workspace --all-targets`

## The Quality Loop
1. **Write/Edit Code**
2. **Run Audit:** `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
3. **Analyze Report:** Check the compiler and linter output.
4. **Fix & Repeat:** Submitting code with compilation or clippy failures is NOT allowed.

## Error Handling
- If `cargo clippy` fails: Fix the style or safety issues immediately.
- If `cargo check` fails: Correct compiler errors before proceeding.
- If no tool is configured: Check the project root for `Cargo.toml`.

---
**Strict Rule:** No code should be committed or reported as "done" without passing these checks.

---



## When to Use
This skill is applicable to execute the workflow or actions described in the overview.
