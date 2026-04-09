# DNS Protocol

NetExec-RS supports querying, enumerating, and interacting with DNS servers natively without depending on OS-level utilities like `nslookup` or `dig`.

## Execution Basics

```bash
nxc dns <target_nameserver> [options]
```

## Supported Operations

### 1. Zone Transfers (AXFR)
Attempt to perform an asynchronous zone transfer to dump the entire internal DNS structure.
```bash
nxc dns 10.0.0.53 -M axfr --domain targ.local
```

### 2. Record Enumeration
Perform targeted lookups against specific subdomains or record types (A, AAAA, MX, TXT).
```bash
nxc dns 10.0.0.53 -M enum_records --type TXT
```

### 3. Dynamic Update Detection
Detect if the DNS server allows insecure dynamic updates, which can be leveraged for active Man-In-The-Middle attacks (e.g., WPAD hijacking or Responder/Inveigh routing).
```bash
nxc dns 10.0.0.53 -M test_update
```

> [!TIP]
> The DNS module integrates seamlessly into the target parser. The discovered records will automatically be populated into your local SQLite `nxc.db` for subsequent protocol cross-testing (e.g., feeding the found hostnames straight into the SMB module).
