# IPMI Protocol

The Intelligent Platform Management Interface (IPMI) protocol is a massive blind-spot in physical network engagements. NetExec-RS allows you to hunt, probe, and attack Baseboard Management Controllers (BMCs).

## Execution Basics

IPMI operates over UDP port `623` by default.

```bash
nxc ipmi <target_ip_or_subnet>
```

By default, just running the protocol will send an RMCP Ping and attempt to fingerprint the BMC manufacturer (HP iLO, Dell iDRAC, Supermicro, etc.) and version numbers.

## Modules

### RAKP Hash Extraction (IPMI 2.0 Auth Bypass)
IPMI v2.0 suffers from a design flaw where the HMAC-SHA1 hash of any valid user can be extracted prior to authentication (often referred to as RAKP Message 2 attack or `ipmitool` cipher 0 vulnerability).

```bash
nxc ipmi 10.0.0.0/16 -M dump_hashes -u Administrator
```

NetExec-RS will scan the `/16` looking for IPMI controllers and silently dump the HMAC-SHA1 hash for the user "Administrator". 

### Default Password Checking
Many BMCs ship with well-known hardcoded keys (`ADMIN:ADMIN`, `root:calvin`).
```bash
nxc ipmi 10.10.10.10 -M check_defaults
```

> [!TIP]
> Dumped RAKP hashes are formatted cleanly for Hashcat mode `7300` (IPMI2 RAKP HMAC-SHA1).
