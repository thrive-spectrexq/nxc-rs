# iLO / iDRAC Protocol

NetExec-RS includes natively integrated Redfish REST API testing to abuse Integrated Lights-Out (HP) and iDRAC (Dell) baseboard management controllers without touching the main OS.

## Execution Basics

Out-of-band management controllers usually listen on a web interface on port `443`. HP iLO can also use `17988`.

```bash
nxc ilo 10.0.0.0/24
```

This will fingerprint the target, report the specific iLO/iDRAC version, chassis serial number, and power state via generic Redfish unauthenticated metadata endpoints.

## Authentication Brute Forcing

By default, the `ilo` protocol supports massive credential stuffing.
```bash
nxc ilo 10.0.0.0/24 -u root Administrator -p ilo_passwords.txt
```

## Modules

### 1. Extract System Data (`sys_info`)
Dump hardware specifications, MAC addresses, and motherboard serial numbers via Redfish APIs.
```bash
nxc ilo <target> -M sys_info -u admin -p default
```

### 2. Reboot & Power Routines (`power_control`)
Cycle the bare metal hypervisor from the out-of-band interface.
```bash
nxc ilo <target> -M power_control --command reset
```
