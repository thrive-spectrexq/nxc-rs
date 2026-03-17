# NetSage + NetExec-RS — Example Network Context

## Topology
- **Production Subnet**: 10.0.1.0/24
- **Management Subnet**: 192.168.10.0/24

## Key Devices
- **Core Router**: 10.0.1.1
- **Database Server**: 10.0.1.50 (Port 5432)
- **Web App**: 10.0.1.20 (Port 80, 443)

## SLA Thresholds
- **Max Latency**: 50ms
- **Max Packet Loss**: 1%

## Active Directory (nxc Context)
- **Domain**: corp.local
- **Domain Controller**: DC01 — 10.0.1.10
- **Domain Controller**: DC02 — 10.0.1.11
- **Domain Admin**: CORP\Administrator
- **Service Accounts**: svc_sql, svc_web, svc_backup
- **MSSQL Server**: SQL01 — 10.0.1.30 (Port 1433)
- **File Server**: FS01 — 10.0.1.50
