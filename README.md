# Get-PrinterMACs

A pure-PowerShell network printer inventory scanner. Point it at a print server's exported queue list (or a spreadsheet of IPs) and it returns each printer's **MAC address, make, model, serial number, and subnet** — using raw SNMP over UDP with zero external dependencies. No SNMP modules, no MIB compilers, no agents.

Built for enterprise print fleets: hundreds of queues, mixed vendors (HP, Zebra, Lexmark, Epson...), mixed firmware generations, scanned in parallel in a couple of minutes.

## Why this exists

Print Management's CSV export tells you the queue name and driver — not the IP, MAC, model, or serial you actually need for asset tracking, DHCP reservations, or switch-port reconciliation. Meanwhile, most SNMP tooling either needs a module installed on a locked-down server or chokes on label printers that only speak SNMPv1. This script fills that gap with hand-built SNMP packets (BER-encoded, v2c with v1 fallback) and vendor-specific workarounds where the standard MIBs come up empty.

## Quick start

```powershell
# 1. Verify SNMP works against one known printer (full hex dump of packets)
.\Get-PrinterMACs2.ps1 -TestIP 10.0.20.50

# 2. Export your printer list from Print Management:
#    Print Servers > [server] > Printers > right-click > Export List
#    > "Text (Comma Delimited) (*.csv)"

# 3. Run the scan on the print server itself
.\Get-PrinterMACs2.ps1 -InputPath .\printers.csv
```

Output lands beside the input as `printers_with_MAC.csv`. CSV-in/CSV-out requires nothing installed — safe for servers with no internet access.

## What it does

1. **Reads the input** — either a Print Management CSV export (no IP column needed) or an .xlsx with an IP column.
2. **Resolves IPs** — when the input has no IP column, it maps each queue through the print spooler (`Get-Printer` → port name → `Get-PrinterPort` → `PrinterHostAddress`), falling back to DNS on the queue's base name. Runs locally on the print server, or remotely via WinRM with `-PrintServer`.
3. **Pings everything in parallel** (runspace pool, default 50 concurrent).
4. **Queries each online device over SNMP** — MAC (`ifPhysAddress`, interfaces 1–4), description (`sysDescr`), model (`hrDeviceDescr`), and serial number, trying SNMPv2c and v1 as needed.
5. **Falls back intelligently** — ARP (`Get-NetNeighbor`) for same-subnet devices that won't answer SNMP; queue-name and driver-name parsing for models; SGD over TCP 9100 for legacy Zebra serials (see below).
6. **Writes one row per queue** with a source column for each derived field, plus a console summary with make/model/subnet breakdowns.

### Serial number retrieval — three paths

Serial numbers are the messy part. The script routes by vendor:

| Device family | Method | OID / mechanism |
|---|---|---|
| HP, Lexmark, Epson, Canon, most lasers | Printer-MIB (standard) | `1.3.6.1.2.1.43.5.1.1.17.1` |
| Zebra Link-OS (ZT4xx, ZD4xx...) | Zebra private MIB | `1.3.6.1.4.1.10642.1.9.0` (+ two alternates) |
| Zebra legacy / ZebraNet (GK420, GX420...) | SGD over TCP 9100 | `! U1 getvar "device.unique_id"` |

The last one matters: **legacy ZebraNet firmware does not publish the printer's serial via SNMP at all** — its MIB describes the print server, not the printer. The script detects these (they identify as `ZebraNet Wired PS` and are v1-only) and queries the serial through Zebra's Set-Get-Do channel on the raw print port instead — the same mechanism Zebra Setup Utilities uses. This is only ever attempted against devices already confirmed as Zebras, since any other brand would treat those bytes as a print job.

Note: `device.unique_id` defaults to the factory serial but is admin-settable. Spot-check one unit against its physical label before trusting a large batch.

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-InputPath` | *(required)* | .csv (Print Management export) or .xlsx (must contain an IP column) |
| `-OutputPath` | `<input>_with_MAC.<ext>` | Output file; extension picks the format (.csv or .xlsx) |
| `-PrintServer` | parsed from CSV | Server to query for queue→port→IP mapping (WinRM if remote) |
| `-TestIP` | — | Diagnostic mode: scan one device with full packet hex dumps |
| `-SnmpCommunity` | `public` | SNMP read community string |
| `-PingTimeoutMs` | `1000` | Per-host ping timeout |
| `-SnmpTimeoutMs` | `1500` | Per-OID SNMP receive timeout |
| `-ThrottleLimit` | `50` | Max concurrent runspaces |

## Output columns

`Printer Name` · `Queue Status` · `IP Address` · `Subnet` (first three octets) · `IP Source` (Port / DNS / File) · `Status` (Online / Offline / No IP) · `MAC Address` · `Method` (SNMP / ARP) · `Make` · `Model` · `Model Source` (SNMP / QueueName / Driver) · `Serial Number` · `Description` (raw sysDescr) · `Driver Name`

The `* Source` columns tell you how trustworthy each value is: SNMP-derived data came from the device itself; QueueName/Driver values are inferred from the print server's configuration.

## Requirements

- Windows PowerShell 5.1+ (uses WPF-free .NET classes only: `UdpClient`, `TcpClient`, `Ping`, runspaces)
- UDP 161 open from the scanning host to the printers; TCP 9100 for the legacy-Zebra serial fallback
- SNMP enabled on the printers with a known read community
- For IP resolution from a CSV export: run on the print server, or WinRM access to it (`-PrintServer`)
- `ImportExcel` module — **only** if reading or writing .xlsx (auto-installed to CurrentUser scope); pure CSV workflows need nothing

## Diagnostic mode

Before a full sweep — or whenever a device family returns blanks — run `-TestIP` against one unit:

```
--- Step 1: Ping ---
--- Step 2: MAC discovery (ifPhysAddress 1..4, v2c then v1) ---
--- Step 3: sysDescr.0 --- (with request/response hex dumps)
--- Step 4: hrDeviceDescr.1 ---
--- Step 5: Serial number (vendor-aware OID chain) ---
--- Step 5b: Zebra SGD fallback (TCP 9100) --- (Zebras only, when SNMP has no serial)
```

The hex dumps make it straightforward to diagnose community-string mismatches, v1-only agents, and devices with SNMP disabled.

## Implementation notes

- SNMP GET packets are constructed byte-by-byte (BER/DER encoding) and parsed with a proper structural walker — no string matching on payloads. Multi-byte (base-128) OID sub-identifiers are supported, which is what makes enterprise arcs like Zebra's `10642` reachable.
- Legacy label printers frequently drop SNMPv2c requests without answering (no error, just a timeout). The script always retries with v1 — and for Zebra serial lookups tries v1 *first* to avoid burning timeouts.
- Multiple queues often point at one physical device; scanning is deduplicated per unique IP and results are fanned back out to every queue row.
- Generic model strings some firmware returns ("Zebra Printer") are rejected so the queue-name/driver fallbacks can supply the real model.

## Limitations

- SNMPv3 is not supported (v1/v2c only).
- Serial retrieval for vendors outside the table above depends on their Printer-MIB compliance; devices that implement neither path show a blank.
- ARP fallback only works for devices on the same subnet as the scanning host.
- WSD-ported queues with non-resolving names can't be mapped to an IP and are reported as `No IP`.

## License

MIT
