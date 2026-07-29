<#
.SYNOPSIS
    Scans network printers from an Excel workbook OR a print-server CSV export,
    retrieves MAC addresses, make, and model via SNMP, and writes results to a
    new Excel or CSV file.

.DESCRIPTION
    Workflow:
      1. Read printer rows from the input .xlsx or .csv
      2. Resolve an IP for every printer:
         - If the input has an IP column, use it directly
         - Otherwise (e.g. a Print Management "Text (Comma Delimited)" export,
           which contains no IP column), resolve IPs from the print server's
           port configuration (Get-Printer -> PortName -> Get-PrinterPort ->
           PrinterHostAddress), falling back to DNS on the queue's base name
      3. Ping every IP in parallel
      4. For each online printer:
         - SNMP query for MAC address (ifPhysAddress, tries v2c then v1, ifaces 1-4)
         - SNMP query for device description (sysDescr.0)
         - SNMP query for device model (hrDeviceDescr.1 - 1.3.6.1.2.1.25.3.2.1.3.1)
         - SNMP query for serial number (prtGeneralSerialNumber.1 - 1.3.6.1.2.1.43.5.1.1.17.1)
         - Parse into best-effort "Make" and "Model" columns
      5. Fall back to Get-NetNeighbor for same-subnet devices that didn't answer SNMP
      6. If SNMP yields no model, fall back to the model hint in the queue name
         (text in parentheses), then the driver name
      7. Write results to a new .xlsx or .csv

    DIAGNOSTIC MODE:
      Use -TestIP <addr> to query a single printer with full hex dump of the
      request and response. Verify SNMP works against one device first.

.PARAMETER InputPath
    Input file. Either:
      - .xlsx with an IP column and printer-name column, or
      - .csv exported from Print Management (Printer Name, Queue Status,
        Jobs In Queue, Server Name, Driver Name, ...) - no IP column needed.

.PARAMETER OutputPath
    Output .xlsx or .csv. Default: <input>_with_MAC.<same extension> beside the
    input. CSV output has no module dependencies (nothing to install on a server).

.PARAMETER PrintServer
    Print server to query for the printer->port->IP mapping when the input has
    no IP column. Default: parsed from the "Server Name" column (e.g.
    "BUSCMFFPS001VM (local)" -> BUSCMFFPS001VM). If it matches the local
    computer name, local cmdlets are used; otherwise remote CIM via WinRM.

.PARAMETER PjlFallback
    Optional. When a PJL-native laser vendor (HP, Lexmark, Brother, Kyocera,
    Xerox, Ricoh, Canon) yields no model or serial via SNMP, probe the device
    with "@PJL INFO ID" over TCP 9100. This recovers the ACTUAL printer's
    model behind external JetDirect EX boxes, whose SNMP agent only describes
    the box itself. Off by default: a pre-PJL device (e.g. an old dot-matrix
    on a JetDirect EX parallel port) would print the probe as a garbage page.
    The -TestIP diagnostic always attempts the PJL probe for these vendors.

.PARAMETER TestIP
    Diagnostic mode. Test one IP and print the SNMP packets in hex.

.PARAMETER SnmpCommunity
    SNMP read community. Default: public.

.PARAMETER PingTimeoutMs
    Per-host ping timeout (ms). Default: 1000.

.PARAMETER SnmpTimeoutMs
    Per-OID SNMP receive timeout (ms). Default: 1500.

.PARAMETER ThrottleLimit
    Max concurrent runspaces. Default: 50.

.EXAMPLE
    # Test one printer to confirm SNMP works
    .\Get-PrinterMACs2.ps1 -TestIP 10.146.253.67

.EXAMPLE
    # Run against the Print Management CSV export, on the print server itself
    .\Get-PrinterMACs2.ps1 -InputPath .\printers_7_22_26.csv

.EXAMPLE
    # Run from a workstation, resolving ports remotely from the print server
    .\Get-PrinterMACs2.ps1 -InputPath .\printers_7_22_26.csv -PrintServer buscmffps001vm

.EXAMPLE
    # Original xlsx workflow still works
    .\Get-PrinterMACs2.ps1 -InputPath .\networkPrinters.xlsx
#>
[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Scan')]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$InputPath,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$OutputPath,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$PrintServer,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$PjlFallback,

    [Parameter(Mandatory, ParameterSetName = 'Diagnose')]
    [string]$TestIP,

    [string]$SnmpCommunity = 'public',
    [int]$PingTimeoutMs    = 1000,
    [int]$SnmpTimeoutMs    = 1500,
    [int]$ThrottleLimit    = 50
)

# ============================================================================
# SNMP code - injected into both the main session (for -TestIP) and into each
# worker runspace via Invoke-Expression. One source of truth.
# ============================================================================
$SnmpCode = @'
# Encodes one OID sub-identifier in BER base-128 form (7 bits per byte, high
# bit set on all but the last byte). Values < 128 stay single-byte, so
# standard MIB OIDs are unchanged; this enables enterprise arcs like 10642
# (Zebra) and 683.
function ConvertTo-BerSubId {
    param([Parameter(Mandatory)] [long]$Value)
    if ($Value -lt 128) { return ,[byte]$Value }
    $groups = New-Object System.Collections.ArrayList
    $v = $Value
    while ($v -gt 0) {
        [void]$groups.Insert(0, [int]($v -band 0x7F))
        $v = $v -shr 7
    }
    $bytes = for ($i = 0; $i -lt $groups.Count; $i++) {
        if ($i -lt $groups.Count - 1) { [byte]($groups[$i] -bor 0x80) } else { [byte]$groups[$i] }
    }
    return ,@($bytes)
}

# Builds an SNMPv1/v2c GET packet for any OID. Sub-identifiers of any size are
# supported via base-128 encoding; the resulting packet must still fit in
# short-form BER lengths for the inner structures (true for any single-OID GET
# with a realistic community string).
function Build-SnmpGetPacket {
    param(
        [Parameter(Mandatory)] [string]$Community,
        [Parameter(Mandatory)] [long[]]$OID,
        [Parameter(Mandatory)] [int]$RequestId,
        [ValidateSet(0, 1)] [int]$Version = 1   # 0 = SNMPv1, 1 = SNMPv2c
    )

    $commBytes = [System.Text.Encoding]::ASCII.GetBytes($Community)
    if ($commBytes.Length -gt 94) { throw "Community string too long." }

    # OID body: first two sub-IDs combined as 40*A+B, rest base-128 encoded
    $oidBody = [System.Collections.Generic.List[byte]]::new()
    $oidBody.Add([byte](40 * $OID[0] + $OID[1]))
    for ($i = 2; $i -lt $OID.Length; $i++) {
        foreach ($b in (ConvertTo-BerSubId -Value $OID[$i])) { $oidBody.Add([byte]$b) }
    }
    if ($oidBody.Count -gt 127) { throw "Encoded OID too long for short-form length." }

    # Build inner pieces with their wrappers
    $vbContent = [System.Collections.Generic.List[byte]]::new()
    $vbContent.Add([byte]0x06); $vbContent.Add([byte]$oidBody.Count)
    foreach ($b in $oidBody) { $vbContent.Add($b) }
    $vbContent.Add([byte]0x05); $vbContent.Add([byte]0x00)            # NULL value

    $vb = [System.Collections.Generic.List[byte]]::new()
    $vb.Add([byte]0x30); $vb.Add([byte]$vbContent.Count)
    foreach ($b in $vbContent) { $vb.Add($b) }

    $vbList = [System.Collections.Generic.List[byte]]::new()
    $vbList.Add([byte]0x30); $vbList.Add([byte]$vb.Count)
    foreach ($b in $vb) { $vbList.Add($b) }

    $pduContent = [System.Collections.Generic.List[byte]]::new()
    # request-id INTEGER (force 4 bytes, MSB cleared so it's always positive)
    $pduContent.Add([byte]0x02); $pduContent.Add([byte]0x04)
    $pduContent.Add([byte]((($RequestId -shr 24) -band 0x7F)))
    $pduContent.Add([byte]((($RequestId -shr 16) -band 0xFF)))
    $pduContent.Add([byte]((($RequestId -shr  8) -band 0xFF)))
    $pduContent.Add([byte](( $RequestId          -band 0xFF)))
    # error-status, error-index
    $pduContent.Add([byte]0x02); $pduContent.Add([byte]0x01); $pduContent.Add([byte]0x00)
    $pduContent.Add([byte]0x02); $pduContent.Add([byte]0x01); $pduContent.Add([byte]0x00)
    foreach ($b in $vbList) { $pduContent.Add($b) }

    if ($pduContent.Count -gt 127) { throw "PDU content too large for short-form length." }

    $pdu = [System.Collections.Generic.List[byte]]::new()
    $pdu.Add([byte]0xA0); $pdu.Add([byte]$pduContent.Count)
    foreach ($b in $pduContent) { $pdu.Add($b) }

    # Outer content: version + community + PDU
    $outerContent = [System.Collections.Generic.List[byte]]::new()
    $outerContent.Add([byte]0x02); $outerContent.Add([byte]0x01); $outerContent.Add([byte]$Version)
    $outerContent.Add([byte]0x04); $outerContent.Add([byte]$commBytes.Length)
    foreach ($b in $commBytes) { $outerContent.Add($b) }
    foreach ($b in $pdu) { $outerContent.Add($b) }

    $outer = [System.Collections.Generic.List[byte]]::new()
    $outer.Add([byte]0x30)
    if ($outerContent.Count -lt 128) {
        $outer.Add([byte]$outerContent.Count)
    } elseif ($outerContent.Count -lt 256) {
        $outer.Add([byte]0x81); $outer.Add([byte]$outerContent.Count)
    } else {
        $outer.Add([byte]0x82)
        $outer.Add([byte](($outerContent.Count -shr 8) -band 0xFF))
        $outer.Add([byte]($outerContent.Count -band 0xFF))
    }
    foreach ($b in $outerContent) { $outer.Add($b) }

    return ,$outer.ToArray()
}

# Reads a BER length at a given offset.
function Read-BerLength {
    param([byte[]]$Data, [int]$Offset)
    $first = [int]$Data[$Offset]
    if ($first -lt 128) { return @{ Length = $first; Consumed = 1 } }
    $n = $first -band 0x7F
    $len = 0
    for ($i = 0; $i -lt $n; $i++) {
        $len = ($len -shl 8) -bor [int]$Data[$Offset + 1 + $i]
    }
    return @{ Length = $len; Consumed = 1 + $n }
}

# Walks the BER structure of a GetResponse and stops at the value's tag/length/data.
# Returns @{ Tag; Offset; Length } or $null on parse failure.
function Find-SnmpValuePosition {
    param([byte[]]$Data)
    if (-not $Data -or $Data.Length -lt 30) { return $null }
    try {
        $off = 0

        # Outer SEQUENCE
        if ($Data[$off] -ne 0x30) { return $null }
        $off++
        $l = Read-BerLength $Data $off; $off += $l.Consumed

        # version INTEGER (skip)
        if ($Data[$off] -ne 0x02) { return $null }
        $off++
        $l = Read-BerLength $Data $off; $off += $l.Consumed + $l.Length

        # community OCTET STRING (skip)
        if ($Data[$off] -ne 0x04) { return $null }
        $off++
        $l = Read-BerLength $Data $off; $off += $l.Consumed + $l.Length

        # GetResponse PDU (0xA2)
        if ($Data[$off] -ne 0xA2) { return $null }
        $off++
        $l = Read-BerLength $Data $off; $off += $l.Consumed

        # request-id, error-status, error-index (skip all three)
        for ($i = 0; $i -lt 3; $i++) {
            if ($Data[$off] -ne 0x02) { return $null }
            $off++
            $l = Read-BerLength $Data $off; $off += $l.Consumed + $l.Length
        }

        # varbind list SEQUENCE
        if ($Data[$off] -ne 0x30) { return $null }
        $off++
        $l = Read-BerLength $Data $off; $off += $l.Consumed

        # varbind SEQUENCE
        if ($Data[$off] -ne 0x30) { return $null }
        $off++
        $l = Read-BerLength $Data $off; $off += $l.Consumed

        # OID (skip)
        if ($Data[$off] -ne 0x06) { return $null }
        $off++
        $l = Read-BerLength $Data $off; $off += $l.Consumed + $l.Length

        # We're at the value tag now
        $valTag = $Data[$off]
        $off++
        $l = Read-BerLength $Data $off; $off += $l.Consumed
        return @{ Tag = $valTag; Offset = $off; Length = $l.Length }
    } catch {
        return $null
    }
}

# Parses a GetResponse expecting an OCTET STRING of exactly 6 bytes (a MAC).
function Parse-SnmpMacResponse {
    param([byte[]]$Data)
    $v = Find-SnmpValuePosition $Data
    if (-not $v) { return $null }
    if ($v.Tag -ne 0x04) { return $null }      # Not an OCTET STRING (probably noSuchObject)
    if ($v.Length -ne 6) { return $null }
    $hex = for ($i = 0; $i -lt 6; $i++) { '{0:X2}' -f $Data[$v.Offset + $i] }
    return ($hex -join ':')
}

# Parses a GetResponse expecting an OCTET STRING (any length, returned as text).
function Parse-SnmpStringResponse {
    param([byte[]]$Data)
    $v = Find-SnmpValuePosition $Data
    if (-not $v) { return $null }
    if ($v.Tag -ne 0x04) { return $null }
    if ($v.Length -le 0) { return $null }
    $bytes = New-Object byte[] $v.Length
    [array]::Copy($Data, $v.Offset, $bytes, 0, $v.Length)
    # Trim nulls and whitespace; collapse internal CR/LF/tabs to spaces
    $s = [System.Text.Encoding]::UTF8.GetString($bytes)
    $s = ($s -replace "[`r`n`t]+", ' ').Trim([char]0, ' ', "`t")
    if ($s.Length -eq 0) { return $null }
    return $s
}

# Sends one SNMP GET. Returns @{ Mac; Description; SentBytes; RecvBytes; Error; ResponseTag }.
function Invoke-SnmpGet {
    param(
        [string]$Target,
        [string]$Community,
        [int[]]$OID,
        [int]$Version,
        [int]$TimeoutMs
    )

    $reqId = Get-Random -Minimum 1 -Maximum 2147483646
    $pkt   = Build-SnmpGetPacket -Community $Community -OID $OID -RequestId $reqId -Version $Version

    $udp    = [System.Net.Sockets.UdpClient]::new()
    $result = @{ SentBytes = $pkt; RecvBytes = $null; Error = $null; ValueTag = $null; ValueOffset = 0; ValueLength = 0 }
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($Target, 161)
        [void]$udp.Send($pkt, $pkt.Length)
        $ep   = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $resp = $udp.Receive([ref]$ep)
        $result.RecvBytes = $resp
        $v = Find-SnmpValuePosition $resp
        if ($v) {
            $result.ValueTag    = $v.Tag
            $result.ValueOffset = $v.Offset
            $result.ValueLength = $v.Length
        }
    } catch [System.Net.Sockets.SocketException] {
        $result.Error = "Socket: $($_.Exception.Message)"
    } catch {
        $result.Error = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    } finally {
        try { $udp.Close() } catch {}
    }
    return $result
}

# Tries v2c then v1, across iface indices 1..4. Returns the first valid MAC.
function Get-PrinterMac {
    param([string]$IP, [string]$Community, [int]$TimeoutMs)
    foreach ($ver in 1, 0) {
        foreach ($idx in 1, 2, 3, 4) {
            $oid = @(1, 3, 6, 1, 2, 1, 2, 2, 1, 6, $idx)
            $r = Invoke-SnmpGet -Target $IP -Community $Community -OID $oid -Version $ver -TimeoutMs $TimeoutMs
            if ($r.RecvBytes -and $r.ValueTag -eq 0x04 -and $r.ValueLength -eq 6) {
                $mac = Parse-SnmpMacResponse $r.RecvBytes
                if ($mac -and $mac -ne '00:00:00:00:00:00') { return $mac }
            }
        }
    }
    return $null
}

# Queries sysDescr.0 (1.3.6.1.2.1.1.1.0). Tries v2c then v1.
function Get-PrinterDescription {
    param([string]$IP, [string]$Community, [int]$TimeoutMs)
    $oid = @(1, 3, 6, 1, 2, 1, 1, 1, 0)
    foreach ($ver in 1, 0) {
        $r = Invoke-SnmpGet -Target $IP -Community $Community -OID $oid -Version $ver -TimeoutMs $TimeoutMs
        if ($r.RecvBytes) {
            $desc = Parse-SnmpStringResponse $r.RecvBytes
            if ($desc) { return $desc }
        }
    }
    return $null
}

# Queries hrDeviceDescr.1 (1.3.6.1.2.1.25.3.2.1.3.1) - Host Resources MIB
# device description. On most printers this is the cleanest model string
# available (e.g. "HP LaserJet Pro 4001dn", "Zebra Technologies ZTC ZD421-203dpi ZPL",
# "Lexmark MS820"). Tries v2c then v1.
function Get-PrinterHrDeviceDescr {
    param([string]$IP, [string]$Community, [int]$TimeoutMs)
    $oid = @(1, 3, 6, 1, 2, 1, 25, 3, 2, 1, 3, 1)
    foreach ($ver in 1, 0) {
        $r = Invoke-SnmpGet -Target $IP -Community $Community -OID $oid -Version $ver -TimeoutMs $TimeoutMs
        if ($r.RecvBytes) {
            $s = Parse-SnmpStringResponse $r.RecvBytes
            if ($s) { return $s }
        }
    }
    return $null
}

# Retrieves the printer serial number, trying vendor-appropriate OIDs:
#   Standard : prtGeneralSerialNumber.1  1.3.6.1.2.1.43.5.1.1.17.1  (Printer-MIB)
#   Zebra    : 1.3.6.1.4.1.10642.1.9.0   (Link-OS / ZebraNet)
#              1.3.6.1.4.1.10642.2.3.27.0 (alternate location on some firmware)
#              1.3.6.1.4.1.683.6.0        (legacy non-Link-OS print servers)
# Zebras generally do NOT implement Printer-MIB serial, so for Make='Zebra'
# the private OIDs are tried first. Failed OIDs on a responding device return
# noSuchObject quickly, so the fallback chain is cheap.
# Returns @{ Serial = <string>; Oid = <dotted string> } or $null.
function Get-PrinterSerialNumber {
    param([string]$IP, [string]$Community, [int]$TimeoutMs, [string]$Make = '')

    $oidStandard    = @{ Oid = @(1,3,6,1,2,1,43,5,1,1,17,1);   Name = '1.3.6.1.2.1.43.5.1.1.17.1' }
    $oidZebraLinkOs = @{ Oid = @(1,3,6,1,4,1,10642,1,9,0);     Name = '1.3.6.1.4.1.10642.1.9.0' }
    $oidZebraAlt    = @{ Oid = @(1,3,6,1,4,1,10642,2,3,27,0);  Name = '1.3.6.1.4.1.10642.2.3.27.0' }
    $oidZebraLegacy = @{ Oid = @(1,3,6,1,4,1,683,6,0);         Name = '1.3.6.1.4.1.683.6.0' }

    if ($Make -match '(?i)zebra') {
        $chain = @($oidZebraLinkOs, $oidZebraAlt, $oidZebraLegacy, $oidStandard)
        $versionOrder = @(0, 1)   # legacy ZebraNet agents are v1-only and TIME OUT on v2c; Link-OS answers v1 fine
    } else {
        $chain = @($oidStandard)
        $versionOrder = @(1, 0)
    }

    foreach ($entry in $chain) {
        foreach ($ver in $versionOrder) {
            $r = Invoke-SnmpGet -Target $IP -Community $Community -OID $entry.Oid -Version $ver -TimeoutMs $TimeoutMs
            if ($r.RecvBytes) {
                $s = Parse-SnmpStringResponse $r.RecvBytes
                if ($s) {
                    $s = $s.Trim()
                    # Reject junk placeholders some firmware returns
                    if ($s -and $s -notmatch '^(?i)(0+|n/?a|none|unknown|x+)$') {
                        return @{ Serial = $s; Oid = $entry.Name }
                    }
                }
            }
        }
    }
    return $null
}

# Legacy-Zebra fallback: queries the serial via SGD (Set-Get-Do) over the raw
# print port, TCP 9100:  ! U1 getvar "device.unique_id"
# On G-series/ZebraNet-era printers this returns the printer serial (their
# SNMP agent only describes the print server, not the printer). The printer
# replies with the value in double quotes; an unknown variable returns "?".
# This is the same mechanism Zebra Setup Utilities uses.
#
# SAFETY: only call this against a CONFIRMED Zebra. Zebras interpret SGD
# commands; any other brand would treat the bytes as a print job.
function Get-ZebraSerialViaSgd {
    param([string]$IP, [int]$TimeoutMs = 3000)
    $client = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $iar = $client.BeginConnect($IP, 9100, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $null }
        $client.EndConnect($iar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs

        $cmd   = "! U1 getvar `"device.unique_id`"`r`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($cmd)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()

        # Response is:  "SERIALVALUE"   (opening quote ... closing quote, no newline)
        $sb       = [System.Text.StringBuilder]::new()
        $buf      = New-Object byte[] 128
        $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
        while ((Get-Date) -lt $deadline) {
            try {
                $n = $stream.Read($buf, 0, $buf.Length)
            } catch { break }                                   # read timeout
            if ($n -le 0) { break }
            [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n))
            $soFar = $sb.ToString()
            if (([regex]::Matches($soFar, '"')).Count -ge 2) { break }
        }
        $raw = $sb.ToString()
        if ($raw -match '"([^"]*)"') {
            $val = $Matches[1].Trim()
            if ($val -and $val -ne '?') { return $val }
        }
    } catch {
    } finally {
        if ($client) { try { $client.Close() } catch {} }
    }
    return $null
}

# HP JetDirect: the IEEE 1284 device ID of the ATTACHED printer, cached by the
# JetDirect from the parallel/USB handshake and exposed at HP enterprise OID
# 1.3.6.1.4.1.11.2.3.9.1.1.7.0 (this is the OID CUPS uses for discovery).
# Pure SNMP - no garbage-page risk - and works on v1-only JetDirect EX boxes.
# Example value: "MFG:HP;CMD:PJL,PCL;MDL:LaserJet 4250;CLS:PRINTER;..."
# Returns the raw device-ID string or $null. Tries v1 first (old EX boxes
# drop v2c requests without answering).
function Get-Hp1284DeviceId {
    param([string]$IP, [string]$Community, [int]$TimeoutMs)
    $oid = @(1, 3, 6, 1, 4, 1, 11, 2, 3, 9, 1, 1, 7, 0)
    foreach ($ver in 0, 1) {
        $r = Invoke-SnmpGet -Target $IP -Community $Community -OID $oid -Version $ver -TimeoutMs $TimeoutMs
        if ($r.RecvBytes) {
            $s = Parse-SnmpStringResponse $r.RecvBytes
            if ($s -and $s -match ':') { return $s }
        }
    }
    return $null
}

# Parses an IEEE 1284 device ID string into Make / Model / Serial.
# Handles both short (MFG/MDL/SN) and long (MANUFACTURER/MODEL/SERIALNUMBER)
# key forms, e.g. "MANUFACTURER:Lexmark International;MODEL:Lexmark C522".
function Parse-Ieee1284DeviceId {
    param([string]$DeviceId)
    $out = @{ Make = ''; Model = ''; Serial = '' }
    if (-not $DeviceId) { return $out }
    foreach ($pair in ($DeviceId -split ';')) {
        if ($pair -match '^\s*([^:]+):(.*)$') {
            $key = $Matches[1].Trim().ToUpperInvariant()
            $val = $Matches[2].Trim()
            if (-not $val) { continue }
            switch ($key) {
                { $_ -in 'MFG', 'MANUFACTURER' }        { if (-not $out.Make)   { $out.Make   = $val } }
                { $_ -in 'MDL', 'MODEL' }               { if (-not $out.Model)  { $out.Model  = $val } }
                { $_ -in 'SN', 'SERN', 'SERIALNUMBER' } { if (-not $out.Serial) { $out.Serial = $val } }
            }
        }
    }
    # Normalize verbose manufacturer strings ("Hewlett-Packard" -> HP etc.)
    if ($out.Make) {
        $norm = Get-MakeFromDescription $out.Make
        if ($norm -and $norm -ne 'Unknown') { $out.Make = $norm }
    }
    # Same vendor-boilerplate cleanup as the hrDeviceDescr path
    if ($out.Model) {
        $m = $out.Model -replace '(?i)^(Zebra(\s+Technologies)?\s+)?(ZTC\s+)?', ''
        $m = $m -replace '(?i)\s+(ZPL|CPCL|EPL2?)\s*$', ''
        $m = $m.Trim()
        if ($m) { $out.Model = $m }
    }
    return $out
}

# PJL probe over TCP 9100:  @PJL INFO ID  (+ INFO CONFIG for a serial, if the
# firmware reports one). Returns the model of the ACTUAL printer - essential
# for external JetDirect EX boxes, whose SNMP agent only describes the box
# itself, not the attached printer. PJL is a readback channel: PJL-capable
# printers (HP LaserJet 4+, Lexmark, Brother, Kyocera, most lasers) answer
# without printing anything.
#
# CAUTION: a pre-PJL device (old dot-matrix, PCL3-only inkjets) would treat
# these bytes as a print job and emit a garbage page. Only call this for makes
# known to speak PJL, and never for Zebras (they have SGD instead).
# Returns @{ Model = <string>; Serial = <string> } or $null.
function Get-PjlPrinterInfo {
    param([string]$IP, [int]$TimeoutMs = 4000)
    $client = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $iar = $client.BeginConnect($IP, 9100, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $null }
        $client.EndConnect($iar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs

        $uel = [string][char]27 + '%-12345X'
        $cmd = "$uel@PJL`r`n@PJL INFO ID`r`n@PJL INFO CONFIG`r`n$uel"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($cmd)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()

        # Each INFO response ends with a form feed (0x0C); read until we've
        # seen both or the deadline passes.
        $sb       = [System.Text.StringBuilder]::new()
        $buf      = New-Object byte[] 512
        $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
        while ((Get-Date) -lt $deadline) {
            try { $n = $stream.Read($buf, 0, $buf.Length) } catch { break }
            if ($n -le 0) { break }
            [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n))
            if (([regex]::Matches($sb.ToString(), "`f")).Count -ge 2) { break }
        }
        $raw = $sb.ToString()
        if (-not $raw) { return $null }

        $model = ''; $serial = ''

        # Model: the line following "@PJL INFO ID", usually quoted.
        if ($raw -match '(?s)@PJL INFO ID\s*[\r\n]+\s*"?([^"\r\n\f]+)') {
            $model = $Matches[1].Trim()
            # Brother-style "HL-L2360D series:84U-F75:Ver.b.26" -> keep model part
            if ($model -match '^([^:]+):') { $model = $Matches[1].Trim() }
        }

        # Serial: some firmware includes it in INFO CONFIG output.
        if ($raw -match '(?i)\bSERIAL\s*(?:NUMBER)?\s*=\s*"?([A-Za-z0-9\-]+)') {
            $serial = $Matches[1].Trim()
        }

        if ($model -or $serial) { return @{ Model = $model; Serial = $serial } }
    } catch {
    } finally {
        if ($client) { try { $client.Close() } catch {} }
    }
    return $null
}

# Best-effort vendor extraction from a sysDescr string.
function Get-MakeFromDescription {
    param([string]$Description)
    if (-not $Description) { return '' }
    $d = $Description
    switch -Regex ($d) {
        '(?i)\b(hewlett[- ]?packard|HP\b|JetDirect|LaserJet|OfficeJet|DesignJet|PageWide)' { return 'HP' }
        '(?i)\b(zebra|ZTC |ZPL|ZQ\d|ZT\d|ZD\d|GK\d|GX\d)'                                  { return 'Zebra' }
        '(?i)\b(lexmark)\b'                                                                 { return 'Lexmark' }
        '(?i)\b(canon|imageRUNNER|iR-?ADV|iR\d|imageCLASS|imagePROGRAF)\b'                  { return 'Canon' }
        '(?i)\b(konica|minolta|bizhub)\b'                                                   { return 'Konica Minolta' }
        '(?i)\b(brother)\b'                                                                 { return 'Brother' }
        '(?i)\b(xerox|workcentre|phaser|versant|altalink|primelink)\b'                      { return 'Xerox' }
        '(?i)\b(ricoh|aficio|savin|lanier|gestetner)\b'                                     { return 'Ricoh' }
        '(?i)\b(kyocera|taskalfa|ecosys)\b'                                                 { return 'Kyocera' }
        '(?i)\b(epson)\b'                                                                   { return 'Epson' }
        '(?i)\b(sharp)\b'                                                                   { return 'Sharp' }
        '(?i)\b(toshiba|e-?studio)\b'                                                       { return 'Toshiba' }
        '(?i)\b(oki|okidata)\b'                                                             { return 'OKI' }
        '(?i)\b(dell)\b'                                                                    { return 'Dell' }
        '(?i)\b(samsung)\b'                                                                 { return 'Samsung' }
        '(?i)\b(datamax|honeywell|intermec)\b'                                              { return 'Honeywell' }
        '(?i)\b(tsc)\b'                                                                     { return 'TSC' }
    }
    return 'Unknown'
}

# Best-effort model extraction from hrDeviceDescr and/or sysDescr.
function Get-ModelFromSnmp {
    param([string]$HrDescr, [string]$SysDescr)

    # HP embeds the model in sysDescr as "...,PID:HP LaserJet Pro 4001dn,..."
    foreach ($s in @($SysDescr, $HrDescr)) {
        if ($s -and $s -match '(?i)\bPID\s*:\s*([^,;]+)') {
            return $Matches[1].Trim()
        }
    }

    if ($HrDescr) {
        $m = $HrDescr.Trim()
        # Strip vendor boilerplate; keep the model core.
        # Handles "Zebra Technologies ZTC ZD421-203dpi ZPL", "Zebra Technologies ZT410", "ZTC GK420d"
        $m = $m -replace '(?i)^(Zebra(\s+Technologies)?\s+)?(ZTC\s+)?', ''
        $m = $m -replace '(?i)\s+(ZPL|CPCL|EPL2?)\s*$', ''           # trailing language tag
        $m = $m -replace '(?i)\s*[,;]\s*(firmware|fw|version|ver\.?|v\d).*$', ''
        $m = $m.Trim()
        # Legacy ZebraNet units report a useless generic "Zebra Printer" - reject
        # so the queue-name / driver fallbacks can supply the real model.
        if ($m -and $m -notmatch '^(?i)(printer|print\s*server|network\s*printer)$') { return $m }
    }

    if ($SysDescr) {
        # Zebra sysDescr: "ZTC ZD421-203dpi ZPL" or "Zebra Technologies ZT410-203dpi / internal wired"
        if ($SysDescr -match '(?i)\bZTC\s+([A-Z0-9][A-Za-z0-9\-\+]*)') { return $Matches[1] }
        if ($SysDescr -match '(?i)\bZebra\s+Technologies\s+([A-Z0-9][A-Za-z0-9\-\+]*)') { return $Matches[1] }
        # Lexmark sysDescr: "Lexmark MS631dw version ..."
        if ($SysDescr -match '(?i)^\s*Lexmark\s+([A-Z]{1,3}\d{3,4}[a-z]*)') { return "Lexmark $($Matches[1])" }
        # Epson sysDescr: "EPSON Built-in ... ET-5850 ..."
        if ($SysDescr -match '(?i)\b((?:ET|WF|XP|L)-\d{3,5}[A-Za-z]*)') { return "EPSON $($Matches[1])" }
    }

    return ''
}
'@

# Activate the SNMP code in the main session (needed for diagnostic mode)
Invoke-Expression $SnmpCode

# ============================================================================
# Diagnostic mode
# ============================================================================
if ($PSCmdlet.ParameterSetName -eq 'Diagnose') {
    Write-Host ""
    Write-Host "=== SNMP Diagnostic against $TestIP ===" -ForegroundColor Cyan
    Write-Host "Community: $SnmpCommunity"
    Write-Host ""

    Write-Host "--- Step 1: Ping ---" -ForegroundColor Yellow
    try {
        $reply = ([System.Net.NetworkInformation.Ping]::new()).Send($TestIP, $PingTimeoutMs)
        Write-Host "  Status: $($reply.Status)  RTT: $($reply.RoundtripTime) ms"
        if ($reply.Status -ne 'Success') {
            Write-Host "  Host did not answer ping. Aborting." -ForegroundColor Red
            return
        }
    } catch {
        Write-Host "  Ping error: $_" -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "--- Step 2: MAC discovery (ifPhysAddress 1..4, v2c then v1) ---" -ForegroundColor Yellow
    $mac = Get-PrinterMac -IP $TestIP -Community $SnmpCommunity -TimeoutMs ($SnmpTimeoutMs * 2)
    if ($mac) {
        Write-Host "  MAC: $mac" -ForegroundColor Green
    } else {
        Write-Host "  No MAC returned." -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "--- Step 3: sysDescr.0 (1.3.6.1.2.1.1.1.0) ---" -ForegroundColor Yellow
    $oidSysDescr = @(1, 3, 6, 1, 2, 1, 1, 1, 0)
    $sysDescr = $null
    foreach ($ver in 1, 0) {
        $verName = if ($ver -eq 1) { 'SNMPv2c' } else { 'SNMPv1' }
        Write-Host ""
        Write-Host "  $verName attempt:" -ForegroundColor Yellow
        $r = Invoke-SnmpGet -Target $TestIP -Community $SnmpCommunity -OID $oidSysDescr -Version $ver -TimeoutMs ($SnmpTimeoutMs * 2)
        Write-Host "    Sent ($($r.SentBytes.Length) bytes): $((($r.SentBytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' '))"
        if ($r.Error) {
            Write-Host "    Error: $($r.Error)" -ForegroundColor Red
            continue
        }
        if ($r.RecvBytes) {
            Write-Host "    Recv ($($r.RecvBytes.Length) bytes): $((($r.RecvBytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' '))"
            $desc = Parse-SnmpStringResponse $r.RecvBytes
            if ($desc) {
                $sysDescr = $desc
                Write-Host "    Description: $desc" -ForegroundColor Green
                break
            } else {
                Write-Host "    Response received but description not parsed." -ForegroundColor Yellow
            }
        }
    }
    if (-not $sysDescr) {
        Write-Host ""
        Write-Host "FAILURE - this printer did not return sysDescr." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "--- Step 4: hrDeviceDescr.1 (1.3.6.1.2.1.25.3.2.1.3.1) ---" -ForegroundColor Yellow
    $hrDescr = Get-PrinterHrDeviceDescr -IP $TestIP -Community $SnmpCommunity -TimeoutMs ($SnmpTimeoutMs * 2)
    if ($hrDescr) {
        Write-Host "  hrDeviceDescr: $hrDescr" -ForegroundColor Green
    } else {
        Write-Host "  No hrDeviceDescr returned (Model will fall back to sysDescr / queue name)." -ForegroundColor Yellow
    }

    $make  = Get-MakeFromDescription $sysDescr
    $model = Get-ModelFromSnmp -HrDescr $hrDescr -SysDescr $sysDescr
    $serial = $null

    if ($make -eq 'HP' -and -not $model) {
        Write-Host ""
        Write-Host "--- Step 5: JetDirect 1284 device ID (SNMP 1.3.6.1.4.1.11.2.3.9.1.1.7.0) ---" -ForegroundColor Yellow
        $devId = Get-Hp1284DeviceId -IP $TestIP -Community $SnmpCommunity -TimeoutMs ($SnmpTimeoutMs * 2)
        if ($devId) {
            Write-Host "  Raw device ID: $devId"
            $p = Parse-Ieee1284DeviceId $devId
            if ($p.Model)  { Write-Host "  Model : $($p.Model)  (via 1284 device ID)" -ForegroundColor Green; if (-not $model)  { $model  = $p.Model } }
            if ($p.Serial) { Write-Host "  Serial: $($p.Serial)  (via 1284 device ID)" -ForegroundColor Green; $serial = $p.Serial }
            if ($p.Make -and $p.Make -ne 'Unknown' -and $p.Make -ne $make) {
                Write-Host "  Make corrected: $make -> $($p.Make) (attached printer differs from JetDirect box)" -ForegroundColor Green
                $make = $p.Make
            }
        } else {
            Write-Host "  No 1284 device ID (very old ROM, or attached printer off/unidirectional)." -ForegroundColor Yellow
        }
    }

    if (-not $serial) {
        Write-Host ""
        Write-Host "--- Step 6: Serial number (vendor-aware OID chain) ---" -ForegroundColor Yellow
        $serialResult = Get-PrinterSerialNumber -IP $TestIP -Community $SnmpCommunity -TimeoutMs ($SnmpTimeoutMs * 2) -Make $make
        if ($serialResult) {
            $serial = $serialResult.Serial
            Write-Host "  Serial: $serial  (from OID $($serialResult.Oid))" -ForegroundColor Green
        } else {
            Write-Host "  No serial number returned from any known SNMP OID." -ForegroundColor Yellow
            if ($make -eq 'Zebra') {
                Write-Host ""
                Write-Host "--- Step 6b: Zebra SGD fallback (TCP 9100, getvar device.unique_id) ---" -ForegroundColor Yellow
                $serial = Get-ZebraSerialViaSgd -IP $TestIP -TimeoutMs ($SnmpTimeoutMs * 2)
                if ($serial) {
                    Write-Host "  Serial: $serial  (via SGD over port 9100)" -ForegroundColor Green
                } else {
                    Write-Host "  No response to SGD getvar either." -ForegroundColor Yellow
                }
            }
        }
    }

    if ((-not $model -or -not $serial) -and $make -match '^(HP|Lexmark|Brother|Kyocera|Xerox|Ricoh|Canon)$') {
        Write-Host ""
        Write-Host "--- Step 7: PJL probe (TCP 9100, @PJL INFO ID) ---" -ForegroundColor Yellow
        Write-Host "  Note: PJL-capable printers answer without printing; a pre-PJL device" -ForegroundColor DarkYellow
        Write-Host "  attached to an external JetDirect box may print this probe as a page." -ForegroundColor DarkYellow
        $pjl = Get-PjlPrinterInfo -IP $TestIP -TimeoutMs ($SnmpTimeoutMs * 2)
        if ($pjl) {
            if ($pjl.Model)  { Write-Host "  Model : $($pjl.Model)  (via PJL)" -ForegroundColor Green; if (-not $model)  { $model  = $pjl.Model } }
            if ($pjl.Serial) { Write-Host "  Serial: $($pjl.Serial)  (via PJL INFO CONFIG)" -ForegroundColor Green; if (-not $serial) { $serial = $pjl.Serial } }
            if (-not $pjl.Model -and -not $pjl.Serial) { Write-Host "  PJL responded but no usable fields parsed." -ForegroundColor Yellow }
        } else {
            Write-Host "  No PJL response (port closed, timeout, or non-PJL device)." -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "  Make  : $make"  -ForegroundColor Green
    Write-Host "  Model : $(if ($model) { $model } else { '(not resolved)' })" -ForegroundColor Green
    Write-Host "  Serial: $(if ($serial) { $serial } else { '(not resolved)' })" -ForegroundColor Green
    return
}

# ============================================================================
# Scan mode - input format detection and prerequisites
# ============================================================================
$inputExt  = [IO.Path]::GetExtension($InputPath).ToLowerInvariant()
$inputIsCsv = ($inputExt -eq '.csv')

if (-not $OutputPath) {
    $dir  = Split-Path -Parent $InputPath
    if (-not $dir) { $dir = '.' }
    $base = [IO.Path]::GetFileNameWithoutExtension($InputPath)
    # Match the input format by default: CSV in -> CSV out (no module install
    # needed on a server), xlsx in -> xlsx out.
    $OutputPath = Join-Path $dir "${base}_with_MAC${inputExt}"
}
$outputIsCsv = ([IO.Path]::GetExtension($OutputPath).ToLowerInvariant() -eq '.csv')

# ImportExcel is only needed if either side is xlsx
if (-not $inputIsCsv -or -not $outputIsCsv) {
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-Host "Installing ImportExcel module (CurrentUser scope)..." -ForegroundColor Yellow
        if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
        }
        Install-Module -Name ImportExcel -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module ImportExcel -ErrorAction Stop
}

# ============================================================================
# Read input
# ============================================================================
Write-Host "Reading $InputPath..." -ForegroundColor Cyan
if ($inputIsCsv) {
    $rows = @(Import-Csv -Path $InputPath)
} else {
    $rows = @(Import-Excel -Path $InputPath)
}
if (-not $rows -or $rows.Count -eq 0) { throw "No data rows found in $InputPath." }

$colNames     = $rows[0].PSObject.Properties.Name
$ipColumn     = $colNames | Where-Object { $_ -match '(?i)^ip' }             | Select-Object -First 1
$nameColumn   = $colNames | Where-Object { $_ -match '(?i)name' -and $_ -notmatch '(?i)server|driver' } | Select-Object -First 1
$statusColumn = $colNames | Where-Object { $_ -match '(?i)queue\s*status' }  | Select-Object -First 1
$driverColumn = $colNames | Where-Object { $_ -match '(?i)^driver\s*name' }  | Select-Object -First 1
$serverColumn = $colNames | Where-Object { $_ -match '(?i)server' }          | Select-Object -First 1
if (-not $ipColumn -and -not $nameColumn) { $nameColumn = $colNames[0] }

# ============================================================================
# Resolve an IP for every row
#   - IP column present  -> use it (original xlsx workflow)
#   - No IP column (Print Management CSV export) -> resolve from the print
#     server's port configuration, then DNS fallback on the queue base name
# ============================================================================
function Resolve-ToIPv4 {
    param([string]$HostOrIp)
    if (-not $HostOrIp) { return $null }
    if ($HostOrIp -match '^\d{1,3}(\.\d{1,3}){3}$') { return $HostOrIp }
    try {
        $a = [System.Net.Dns]::GetHostAddresses($HostOrIp) |
             Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
             Select-Object -First 1
        if ($a) { return $a.IPAddressToString }
    } catch {}
    return $null
}

if ($ipColumn) {
    Write-Host "IP column '$ipColumn' found - using IPs from the input file." -ForegroundColor Cyan
    foreach ($row in $rows) {
        Add-Member -InputObject $row -NotePropertyName '_ResolvedIP' -NotePropertyValue $row.$ipColumn -Force
        Add-Member -InputObject $row -NotePropertyName '_IpSource'   -NotePropertyValue 'File' -Force
    }
} else {
    Write-Host "No IP column in the input - resolving IPs from print server port configuration..." -ForegroundColor Cyan

    # Determine which print server to query
    if (-not $PrintServer -and $serverColumn) {
        $rawServer = ($rows | Where-Object { $_.$serverColumn } | Select-Object -First 1).$serverColumn
        if ($rawServer -match '^([^\s(]+)') { $PrintServer = $Matches[1] }   # "BUSCMFFPS001VM (local)" -> BUSCMFFPS001VM
    }

    # Build queue name -> IP map from Get-Printer / Get-PrinterPort
    $queueToIp = @{}
    try {
        $cimParams = @{ ErrorAction = 'Stop' }
        if ($PrintServer -and $PrintServer -notmatch "^(?i)$([regex]::Escape($env:COMPUTERNAME))$") {
            $cimParams.ComputerName = $PrintServer
            Write-Host "Querying remote print server '$PrintServer' via WinRM..." -ForegroundColor Cyan
        } else {
            Write-Host "Querying local print spooler ($env:COMPUTERNAME)..." -ForegroundColor Cyan
        }

        $printers = Get-Printer @cimParams
        $ports    = Get-PrinterPort @cimParams

        # Port name -> host address. Standard TCP/IP ports expose
        # PrinterHostAddress; some ports are simply named after the IP/host.
        $portToAddr = @{}
        foreach ($p in $ports) {
            $addr = $null
            if ($p.PSObject.Properties['PrinterHostAddress'] -and $p.PrinterHostAddress) {
                $addr = $p.PrinterHostAddress
            } elseif ($p.Name -match '^\d{1,3}(\.\d{1,3}){3}') {
                $addr = ($p.Name -split '[:_]')[0]
            }
            if ($addr) { $portToAddr[$p.Name] = $addr }
        }

        foreach ($pr in $printers) {
            if ($pr.PortName -and $portToAddr.ContainsKey($pr.PortName)) {
                $queueToIp[$pr.Name] = $portToAddr[$pr.PortName]
            }
        }
        Write-Host "Port map built: $($queueToIp.Count) queue(s) mapped to a host address." -ForegroundColor Cyan
    } catch {
        Write-Warning "Could not query print server port configuration: $_"
        Write-Warning "Falling back to DNS resolution of queue names only."
    }

    $viaPort = 0; $viaDns = 0; $unresolved = 0
    foreach ($row in $rows) {
        $qName = if ($nameColumn) { [string]$row.$nameColumn } else { '' }
        $ip = $null; $src = ''

        if ($qName -and $queueToIp.ContainsKey($qName)) {
            $ip = Resolve-ToIPv4 $queueToIp[$qName]
            if ($ip) { $src = 'Port'; $viaPort++ }
        }
        if (-not $ip -and $qName) {
            # Strip the model hint - "BUSCARPRT001 (ZT411)" -> "BUSCARPRT001"
            $baseName = ($qName -replace '\s*\([^)]*\)\s*$', '').Trim()
            if ($baseName) {
                $ip = Resolve-ToIPv4 $baseName
                if ($ip) { $src = 'DNS'; $viaDns++ }
            }
        }
        if (-not $ip) { $unresolved++ }

        Add-Member -InputObject $row -NotePropertyName '_ResolvedIP' -NotePropertyValue $ip  -Force
        Add-Member -InputObject $row -NotePropertyName '_IpSource'   -NotePropertyValue $src -Force
    }
    Write-Host ("IP resolution: {0} via port config, {1} via DNS, {2} unresolved." -f $viaPort, $viaDns, $unresolved) -ForegroundColor Cyan
}

$entries = @($rows | Where-Object { $_._ResolvedIP -match '^\d{1,3}(\.\d{1,3}){3}$' })
Write-Host "Found $($entries.Count) printer(s) with valid IP addresses." -ForegroundColor Cyan
if ($entries.Count -eq 0) { throw "No printers could be resolved to an IP address. Nothing to scan." }

# Deduplicate IPs so each device is only queried once (multiple queues can
# share one physical printer/port).
$uniqueIps = $entries | ForEach-Object { $_._ResolvedIP } | Sort-Object -Unique
Write-Host "$($uniqueIps.Count) unique IP(s) to scan." -ForegroundColor Cyan

# ============================================================================
# Worker scriptblock
# ============================================================================
$workerScript = {
    param([string]$IP, [string]$Community, [int]$PingTimeout, [int]$SnmpTimeout, [string]$Code, [bool]$UsePjl)

    Invoke-Expression $Code

    $r = [pscustomobject]@{
        IP          = $IP
        Online      = $false
        MAC         = ''
        Method      = ''
        Description = ''
        Make        = ''
        Model       = ''
        ModelSource = ''
        Serial      = ''
    }

    # 1. Ping
    try {
        $reply = ([System.Net.NetworkInformation.Ping]::new()).Send($IP, $PingTimeout)
        if ($reply.Status -ne [System.Net.NetworkInformation.IPStatus]::Success) { return $r }
        $r.Online = $true
    } catch {
        return $r
    }

    # 2. SNMP MAC
    $mac = Get-PrinterMac -IP $IP -Community $Community -TimeoutMs $SnmpTimeout
    if ($mac) {
        $r.MAC    = $mac
        $r.Method = 'SNMP'
    } else {
        # 3. ARP fallback
        try {
            $n = Get-NetNeighbor -IPAddress $IP -ErrorAction SilentlyContinue |
                 Where-Object {
                     $_.LinkLayerAddress -and
                     ($_.LinkLayerAddress -notmatch '^(00-){5}00$') -and
                     ($_.State -ne 'Unreachable')
                 } |
                 Select-Object -First 1
            if ($n) {
                $r.MAC    = ($n.LinkLayerAddress -replace '-', ':')
                $r.Method = 'ARP'
            }
        } catch {}
    }

    # 4. SNMP sysDescr - try regardless of MAC source (some devices answer
    # sysDescr but not ifPhysAddress, so the MAC came from ARP but description
    # may still be available)
    $desc = Get-PrinterDescription -IP $IP -Community $Community -TimeoutMs $SnmpTimeout
    if ($desc) {
        $r.Description = $desc
        $r.Make        = Get-MakeFromDescription $desc
    }

    # 5. SNMP hrDeviceDescr + serial number - only attempt if the device is
    # answering SNMP at all (skip the extra timeout cost on dead/SNMP-silent
    # devices).
    if ($desc -or $r.Method -eq 'SNMP') {
        $hrDescr = Get-PrinterHrDeviceDescr -IP $IP -Community $Community -TimeoutMs $SnmpTimeout
        $r.Model = Get-ModelFromSnmp -HrDescr $hrDescr -SysDescr $desc
        if ($r.Model) { $r.ModelSource = 'SNMP' }
        if (-not $r.Make -and $hrDescr) { $r.Make = Get-MakeFromDescription $hrDescr }

        # 5. HP JetDirect 1284 device ID (pure SNMP, cheap): identifies the
        # ACTUAL printer attached to a JetDirect - essential for external
        # JetDirect EX boxes whose own MIB has no printer model. Can also
        # correct the Make (non-HP printers are often attached to HP boxes),
        # so this must run BEFORE the serial lookup, which routes by Make.
        if ($r.Make -eq 'HP' -and (-not $r.Model -or -not $r.Serial)) {
            $devId = Get-Hp1284DeviceId -IP $IP -Community $Community -TimeoutMs $SnmpTimeout
            if ($devId) {
                $p = Parse-Ieee1284DeviceId $devId
                if (-not $r.Model -and $p.Model) {
                    $r.Model = $p.Model
                    $r.ModelSource = '1284ID'
                }
                if (-not $r.Serial -and $p.Serial) { $r.Serial = $p.Serial }
                if ($p.Make -and $p.Make -ne 'Unknown') { $r.Make = $p.Make }
            }
        }

        # 6. Serial number, routed by (possibly corrected) Make.
        if (-not $r.Serial) {
            $serial = Get-PrinterSerialNumber -IP $IP -Community $Community -TimeoutMs $SnmpTimeout -Make $r.Make
            if ($serial) {
                $r.Serial = $serial.Serial
            } elseif ($r.Make -eq 'Zebra') {
                # Legacy ZebraNet units don't expose the printer serial via SNMP
                # at all - fall back to SGD getvar over TCP 9100 (Zebra-only,
                # safe: ZPL firmware interprets or silently ignores SGD).
                $sgd = Get-ZebraSerialViaSgd -IP $IP -TimeoutMs $SnmpTimeout
                if ($sgd) { $r.Serial = $sgd }
            }
        }

        # 7. Optional PJL probe (-PjlFallback): recovers the ACTUAL printer's
        # model/serial behind external JetDirect EX boxes, whose SNMP agent
        # only describes the box. Restricted to PJL-native laser vendors;
        # never Zebra (SGD covers those) and never unknown makes, since
        # pre-PJL hardware would print the probe as a garbage page.
        if ($UsePjl -and (-not $r.Model -or -not $r.Serial) -and
            $r.Make -match '^(HP|Lexmark|Brother|Kyocera|Xerox|Ricoh|Canon)$') {
            $pjl = Get-PjlPrinterInfo -IP $IP -TimeoutMs ($SnmpTimeout * 2)
            if ($pjl) {
                if (-not $r.Model -and $pjl.Model) {
                    $r.Model = $pjl.Model
                    $r.ModelSource = 'PJL'
                }
                if (-not $r.Serial -and $pjl.Serial) { $r.Serial = $pjl.Serial }
            }
        }
    }

    return $r
}

# ============================================================================
# Parallel scan (one job per unique IP)
# ============================================================================
Write-Host "Starting parallel scan (throttle=$ThrottleLimit, community=$SnmpCommunity)..." -ForegroundColor Cyan

$pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
$pool.Open()
$jobs = New-Object System.Collections.ArrayList

foreach ($ip in $uniqueIps) {
    $ps = [powershell]::Create()
    [void]$ps.AddScript($workerScript)
    [void]$ps.AddArgument($ip)
    [void]$ps.AddArgument($SnmpCommunity)
    [void]$ps.AddArgument($PingTimeoutMs)
    [void]$ps.AddArgument($SnmpTimeoutMs)
    [void]$ps.AddArgument($SnmpCode)
    [void]$ps.AddArgument($PjlFallback.IsPresent)
    $ps.RunspacePool = $pool
    [void]$jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke(); IP = $ip })
}

$resultsByIp = @{}
$total       = $jobs.Count
$completed   = 0
$start       = Get-Date

while ($jobs.Count -gt 0) {
    for ($i = $jobs.Count - 1; $i -ge 0; $i--) {
        if ($jobs[$i].Handle.IsCompleted) {
            try {
                $out = $jobs[$i].PS.EndInvoke($jobs[$i].Handle)
                if ($out -and $out.Count -gt 0) { $resultsByIp[$jobs[$i].IP] = $out[0] }
            } catch {
                Write-Verbose "Worker error for $($jobs[$i].IP): $_"
            }
            $jobs[$i].PS.Dispose()
            $jobs.RemoveAt($i)
            $completed++
            $pct     = [math]::Round(($completed / $total) * 100, 1)
            $elapsed = (Get-Date) - $start
            $rate    = if ($elapsed.TotalSeconds -gt 0) { [math]::Round($completed / $elapsed.TotalSeconds, 1) } else { 0 }
            Write-Progress -Activity "Scanning printers" -Status "$completed / $total ($pct%) - $rate/sec" -PercentComplete $pct
        }
    }
    if ($jobs.Count -gt 0) { Start-Sleep -Milliseconds 100 }
}

Write-Progress -Activity "Scanning printers" -Completed
$pool.Close()
$pool.Dispose()

# ============================================================================
# Model fallbacks from CSV metadata (queue-name hint, then driver name)
# ============================================================================
function Get-ModelHintFromQueueName {
    param([string]$QueueName)
    if ($QueueName -and $QueueName -match '\(([^)]+)\)\s*$') { return $Matches[1].Trim() }
    return ''
}

function Get-ModelFromDriverName {
    param([string]$DriverName)
    if (-not $DriverName) { return '' }
    # Universal/generic drivers carry no model information
    if ($DriverName -match '(?i)universal|generic|global|text\s*only') { return '' }
    $m = $DriverName.Trim()
    $m = $m -replace '(?i)^ZDesigner\s+', ''                 # "ZDesigner ZD421-203dpi ZPL" -> "ZD421-203dpi ZPL"
    $m = $m -replace '(?i)\s+(ZPL|CPCL|EPL2?)\s*$', ''
    $m = $m -replace '(?i)\s*\((ZPL|CPCL|EPL2?)\)\s*$', ''
    $m = $m -replace '(?i)\s+Series(\s+XL)?\s*$', ''         # "Lexmark MS820 Series XL" -> "Lexmark MS820"
    $m = $m -replace '(?i)\s+(PS|PCL\s?\d?|XPS)\s*$', ''
    return $m.Trim()
}

# ============================================================================
# Build output and write (one row per input queue; shared IPs reuse the same
# scan result)
# ============================================================================
$output = foreach ($row in $rows) {
    $ip    = $row._ResolvedIP
    $r     = if ($ip) { $resultsByIp[$ip] } else { $null }
    $qName = if ($nameColumn) { [string]$row.$nameColumn } else { '' }
    $drv   = if ($driverColumn) { [string]$row.$driverColumn } else { '' }

    # Model: SNMP/PJL first, then queue-name hint, then driver name
    $model       = if ($r -and $r.Model) { $r.Model } else { '' }
    $modelSource = if ($model) { if ($r.ModelSource) { $r.ModelSource } else { 'SNMP' } } else { '' }
    if (-not $model) {
        $model = Get-ModelHintFromQueueName $qName
        if ($model) { $modelSource = 'QueueName' }
    }
    if (-not $model) {
        $model = Get-ModelFromDriverName $drv
        if ($model) { $modelSource = 'Driver' }
    }

    # Make: SNMP first, then infer from whatever model string we ended up with
    $make = if ($r -and $r.Make) { $r.Make } else { '' }
    if ((-not $make -or $make -eq 'Unknown') -and $model) {
        $inferred = Get-MakeFromDescription "$model $drv"
        if ($inferred -and $inferred -ne 'Unknown') { $make = $inferred }
    }

    [pscustomobject]@{
        'Printer Name' = $qName
        'Queue Status' = if ($statusColumn) { $row.$statusColumn } else { '' }
        'IP Address'   = if ($ip) { $ip } else { '' }
        'Subnet'       = if ($ip -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') { $Matches[1] } else { '' }
        'IP Source'    = $row._IpSource
        'Status'       = if (-not $ip) { 'No IP' } elseif ($r) { if ($r.Online) { 'Online' } else { 'Offline' } } else { 'Skipped' }
        'MAC Address'  = if ($r) { $r.MAC } else { '' }
        'Method'       = if ($r) { $r.Method } else { '' }
        'Make'         = $make
        'Model'        = $model
        'Model Source' = $modelSource
        'Serial Number'= if ($r) { $r.Serial } else { '' }
        'Description'  = if ($r) { $r.Description } else { '' }
        'Driver Name'  = $drv
    }
}

if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }
if ($outputIsCsv) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
} else {
    $output | Export-Excel -Path $OutputPath -WorksheetName 'Printers' `
                -AutoSize -BoldTopRow -FreezeTopRow -TableStyle Medium2
}

# ============================================================================
# Summary
# ============================================================================
$onlineCount  = @($output | Where-Object { $_.Status        -eq 'Online' }).Count
$offlineCount = @($output | Where-Object { $_.Status        -eq 'Offline' }).Count
$noIpCount    = @($output | Where-Object { $_.Status        -eq 'No IP' }).Count
$macFound     = @($output | Where-Object { $_.'MAC Address' -ne '' }).Count
$descFound    = @($output | Where-Object { $_.Description   -ne '' }).Count
$modelFound   = @($output | Where-Object { $_.Model         -ne '' }).Count
$modelSnmp    = @($output | Where-Object { $_.'Model Source' -eq 'SNMP' }).Count
$serialFound  = @($output | Where-Object { $_.'Serial Number' -ne '' }).Count
$bySnmp       = @($output | Where-Object { $_.Method        -eq 'SNMP' }).Count
$byArp        = @($output | Where-Object { $_.Method        -eq 'ARP' }).Count
$makeBreakdown  = $output | Where-Object { $_.Make   -ne '' } | Group-Object Make   | Sort-Object Count -Descending
$modelBreakdown = $output | Where-Object { $_.Model  -ne '' } | Group-Object Model  | Sort-Object Count -Descending
$subnetBreakdown = $output | Where-Object { $_.Subnet -ne '' } | Group-Object Subnet | Sort-Object Count -Descending

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Green
Write-Host ("  Total queues        : {0}" -f $output.Count)
Write-Host ("  Unique IPs scanned  : {0}" -f $uniqueIps.Count)
Write-Host ("  Online              : {0}" -f $onlineCount)
Write-Host ("  Offline             : {0}" -f $offlineCount)
if ($noIpCount) {
    Write-Host ("  No IP resolved      : {0}" -f $noIpCount) -ForegroundColor Yellow
}
Write-Host ("  MACs resolved       : {0}  (SNMP: {1}, ARP: {2})" -f $macFound, $bySnmp, $byArp)
Write-Host ("  Descriptions found  : {0}" -f $descFound)
Write-Host ("  Models resolved     : {0}  (via SNMP: {1})" -f $modelFound, $modelSnmp)
Write-Host ("  Serials retrieved   : {0}" -f $serialFound)
if ($makeBreakdown) {
    Write-Host ""
    Write-Host "  Make breakdown:" -ForegroundColor Cyan
    foreach ($g in $makeBreakdown) {
        Write-Host ("    {0,-20} {1}" -f $g.Name, $g.Count)
    }
}
if ($modelBreakdown) {
    Write-Host ""
    Write-Host "  Model breakdown (top 15):" -ForegroundColor Cyan
    foreach ($g in ($modelBreakdown | Select-Object -First 15)) {
        Write-Host ("    {0,-30} {1}" -f $g.Name, $g.Count)
    }
}
if ($subnetBreakdown) {
    Write-Host ""
    Write-Host "  Subnet breakdown:" -ForegroundColor Cyan
    foreach ($g in $subnetBreakdown) {
        Write-Host ("    {0,-20} {1}" -f "$($g.Name).0/24", $g.Count)
    }
}
Write-Host ""
Write-Host "Output written to: $OutputPath" -ForegroundColor Green