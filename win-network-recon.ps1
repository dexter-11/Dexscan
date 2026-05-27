<#
.SYNOPSIS
    Light-Recon.ps1 — Fast Internal Network Scanner for Windows
.DESCRIPTION
    Tunnel-friendly port scanner designed to run from a compromised Windows host.
    Uses TcpClient async connections (not Test-NetConnection) for speed.

    Phase 0: Input parsing + alive check
    Phase 1: OS fingerprint (TTL-based)
    Phase 2: Hostname extraction (DNS PTR, NetBIOS, SMB, SSL CN)
    Phase 3: Port scan with fallback service labels
.PARAMETER Targets
    One or more IPs, CIDR ranges (10.10.10.0/24), or ranges (10.10.10.1-50)
.PARAMETER InputFile
    Path to a file containing one IP per line
.PARAMETER Timeout
    TCP connect timeout in milliseconds (default: 1000)
.PARAMETER OutputFile
    Save results to a file (plain text, no ANSI)
.EXAMPLE
    .\Light-Recon.ps1 -Targets 10.10.10.0/24
    .\Light-Recon.ps1 -Targets 10.10.10.1-50 -Timeout 1500
    .\Light-Recon.ps1 -InputFile .\targets.txt -OutputFile results.txt
    .\Light-Recon.ps1 -Targets 10.10.10.5,10.10.10.10,10.10.10.20
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string[]]$Targets,

    [string]$InputFile,

    [int]$Timeout = 1000,

    [string]$OutputFile
)

# ============================================================================
# Globals
# ============================================================================
$Script:HostsCompleted = 0
$Script:TotalHosts     = 0
$Script:ScanStart      = Get-Date
$Script:NoHostnameList = @()
$Script:Results        = @()
$Script:ADHostnameMap  = @{}    # Pre-populated from Get-ADComputer if available
$Script:ADAvailable    = $false


# ============================================================================
# Output Helpers
# ============================================================================
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
    if ($Script:OutputFile) {
        $clean = $Message -replace '\e\[[0-9;]*m', ''
        Add-Content -Path $Script:OutputFile -Value $clean -ErrorAction SilentlyContinue
    }
}

function Write-Banner {
    Write-Log ""
    Write-Log "  ╔═══════════════════════════════════════════════════════════╗" "Cyan"
    Write-Log "  ║         Light-Recon.ps1 — Windows Network Scanner        ║" "Cyan"
    Write-Log "  ╚═══════════════════════════════════════════════════════════╝" "Cyan"
    Write-Log ""
}

# ============================================================================
# IP Range Expansion
# ============================================================================
function Expand-IPRange {
    param([string[]]$InputTargets)

    $ipList = @()

    foreach ($entry in $InputTargets) {
        $entry = $entry.Trim()
        if ([string]::IsNullOrWhiteSpace($entry) -or $entry.StartsWith("#")) { continue }

        # CIDR: 10.10.10.0/24
        if ($entry -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
            $network  = [System.Net.IPAddress]::Parse($Matches[1])
            $cidr     = [int]$Matches[2]
            $netBytes = $network.GetAddressBytes()
            [Array]::Reverse($netBytes)
            $netInt   = [BitConverter]::ToUInt32($netBytes, 0)
            $hostBits = 32 - $cidr
            $numHosts = [Math]::Pow(2, $hostBits) - 2  # exclude network + broadcast

            for ($i = 1; $i -le $numHosts; $i++) {
                $ipInt   = $netInt + $i
                $ipBytes = [BitConverter]::GetBytes([UInt32]$ipInt)
                [Array]::Reverse($ipBytes)
                $ipList += ([System.Net.IPAddress]::new($ipBytes)).ToString()
            }
        }
        # Range: 10.10.10.1-50
        elseif ($entry -match '^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$') {
            $base  = $Matches[1]
            $start = [int]$Matches[2]
            $end   = [int]$Matches[3]
            for ($i = $start; $i -le $end; $i++) {
                $ipList += "$base.$i"
            }
        }
        # Comma-separated or single IP
        else {
            $entry -split ',' | ForEach-Object {
                $ip = $_.Trim()
                if ($ip -match '^\d+\.\d+\.\d+\.\d+$') {
                    $ipList += $ip
                }
            }
        }
    }

    return $ipList | Select-Object -Unique
}

# ============================================================================
# Fast TCP Port Test (async with timeout)
# ============================================================================
function Test-TcpPort {
    param(
        [string]$IP,
        [int]$Port,
        [int]$TimeoutMs = 1000
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $task   = $client.ConnectAsync($IP, $Port)
        $waited = $task.Wait($TimeoutMs)

        if ($waited -and $client.Connected) {
            $client.Close()
            $client.Dispose()
            return $true
        }
        $client.Close()
        $client.Dispose()
        return $false
    }
    catch {
        try { $client.Close(); $client.Dispose() } catch {}
        return $false
    }
}

# ============================================================================
# Port Lists & Labels
# ============================================================================
$WinPorts = @(
    21, 53, 80, 88, 135, 139, 389, 443, 445, 464, 593, 636,
    1433, 3268, 3269, 3389,
    5985, 5986,
    8080, 8443, 9389,
    47001
)

$LinPorts = @(
    21, 22, 25, 53, 80, 110, 111, 139, 143, 389, 443, 445,
    993, 995, 1099, 2049,
    3000, 3306, 3389,
    5432, 5601, 5900, 5901,
    6379, 8000, 8080, 8443, 8888,
    9000, 9001, 9090, 9200, 9443,
    10000, 27017
)

$PortLabels = @{
    21    = "FTP"
    22    = "SSH"
    25    = "SMTP"
    53    = "DNS"
    80    = "HTTP"
    88    = "Kerberos"
    110   = "POP3"
    111   = "RPCbind"
    135   = "MSRPC"
    139   = "NetBIOS-SSN"
    143   = "IMAP"
    389   = "LDAP"
    443   = "HTTPS"
    445   = "SMB"
    464   = "Kpasswd"
    593   = "RPC-over-HTTP"
    636   = "LDAPS"
    993   = "IMAPS"
    995   = "POP3S"
    1099  = "Java-RMI"
    1433  = "MSSQL"
    2049  = "NFS"
    3000  = "Grafana/Dev-Web"
    3268  = "LDAP-GC"
    3269  = "LDAPS-GC"
    3306  = "MySQL"
    3389  = "RDP"
    5432  = "PostgreSQL"
    5601  = "Kibana"
    5900  = "VNC"
    5901  = "VNC-1"
    5985  = "WinRM-HTTP"
    5986  = "WinRM-HTTPS"
    6379  = "Redis"
    8000  = "HTTP-Alt"
    8080  = "HTTP-Proxy"
    8443  = "HTTPS-Alt"
    8888  = "HTTP-Alt"
    9000  = "Portainer/SonarQube"
    9001  = "Supervisord"
    9090  = "Prometheus/Web-Admin"
    9200  = "Elasticsearch"
    9389  = "AD-Web-Services"
    9443  = "HTTPS-Alt"
    10000 = "Webmin"
    27017 = "MongoDB"
    47001 = "WinRM"
}

# ============================================================================
# Phase 1: OS Fingerprinting (TTL + port probes)
# ============================================================================
function Get-OSFingerprint {
    param([string]$IP)

    $os = "Unknown"

    # TTL from ping
    try {
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($IP, $Timeout)
        if ($reply.Status -eq 'Success') {
            $ttl = $reply.Options.Ttl
            if ($ttl -le 64)  { $os = "Linux" }
            elseif ($ttl -le 128) { $os = "Windows" }
        }
        $ping.Dispose()
    } catch {}

    # Port-based tiebreaker
    if ($os -eq "Unknown" -or $os -eq "Linux") {
        if (Test-TcpPort -IP $IP -Port 135 -TimeoutMs $Timeout) { $os = "Windows" }
        elseif (Test-TcpPort -IP $IP -Port 5985 -TimeoutMs $Timeout) { $os = "Windows" }
        elseif (Test-TcpPort -IP $IP -Port 88 -TimeoutMs $Timeout) { $os = "Windows" }
    }
    if ($os -eq "Unknown" -or $os -eq "Windows") {
        $ssh = Test-TcpPort -IP $IP -Port 22 -TimeoutMs $Timeout
        $rpc = Test-TcpPort -IP $IP -Port 135 -TimeoutMs $Timeout
        if ($ssh -and (-not $rpc)) { $os = "Linux" }
    }

    return $os
}

# ============================================================================
# Phase 2: Hostname Extraction
# ============================================================================
function Get-HostnameFromTarget {
    param([string]$IP, [string]$OS)

    $hostname = ""
    $method   = ""

    # --- 0. AD Cache (instant — pre-populated from Get-ADComputer) ---
    if ($Script:ADAvailable -and $Script:ADHostnameMap.ContainsKey($IP)) {
        $adEntry  = $Script:ADHostnameMap[$IP]
        if ($adEntry.DNSHostName) {
            $hostname = $adEntry.DNSHostName
        } else {
            $hostname = $adEntry.Name
        }
        $method = "AD-Cache"
        return @{ Hostname = $hostname; Method = $method }
    }

    # --- 1. DNS PTR (Resolve-DnsName with NetBIOS fallback) ---
    try {
        $dns = Resolve-DnsName -Name $IP -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop
        if ($dns.NameHost) {
            $hostname = ($dns.NameHost | Select-Object -First 1).TrimEnd('.')
            $method = "DNS-PTR"
        }
    } catch {}

    # --- 2. .NET reverse DNS ---
    if (-not $hostname) {
        try {
            $entry = [System.Net.Dns]::GetHostEntry($IP)
            if ($entry.HostName -and $entry.HostName -ne $IP) {
                $hostname = $entry.HostName
                $method = "GetHostEntry"
            }
        } catch {}
    }

    # --- 3. NetBIOS via nbtstat (Windows native, no install needed) ---
    if (-not $hostname -and ($OS -eq "Windows" -or $OS -eq "Unknown")) {
        try {
            $nbt = nbtstat -A $IP 2>$null
            $line = $nbt | Where-Object { $_ -match '<00>\s+UNIQUE' } | Select-Object -First 1
            if ($line -match '^\s*(\S+)\s+<00>') {
                $hostname = $Matches[1].Trim()
                $method = "nbtstat"
            }
        } catch {}
    }

    # --- 4. Resolve-DnsName with NetBIOS/LLMNR fallback ---
    if (-not $hostname) {
        try {
            $dns2 = Resolve-DnsName -Name $IP -Type PTR -NetbiosFallback -LlmnrFallback -QuickTimeout -ErrorAction Stop
            if ($dns2.NameHost) {
                $hostname = ($dns2.NameHost | Select-Object -First 1).TrimEnd('.')
                $method = "DNS-NetBIOS-Fallback"
            }
        } catch {}
    }

    # --- 5. SSL Certificate CN (HTTPS ports) ---
    if (-not $hostname) {
        $sslPorts = @(443, 636, 8443, 3389)
        foreach ($sp in $sslPorts) {
            if (Test-TcpPort -IP $IP -Port $sp -TimeoutMs $Timeout) {
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $tcpClient.Connect($IP, $sp)
                    $sslStream = New-Object System.Net.Security.SslStream(
                        $tcpClient.GetStream(), $false,
                        { param($s,$c,$ch,$e) $true }   # Accept any cert
                    )
                    $sslStream.AuthenticateAsClient($IP)
                    $cert = $sslStream.RemoteCertificate
                    if ($cert) {
                        $subject = $cert.Subject
                        if ($subject -match 'CN=([^,]+)') {
                            $cn = $Matches[1].Trim()
                            if ($cn -ne $IP -and -not $cn.StartsWith("*.")) {
                                $hostname = $cn
                                $method = "SSL-CN:$sp"
                            }
                        }
                    }
                    $sslStream.Close()
                    $tcpClient.Close()
                    if ($hostname) { break }
                } catch {
                    try { $tcpClient.Close() } catch {}
                }
            }
        }
    }

    # --- 6. SMB hostname via net view (quick, native) ---
    if (-not $hostname -and (Test-TcpPort -IP $IP -Port 445 -TimeoutMs $Timeout)) {
        try {
            $netView = net view "\\$IP" /all 2>$null
            if ($netView) {
                # net view header sometimes shows \\HOSTNAME
                $headerLine = $netView | Where-Object { $_ -match '\\\\' } | Select-Object -First 1
                if ($headerLine -match '\\\\(\S+)') {
                    $candidate = $Matches[1].Trim()
                    if ($candidate -ne $IP) {
                        $hostname = $candidate
                        $method = "net-view"
                    }
                }
            }
        } catch {}
    }

    return @{ Hostname = $hostname; Method = $method }
}

# ============================================================================
# Phase 3: Port Scan
# ============================================================================
function Invoke-PortScan {
    param([string]$IP, [string]$OS)

    # Pick port list
    $ports = switch ($OS) {
        "Windows" { $WinPorts }
        "Linux"   { $LinPorts }
        default   { ($WinPorts + $LinPorts) | Sort-Object -Unique }
    }

    Write-Log "  [*] Scanning $($ports.Count) ports..." "DarkCyan"

    $openPorts = @()
    foreach ($port in $ports) {
        if (Test-TcpPort -IP $IP -Port $port -TimeoutMs $Timeout) {
            $openPorts += $port
        }
    }

    if ($openPorts.Count -eq 0) {
        Write-Log "  [!] No open ports found from curated list" "Yellow"
        return
    }

    $portStr = $openPorts -join ','
    Write-Log "  [+] Open ports: $portStr" "Green"
    Write-Log ""
    Write-Log ("  {0,-13}{1,-8}{2}" -f "PORT", "STATE", "SERVICE") "Cyan"
    Write-Log ("  {0,-13}{1,-8}{2}" -f "----", "-----", "-------") "Cyan"

    foreach ($port in $openPorts) {
        $svc = if ($PortLabels.ContainsKey($port)) {
            $PortLabels[$port]
        } else {
            "unknown"
        }

        # Try to grab banner for extra context on key ports
        $bannerInfo = ""
        if ($port -in @(21, 22, 25, 80, 110, 143, 8080)) {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect($IP, $port)
                $tcpClient.ReceiveTimeout = 2000
                $stream = $tcpClient.GetStream()

                # For HTTP, send a HEAD request
                if ($port -in @(80, 8080, 8443, 443)) {
                    $request = "HEAD / HTTP/1.0`r`nHost: $IP`r`n`r`n"
                    $bytes = [Text.Encoding]::ASCII.GetBytes($request)
                    $stream.Write($bytes, 0, $bytes.Length)
                }

                Start-Sleep -Milliseconds 500
                if ($stream.DataAvailable) {
                    $buffer = New-Object byte[] 512
                    $read = $stream.Read($buffer, 0, 512)
                    $banner = [Text.Encoding]::ASCII.GetString($buffer, 0, $read).Trim()
                    # Extract just the first line
                    $firstLine = ($banner -split "`n")[0].Trim()
                    if ($firstLine.Length -gt 60) { $firstLine = $firstLine.Substring(0, 60) + "..." }
                    $bannerInfo = " | $firstLine"
                }
                $tcpClient.Close()
            } catch {
                try { $tcpClient.Close() } catch {}
            }
        }

        $line = "  {0,-13}{1,-8}{2}{3}" -f "$port/tcp", "open", $svc, $bannerInfo
        Write-Log $line "White"
    }
}

# ============================================================================
# Summary
# ============================================================================
function Write-Summary {
    $elapsed = (Get-Date) - $Script:ScanStart

    Write-Log "" 
    Write-Log "  ═══════════════════════════════════════════════════════════" "White"
    Write-Log "  Scan complete. $($Script:HostsCompleted) host(s) scanned in $([math]::Round($elapsed.TotalSeconds))s" "Green"

    if ($Script:NoHostnameList.Count -gt 0) {
        Write-Log ""
        Write-Host -BackgroundColor DarkYellow -ForegroundColor Black "                                                              "
        Write-Host -BackgroundColor DarkYellow -ForegroundColor Black "    WARNING: $($Script:NoHostnameList.Count) HOST(S) WITH NO HOSTNAME RESOLVED                "
        Write-Host -BackgroundColor DarkYellow -ForegroundColor Black "                                                              "
        if ($Script:OutputFile) {
            Add-Content -Path $Script:OutputFile -Value "  !! WARNING: $($Script:NoHostnameList.Count) HOST(S) WITH NO HOSTNAME RESOLVED !!"
        }
        foreach ($nh in $Script:NoHostnameList) {
            Write-Log "    ->  $nh" "Yellow"
        }
        Write-Log ""
        Write-Log "  Manual follow-up:" "Yellow"
        Write-Log "    * nbtstat -A <ip>" "Yellow"
        Write-Log "    * nslookup <ip> <DC_IP>" "Yellow"
        Write-Log "    * [System.Net.Dns]::GetHostEntry('<ip>')" "Yellow"
        Write-Log "    * nltest /dsgetdc:<domain>" "Yellow"
        Write-Log "    * Get-ADComputer -Filter * (if on domain)" "Yellow"
    }

    Write-Log "  ═══════════════════════════════════════════════════════════" "White"
}

# ============================================================================
# Main
# ============================================================================

# --- Parse input ---
$allTargets = @()

if ($InputFile) {
    if (Test-Path $InputFile) {
        $fileLines = Get-Content $InputFile | Where-Object { $_.Trim() -and -not $_.StartsWith("#") }
        $allTargets = Expand-IPRange -InputTargets $fileLines
    } else {
        Write-Log "  [!] File not found: $InputFile" "Red"
        exit 1
    }
}

if ($Targets) {
    $allTargets += Expand-IPRange -InputTargets $Targets
}

$allTargets = $allTargets | Select-Object -Unique

if ($allTargets.Count -eq 0) {
    Write-Log ""
    Write-Log "  Usage:" "Cyan"
    Write-Log "    .\Light-Recon.ps1 -Targets 10.10.10.0/24"
    Write-Log "    .\Light-Recon.ps1 -Targets 10.10.10.1-50 -Timeout 1500"
    Write-Log "    .\Light-Recon.ps1 -InputFile targets.txt -OutputFile results.txt"
    Write-Log "    .\Light-Recon.ps1 -Targets 10.10.10.5,10.10.10.10"
    exit 0
}

$Script:TotalHosts = $allTargets.Count

# --- Init output file ---
if ($OutputFile) {
    $Script:OutputFile = $OutputFile
    "" | Set-Content -Path $OutputFile
}

# --- Banner ---
Write-Banner
Write-Log "  Targets: $($allTargets.Count) | Timeout: ${Timeout}ms | $(Get-Date)" "White"
Write-Log ""

# --- Check for Get-ADComputer and pre-populate hostname map ---
Write-Log "  [*] Checking for Active Directory module..." "DarkCyan"
try {
    # Test if the cmdlet exists (RSAT AD module loaded or available)
    $null = Get-Command Get-ADComputer -ErrorAction Stop

    Write-Log "  [+] Get-ADComputer available — pulling all computer objects..." "Green"

    $adComputers = Get-ADComputer -Filter * -Properties Name, DNSHostName, IPv4Address -ErrorAction Stop

    $adCount = 0
    foreach ($comp in $adComputers) {
        # Map by IPv4Address if present
        if ($comp.IPv4Address) {
            $Script:ADHostnameMap[$comp.IPv4Address] = @{
                Name        = $comp.Name
                DNSHostName = $comp.DNSHostName
            }
            $adCount++
        }

        # Also try resolving the DNS hostname to IP for hosts without IPv4Address populated
        if ($comp.DNSHostName -and -not $comp.IPv4Address) {
            try {
                $resolved = [System.Net.Dns]::GetHostAddresses($comp.DNSHostName) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    Select-Object -First 1
                if ($resolved) {
                    $Script:ADHostnameMap[$resolved.ToString()] = @{
                        Name        = $comp.Name
                        DNSHostName = $comp.DNSHostName
                    }
                    $adCount++
                }
            } catch {}
        }
    }

    $Script:ADAvailable = $true
    Write-Log "  [+] Cached $adCount computer(s) from AD" "Green"
    Write-Log ""

} catch {
    # TIP: If RSAT isn't installed but you have a foothold, alternatives:
    #   - Import the DLL directly:  Import-Module Microsoft.ActiveDirectory.Management.dll
    #   - Use PowerView:  Get-DomainComputer | Select-Object name, dnshostname, ipv4address
    Write-Log "  [i] AD module not available — using normal hostname discovery" "Yellow"
    Write-Log "      Tip: If you have a foothold, try loading the DLL manually:" "DarkGray"
    Write-Log "           Import-Module Microsoft.ActiveDirectory.Management.dll" "DarkGray"
    Write-Log "      Or use PowerView: Get-DomainComputer | Select name,dnshostname" "DarkGray"
    Write-Log ""
}

# --- Alive check + scan loop ---
foreach ($ip in $allTargets) {

    # Quick alive check (ICMP ping)
    $alive = $false
    try {
        $p = New-Object System.Net.NetworkInformation.Ping
        $r = $p.Send($ip, $Timeout)
        $alive = ($r.Status -eq 'Success')
        $p.Dispose()
    } catch {}

    # If ping fails, try a TCP probe on common ports before declaring dead
    if (-not $alive) {
        foreach ($probe in @(445, 80, 135, 22, 443)) {
            if (Test-TcpPort -IP $ip -Port $probe -TimeoutMs $Timeout) {
                $alive = $true
                break
            }
        }
    }

    if (-not $alive) {
        continue   # Skip dead hosts silently
    }

    $hostStart = Get-Date
    Write-Log "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "White"
    Write-Log "  TARGET: $ip" "Yellow"
    Write-Log "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "White"

    # --- Phase 1: OS ---
    Write-Log "  [*] Phase 1: OS Fingerprinting..." "DarkCyan"
    $os = Get-OSFingerprint -IP $ip
    $osColor = switch ($os) { "Windows" { "Red" } "Linux" { "Green" } default { "Yellow" } }
    Write-Log "  [+] OS: $os" $osColor

    # --- Phase 2: Hostname ---
    Write-Log "  [*] Phase 2: Hostname Extraction..." "DarkCyan"
    $hnResult = Get-HostnameFromTarget -IP $ip -OS $os

    if ($hnResult.Hostname) {
        Write-Log "  [+] Hostname: $($hnResult.Hostname)  (via $($hnResult.Method))" "Cyan"
    } else {
        Write-Log ""
        Write-Host -BackgroundColor DarkYellow -ForegroundColor Black "                                                              "
        Write-Host -BackgroundColor DarkYellow -ForegroundColor Black "    !! NO HOSTNAME FOUND - NEEDS MANUAL INVESTIGATION !!      "
        Write-Host -BackgroundColor DarkYellow -ForegroundColor Black "                                                              "
        if ($Script:OutputFile) {
            Add-Content -Path $Script:OutputFile -Value "    !! NO HOSTNAME FOUND - NEEDS MANUAL INVESTIGATION !!"
        }
        Write-Log ""
        $Script:NoHostnameList += $ip
    }

    # --- Phase 3: Ports ---
    Write-Log "  [*] Phase 3: Service Discovery..." "DarkCyan"
    Invoke-PortScan -IP $ip -OS $os

    $Script:HostsCompleted++
    $elapsed = (Get-Date) - $hostStart
    Write-Log ""
    Write-Log "  [i] Host completed in $([math]::Round($elapsed.TotalSeconds))s" "DarkCyan"
    Write-Log ""
}

# --- Summary ---
Write-Summary
