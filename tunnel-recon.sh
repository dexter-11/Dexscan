#!/bin/bash
# ============================================================================
# light_recon.sh — Tunnel-Friendly Host Scanner
# ============================================================================
# Designed for ligolo/chisel/sshuttle pivots where full nmap scans crash.
# Phase 1: OS fingerprint (TTL-based + key port probes)
# Phase 2: Hostname extraction (SMB/RDP/SSH depending on OS)
# Phase 3: Lightweight port scan with fallback service labels
# ============================================================================

# --- Colors ---
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
RST='\033[0m'

# --- Usage ---
usage() {
    echo -e "${CYN}Usage:${RST}"
    echo "  $0 <target_ip>              Scan a single host"
    echo "  $0 -f <file_of_ips>         Scan list of IPs (one per line)"
    echo "  $0 -r <start_ip> <end_ip>   Scan a range (last octet)"
    echo ""
    echo "  Options:"
    echo "    -t <seconds>    Per-port timeout (default: 2)"
    echo "    -o <file>       Output results to file"
    echo "    -q              Quiet mode (minimal output)"
    echo ""
    echo "  Examples:"
    echo "    $0 10.10.110.50"
    echo "    $0 -f targets.txt -o results.txt"
    echo "    $0 -r 10.10.110.1 10.10.110.254 -t 3"
    exit 1
}

# --- Defaults ---
TIMEOUT=2
OUTFILE=""
QUIET=0
TARGETS=()

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f)
            [[ -f "$2" ]] || { echo "File not found: $2"; exit 1; }
            mapfile -t TARGETS < "$2"
            shift 2 ;;
        -r)
            BASE="${2%.*}"
            START="${2##*.}"
            END="${3##*.}"
            for i in $(seq "$START" "$END"); do
                TARGETS+=("${BASE}.${i}")
            done
            shift 3 ;;
        -t)
            TIMEOUT="$2"
            shift 2 ;;
        -o)
            OUTFILE="$2"
            shift 2 ;;
        -q)
            QUIET=1
            shift ;;
        -h|--help)
            usage ;;
        *)
            TARGETS+=("$1")
            shift ;;
    esac
done

[[ ${#TARGETS[@]} -eq 0 ]] && usage

# --- Logging helper ---
log() {
    local msg="$1"
    echo -e "$msg"
    [[ -n "$OUTFILE" ]] && echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTFILE"
}

# --- Port lists ---
# Windows: AD/domain ports + common services
WIN_PORTS=(
    53 88 135 139 389 445 464 593 636
    1433 3268 3269 3389 5985 5986
    80 443 8080 8443
    47001 49664 49665 49666 49667 49668 49669
)

# Linux: SSH, web, common services
LIN_PORTS=(
    21 22 25 53 80 110 111 139 143 443
    445 993 995 1099 2049 3306 5432
    5900 5901 6379 8080 8443 8888
    9090 9200 27017
)

# Fallback labels when nmap returns nothing useful
declare -A PORT_LABELS
PORT_LABELS=(
    [21]="FTP"
    [22]="SSH"
    [25]="SMTP"
    [53]="DNS"
    [80]="HTTP"
    [88]="Kerberos"
    [110]="POP3"
    [111]="RPCbind"
    [135]="MSRPC"
    [139]="NetBIOS-SSN"
    [143]="IMAP"
    [389]="LDAP"
    [443]="HTTPS"
    [445]="SMB"
    [464]="Kpasswd"
    [593]="RPC-over-HTTP"
    [636]="LDAPS"
    [993]="IMAPS"
    [995]="POP3S"
    [1099]="Java-RMI"
    [1433]="MSSQL"
    [2049]="NFS"
    [3268]="LDAP-GC"
    [3269]="LDAPS-GC"
    [3306]="MySQL"
    [3389]="RDP"
    [5432]="PostgreSQL"
    [5900]="VNC"
    [5901]="VNC-1"
    [5985]="WinRM-HTTP"
    [5986]="WinRM-HTTPS"
    [6379]="Redis"
    [8080]="HTTP-Proxy"
    [8443]="HTTPS-Alt"
    [8888]="HTTP-Alt"
    [9090]="Web-Admin"
    [9200]="Elasticsearch"
    [27017]="MongoDB"
    [47001]="WinRM"
    [49664]="MSRPC-High"
    [49665]="MSRPC-High"
    [49666]="MSRPC-High"
    [49667]="MSRPC-High"
    [49668]="MSRPC-High"
    [49669]="MSRPC-High"
)

# ============================================================================
# Phase 1: OS Fingerprinting
# ============================================================================
fingerprint_os() {
    local ip="$1"
    local os="unknown"

    # --- Method 1: TTL from ping ---
    local ttl
    ttl=$(ping -c 1 -W "$TIMEOUT" "$ip" 2>/dev/null | grep -i "ttl=" | head -1 | sed -n 's/.*ttl=\([0-9]*\).*/\1/Ip')

    if [[ -n "$ttl" ]]; then
        if [[ "$ttl" -le 64 ]]; then
            os="linux"
        elif [[ "$ttl" -le 128 ]]; then
            os="windows"
        fi
    fi

    # --- Method 2: Quick port probes as tiebreaker/backup ---
    if [[ "$os" == "unknown" ]] || [[ "$os" == "linux" ]]; then
        # Check for distinctly Windows ports (135/RPC, 445/SMB, 3389/RDP)
        if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/135" 2>/dev/null; then
            os="windows"
        elif timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/5985" 2>/dev/null; then
            os="windows"
        fi
    fi

    if [[ "$os" == "unknown" ]] || [[ "$os" == "windows" ]]; then
        # SSH on port 22 is a strong Linux indicator (unless it's OpenSSH on Windows)
        if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/22" 2>/dev/null; then
            # If 22 is open but 135 isn't, almost certainly Linux
            if ! timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/135" 2>/dev/null; then
                os="linux"
            fi
        fi
    fi

    echo "$os"
}

# ============================================================================
# Phase 2: Hostname Extraction
# ============================================================================
get_hostname() {
    local ip="$1"
    local os="$2"
    local hostname=""

    if [[ "$os" == "windows" ]]; then
        # --- Try 1: SMB/NetBIOS via nbtscan (fast, single packet) ---
        if command -v nbtscan &>/dev/null; then
            hostname=$(nbtscan -q "$ip" 2>/dev/null | awk '{print $2}' | head -1)
        fi

        # --- Try 2: nmblookup ---
        if [[ -z "$hostname" ]] && command -v nmblookup &>/dev/null; then
            hostname=$(nmblookup -A "$ip" 2>/dev/null | grep '<00>' | grep -v '<GROUP>' | head -1 | awk '{print $1}')
        fi

        # --- Try 3: crackmapexec/nxc SMB (single host, fast) ---
        if [[ -z "$hostname" ]]; then
            if command -v nxc &>/dev/null; then
                local cme_out
                cme_out=$(nxc smb "$ip" --timeout "$TIMEOUT" 2>/dev/null | head -1)
                hostname=$(echo "$cme_out" | grep -oP '(?<=name:)\S+' || echo "$cme_out" | awk -F'[][]' '{print $2}' | xargs 2>/dev/null)
            elif command -v crackmapexec &>/dev/null; then
                local cme_out
                cme_out=$(crackmapexec smb "$ip" --timeout "$TIMEOUT" 2>/dev/null | head -1)
                hostname=$(echo "$cme_out" | grep -oP '(?<=name:)\S+' || echo "$cme_out" | awk -F'[][]' '{print $2}' | xargs 2>/dev/null)
            fi
        fi

        # --- Try 4: RDP NTLM info via nmap (targeted single port, won't overload) ---
        if [[ -z "$hostname" || "$hostname" == " " ]]; then
            local rdp_out
            rdp_out=$(nmap -Pn -n -p 3389 --script rdp-ntlm-info "$ip" 2>/dev/null)
            hostname=$(echo "$rdp_out" | grep "NetBIOS_Computer_Name" | awk -F': ' '{print $2}' | xargs 2>/dev/null)
            # Also grab domain if available
            local domain
            domain=$(echo "$rdp_out" | grep "NetBIOS_Domain_Name" | awk -F': ' '{print $2}' | xargs 2>/dev/null)
            if [[ -n "$domain" && -n "$hostname" ]]; then
                hostname="${hostname} (${domain})"
            fi
        fi

        # --- Try 5: LDAP for DCs ---
        if [[ -z "$hostname" || "$hostname" == " " ]]; then
            local ldap_out
            ldap_out=$(nmap -Pn -n -p 389 --script ldap-rootdse "$ip" 2>/dev/null)
            hostname=$(echo "$ldap_out" | grep "dnsHostName" | awk -F': ' '{print $2}' | xargs 2>/dev/null)
        fi

    elif [[ "$os" == "linux" ]]; then
        # --- Try 1: SSH banner grab ---
        local ssh_banner
        ssh_banner=$(timeout "$TIMEOUT" bash -c "echo '' | nc -w $TIMEOUT $ip 22 2>/dev/null" | head -1)
        # Some SSH banners contain the hostname, but mainly useful for OS detail

        # --- Try 2: Reverse DNS ---
        if command -v host &>/dev/null; then
            hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
        elif command -v dig &>/dev/null; then
            hostname=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//')
        fi

        # --- Try 3: SMB if 445 is open (Samba boxes) ---
        if [[ -z "$hostname" ]] && timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/445" 2>/dev/null; then
            if command -v nbtscan &>/dev/null; then
                hostname=$(nbtscan -q "$ip" 2>/dev/null | awk '{print $2}' | head -1)
            fi
        fi

        # --- Try 4: SNMP community string public ---
        if [[ -z "$hostname" ]] && command -v snmpwalk &>/dev/null; then
            hostname=$(snmpwalk -v2c -c public "$ip" sysName.0 2>/dev/null | awk -F'"' '{print $2}')
        fi
    fi

    # Clean up
    hostname=$(echo "$hostname" | xargs 2>/dev/null)
    [[ -z "$hostname" || "$hostname" == " " ]] && hostname="N/A"
    echo "$hostname"
}

# ============================================================================
# Phase 3: Lightweight Port Scan
# ============================================================================
scan_ports() {
    local ip="$1"
    local os="$2"
    local open_ports=()

    # Pick port list based on OS
    local -a ports
    if [[ "$os" == "windows" ]]; then
        ports=("${WIN_PORTS[@]}")
    elif [[ "$os" == "linux" ]]; then
        ports=("${LIN_PORTS[@]}")
    else
        # Unknown OS: merge both lists, deduplicate
        ports=($(echo "${WIN_PORTS[@]} ${LIN_PORTS[@]}" | tr ' ' '\n' | sort -nu))
    fi

    [[ "$QUIET" -eq 0 ]] && log "  ${BLU}[*]${RST} Scanning ${#ports[@]} ports..."

    # --- Fast TCP connect scan using /dev/tcp (no nmap overhead) ---
    for port in "${ports[@]}"; do
        if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            open_ports+=("$port")
        fi
    done

    if [[ ${#open_ports[@]} -eq 0 ]]; then
        log "  ${YLW}[!]${RST} No open ports found from curated list"
        return
    fi

    # --- Now do a targeted nmap ONLY on discovered open ports for service info ---
    local port_csv
    port_csv=$(IFS=,; echo "${open_ports[*]}")

    log "  ${GRN}[+]${RST} Open ports: ${port_csv}"
    log ""
    log "  ${CYN}PORT        STATE   SERVICE${RST}"
    log "  ${CYN}----        -----   -------${RST}"

    # Single targeted nmap call — minimal traffic
    local nmap_out
    nmap_out=$(nmap -Pn -n -sV --version-intensity 0 -p "$port_csv" --open "$ip" 2>/dev/null)

    for port in "${open_ports[@]}"; do
        # Try to grab service from nmap output
        local svc
        svc=$(echo "$nmap_out" | grep "^${port}/tcp" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | xargs 2>/dev/null)

        # If nmap returned nothing useful, use our fallback label
        if [[ -z "$svc" || "$svc" == "?" || "$svc" == "unknown" || "$svc" =~ ^tcpwrapped ]]; then
            local label="${PORT_LABELS[$port]:-unknown}"
            svc="${label} (assumed)"
        fi

        printf -v line "  %-12s%-8s%s" "${port}/tcp" "open" "$svc"
        log "$line"
    done
}

# ============================================================================
# Main Loop
# ============================================================================
SCAN_START=$(date +%s)

log ""
log "╔══════════════════════════════════════════════════════════╗"
log "║           ${CYN}light_recon.sh${RST} — Tunnel-Safe Scanner          ║"
log "╚══════════════════════════════════════════════════════════╝"
log ""
log "  Targets: ${#TARGETS[@]} | Timeout: ${TIMEOUT}s | $(date)"
log ""

if [[ -n "$OUTFILE" ]]; then
    echo "" > "$OUTFILE"
    log "  ${BLU}[*]${RST} Logging to: $OUTFILE"
    log ""
fi

for ip in "${TARGETS[@]}"; do
    # Skip blank lines and comments
    [[ -z "$ip" || "$ip" =~ ^# ]] && continue

    HOST_START=$(date +%s)
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "  ${YLW}TARGET:${RST} $ip"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # --- Phase 1 ---
    log "  ${BLU}[*]${RST} Phase 1: OS Fingerprinting..."
    os=$(fingerprint_os "$ip")
    if [[ "$os" == "windows" ]]; then
        log "  ${GRN}[+]${RST} OS: ${RED}Windows${RST}"
    elif [[ "$os" == "linux" ]]; then
        log "  ${GRN}[+]${RST} OS: ${GRN}Linux${RST}"
    else
        log "  ${YLW}[!]${RST} OS: ${YLW}Unknown${RST} (scanning all ports)"
    fi

    # --- Phase 2 ---
    log "  ${BLU}[*]${RST} Phase 2: Hostname Extraction..."
    hostname=$(get_hostname "$ip" "$os")
    log "  ${GRN}[+]${RST} Hostname: ${CYN}${hostname}${RST}"

    # --- Phase 3 ---
    log "  ${BLU}[*]${RST} Phase 3: Service Discovery..."
    scan_ports "$ip" "$os"

    HOST_END=$(date +%s)
    log ""
    log "  ${BLU}[i]${RST} Host completed in $((HOST_END - HOST_START))s"
    log ""
done

SCAN_END=$(date +%s)
log "═══════════════════════════════════════════════════════════"
log "  ${GRN}Scan complete.${RST} ${#TARGETS[@]} host(s) in $((SCAN_END - SCAN_START))s"
log "═══════════════════════════════════════════════════════════"
