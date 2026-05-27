#!/bin/bash
# ============================================================================
# light_recon.sh v2 — Tunnel-Friendly Host Scanner
# ============================================================================
# Designed for ligolo/chisel/sshuttle pivots where full nmap scans crash.
#
# Phase 0: Tool dependency check
# Phase 1: OS fingerprint (TTL + key port probes)
# Phase 2: Hostname extraction (multi-method: SMB, RDP-NTLM, HTTP-NTLM,
#           MSSQL-NTLM, SSL CN, SSH banner, reverse DNS, SNMP, LDAP)
# Phase 3: Lightweight port scan with fallback service labels
# ============================================================================

# --- Colors ---
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
MAG='\033[0;35m'
BOLD='\033[1m'
BYELLOW='\033[1;33m'       # Bold yellow for hostname warnings
BYELLOW_BG='\033[1;43;30m' # Bold yellow background, black text
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
HOSTS_COMPLETED=0
INTERRUPTED=0

# --- Ctrl+C handler ---
handle_interrupt() {
    INTERRUPTED=1
    echo ""
    log ""
    log "  ${RED}${BOLD}[!] Ctrl+C detected — stopping scan gracefully...${RST}"
    log ""
    print_summary
    exit 130
}

# --- Summary printer (called on normal exit and Ctrl+C) ---
print_summary() {
    SCAN_END=$(date +%s)
    log ""
    log "═══════════════════════════════════════════════════════════════"

    if [[ "$INTERRUPTED" -eq 1 ]]; then
        log "  ${RED}${BOLD}INTERRUPTED.${RST} ${HOSTS_COMPLETED}/${#TARGETS[@]} host(s) scanned in $((SCAN_END - SCAN_START))s"
        local remaining=$((${#TARGETS[@]} - HOSTS_COMPLETED))
        log "  ${YLW}${remaining} host(s) were NOT scanned.${RST}"
    else
        log "  ${GRN}Scan complete.${RST} ${#TARGETS[@]} host(s) in $((SCAN_END - SCAN_START))s"
    fi

    if [[ ${#NO_HOSTNAME_HOSTS[@]} -gt 0 ]]; then
        log ""
        log "  ${BYELLOW_BG}                                                          ${RST}"
        log "  ${BYELLOW_BG}   ⚠  HOSTS WITH NO HOSTNAME: ${#NO_HOSTNAME_HOSTS[@]} host(s)                  ${RST}"
        log "  ${BYELLOW_BG}                                                          ${RST}"
        for nh in "${NO_HOSTNAME_HOSTS[@]}"; do
            log "    ${BYELLOW}→  ${nh}${RST}"
        done
        log ""
        log "  ${YLW}  Manual follow-up suggestions:${RST}"
        log "  ${YLW}    • rpcclient -U '' -N <ip> -c 'srvinfo'${RST}"
        log "  ${YLW}    • enum4linux-ng -A <ip>${RST}"
        log "  ${YLW}    • dig @<DC_IP> -x <ip>  (query internal DNS directly)${RST}"
        log "  ${YLW}    • ldapsearch -x -H ldap://<DC> -b 'DC=domain,DC=local'${RST}"
        log "  ${YLW}    • RDP to the host if 3389 is open${RST}"
    fi

    log "═══════════════════════════════════════════════════════════════"
}

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

# --- Logging helper (strips ANSI for file output) ---
log() {
    local msg="$1"
    echo -e "$msg"
    [[ -n "$OUTFILE" ]] && echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTFILE"
}

# ============================================================================
# Phase 0: Tool Dependency Check
# ============================================================================
check_tools() {
    log ""
    log "  ${BLU}[*]${RST} Phase 0: Checking tool dependencies..."
    log ""

    # Required — script won't function without these
    local required_tools=("nmap" "nc" "ping")
    # Optional — extra hostname/enum capabilities
    local optional_tools=("nbtscan" "nmblookup" "nxc" "crackmapexec" "host" "dig" "snmpwalk" "openssl" "curl" "smbclient" "rpcclient")

    local missing_required=()
    local missing_optional=()

    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log "    ${GRN}✓${RST}  ${tool}"
        else
            log "    ${RED}✗${RST}  ${tool} ${RED}(REQUIRED — script will exit)${RST}"
            missing_required+=("$tool")
        fi
    done

    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log "    ${GRN}✓${RST}  ${tool}"
        else
            log "    ${YLW}○${RST}  ${tool} ${YLW}(optional — install for better hostname results)${RST}"
            missing_optional+=("$tool")
        fi
    done

    log ""

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        log "  ${RED}[!] FATAL: Missing required tools: ${missing_required[*]}${RST}"
        log "  ${RED}    Install them before running this script.${RST}"
        exit 1
    fi

    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        log "  ${YLW}[i]${RST} Missing optional tools reduce hostname discovery accuracy."
        log "  ${YLW}    Consider: apt install ${missing_optional[*]}${RST}"
    fi

    log ""
}

# ============================================================================
# Port Lists
# ============================================================================

# Windows: AD/domain + common services + web + RDP + WinRM + MSSQL
WIN_PORTS=(
    21 53 80 88 135 139 389 443 445 464 593 636
    1433 3268 3269 3389
    5985 5986
    8080 8443 9389
    47001
)

# Linux: SSH, web, databases, NFS, RPCbind, RDP (xrdp), plus modern web ports
LIN_PORTS=(
    21 22 25 53 80 110 111 139 143 389 443 445
    993 995 1099 2049
    3000 3306 3389
    5432 5601 5900 5901
    6379 8000 8080 8443 8888
    9000 9001 9090 9200 9443
    10000 27017
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
    [3000]="Grafana/Dev-Web"
    [3268]="LDAP-GC"
    [3269]="LDAPS-GC"
    [3306]="MySQL"
    [3389]="RDP"
    [5432]="PostgreSQL"
    [5601]="Kibana"
    [5900]="VNC"
    [5901]="VNC-1"
    [5985]="WinRM-HTTP"
    [5986]="WinRM-HTTPS"
    [6379]="Redis"
    [8000]="HTTP-Alt"
    [8080]="HTTP-Proxy"
    [8443]="HTTPS-Alt"
    [8888]="HTTP-Alt"
    [9000]="Portainer/SonarQube"
    [9001]="Supervisord/HTTP-Alt"
    [9090]="Prometheus/Web-Admin"
    [9200]="Elasticsearch"
    [9389]="AD-Web-Services"
    [9443]="HTTPS-Alt"
    [10000]="Webmin/Virtualmin"
    [27017]="MongoDB"
    [47001]="WinRM"
)

# ============================================================================
# Phase 1: OS Fingerprinting
# ============================================================================
fingerprint_os() {
    local ip="$1"
    local os="unknown"

    # --- Method 1: TTL from ping ---
    local ttl
    ttl=$(ping -c 1 -W "$TIMEOUT" "$ip" 2>/dev/null \
        | grep -i "ttl=" | head -1 \
        | sed -n 's/.*ttl=\([0-9]*\).*/\1/Ip')

    if [[ -n "$ttl" ]]; then
        if [[ "$ttl" -le 64 ]]; then
            os="linux"
        elif [[ "$ttl" -le 128 ]]; then
            os="windows"
        fi
    fi

    # --- Method 2: Key port probes as tiebreaker ---
    if [[ "$os" == "unknown" || "$os" == "linux" ]]; then
        # 135/RPC or 88/Kerberos are almost exclusively Windows
        if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/135" 2>/dev/null; then
            os="windows"
        elif timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/5985" 2>/dev/null; then
            os="windows"
        elif timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/88" 2>/dev/null; then
            os="windows"
        fi
    fi

    if [[ "$os" == "unknown" || "$os" == "windows" ]]; then
        # SSH open + no RPC = almost certainly Linux
        if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/22" 2>/dev/null; then
            if ! timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/135" 2>/dev/null; then
                os="linux"
            fi
        fi
    fi

    echo "$os"
}

# ============================================================================
# Phase 2: Hostname Extraction (multi-method)
# ============================================================================

# Helper: extract NTLM hostname from nmap *-ntlm-info script output
parse_ntlm_hostname() {
    local nmap_out="$1"
    local hn="" dn="" fqdn=""

    hn=$(echo "$nmap_out" | grep "NetBIOS_Computer_Name" | awk -F': ' '{print $2}' | xargs 2>/dev/null)
    dn=$(echo "$nmap_out" | grep "NetBIOS_Domain_Name" | awk -F': ' '{print $2}' | xargs 2>/dev/null)
    fqdn=$(echo "$nmap_out" | grep "DNS_Computer_Name" | awk -F': ' '{print $2}' | xargs 2>/dev/null)

    if [[ -n "$fqdn" ]]; then
        echo "$fqdn"
    elif [[ -n "$hn" && -n "$dn" ]]; then
        echo "${hn} (${dn})"
    elif [[ -n "$hn" ]]; then
        echo "$hn"
    fi
}

# Helper: try SSL CN extraction from a port
try_ssl_cn() {
    local ip="$1"
    local port="$2"
    if command -v openssl &>/dev/null && timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
        local cn
        cn=$(echo | timeout 5 openssl s_client -connect "${ip}:${port}" 2>/dev/null \
            | openssl x509 -noout -subject 2>/dev/null \
            | sed -n 's/.*CN\s*=\s*//p' | xargs 2>/dev/null)
        # Skip wildcards and bare IPs — not useful hostnames
        if [[ -n "$cn" && "$cn" != "*."* && "$cn" != "$ip" ]]; then
            echo "$cn"
        fi
    fi
}

get_hostname() {
    local ip="$1"
    local os="$2"
    local hostname=""
    local method=""

    # ------------------------------------------------------------------
    # WINDOWS hostname methods (ordered by speed / tunnel cost)
    # ------------------------------------------------------------------
    if [[ "$os" == "windows" ]]; then

        # 1. nbtscan — single UDP packet, fastest possible
        if [[ -z "$hostname" ]] && command -v nbtscan &>/dev/null; then
            hostname=$(nbtscan -q "$ip" 2>/dev/null | awk '{print $2}' | head -1)
            [[ -n "$hostname" ]] && method="nbtscan"
        fi

        # 2. nmblookup
        if [[ -z "$hostname" ]] && command -v nmblookup &>/dev/null; then
            hostname=$(nmblookup -A "$ip" 2>/dev/null | grep '<00>' | grep -v '<GROUP>' | head -1 | awk '{print $1}')
            [[ -n "$hostname" ]] && method="nmblookup"
        fi

        # 3. nxc / crackmapexec SMB — one TCP handshake, pulls name + domain + OS
        if [[ -z "$hostname" ]]; then
            local cme_cmd=""
            command -v nxc &>/dev/null && cme_cmd="nxc"
            [[ -z "$cme_cmd" ]] && command -v crackmapexec &>/dev/null && cme_cmd="crackmapexec"
            if [[ -n "$cme_cmd" ]]; then
                local cme_out
                cme_out=$($cme_cmd smb "$ip" --timeout "$TIMEOUT" 2>/dev/null | head -1)
                hostname=$(echo "$cme_out" | grep -oP '(?<=name:)\S+' 2>/dev/null)
                [[ -z "$hostname" ]] && hostname=$(echo "$cme_out" | awk -F'[][]' '{print $2}' | xargs 2>/dev/null)
                [[ -n "$hostname" ]] && method="$cme_cmd"
            fi
        fi

        # 4. nmap smb-os-discovery (single port 445)
        if [[ -z "$hostname" ]] && timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/445" 2>/dev/null; then
            local smb_out
            smb_out=$(nmap -Pn -n -p 445 --script smb-os-discovery "$ip" 2>/dev/null)
            local smb_fqdn
            smb_fqdn=$(echo "$smb_out" | grep "FQDN:" | awk -F': ' '{print $2}' | xargs 2>/dev/null)
            [[ -n "$smb_fqdn" ]] && hostname="$smb_fqdn"
            if [[ -z "$hostname" ]]; then
                hostname=$(echo "$smb_out" | grep "Computer name:" | awk -F': ' '{print $2}' | xargs 2>/dev/null)
            fi
            [[ -n "$hostname" ]] && method="smb-os-discovery"
        fi

        # 5. RDP NTLM info (port 3389 — no auth required)
        if [[ -z "$hostname" ]] && timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/3389" 2>/dev/null; then
            local rdp_out
            rdp_out=$(nmap -Pn -n -p 3389 --script rdp-ntlm-info "$ip" 2>/dev/null)
            hostname=$(parse_ntlm_hostname "$rdp_out")
            [[ -n "$hostname" ]] && method="rdp-ntlm-info"
        fi

        # 6. MSSQL NTLM info (port 1433 — no auth required)
        if [[ -z "$hostname" ]] && timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/1433" 2>/dev/null; then
            local sql_out
            sql_out=$(nmap -Pn -n -p 1433 --script ms-sql-ntlm-info "$ip" 2>/dev/null)
            hostname=$(parse_ntlm_hostname "$sql_out")
            [[ -n "$hostname" ]] && method="ms-sql-ntlm-info"
        fi

        # 7. HTTP NTLM info (IIS, Exchange, WinRM — no auth required)
        if [[ -z "$hostname" ]]; then
            local http_ntlm_ports=(80 443 5985 8080 5986 8443)
            for hp in "${http_ntlm_ports[@]}"; do
                if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$hp" 2>/dev/null; then
                    local http_out
                    http_out=$(nmap -Pn -n -p "$hp" --script http-ntlm-info "$ip" 2>/dev/null)
                    hostname=$(parse_ntlm_hostname "$http_out")
                    if [[ -n "$hostname" ]]; then
                        method="http-ntlm-info:${hp}"
                        break
                    fi
                fi
            done
        fi

        # 8. SSL certificate Common Name
        if [[ -z "$hostname" ]]; then
            local ssl_ports=(443 636 3269 8443 3389)
            for sp in "${ssl_ports[@]}"; do
                hostname=$(try_ssl_cn "$ip" "$sp")
                if [[ -n "$hostname" ]]; then
                    method="ssl-cn:${sp}"
                    break
                fi
            done
        fi

        # 9. LDAP rootDSE dnsHostName (port 389 — for DCs)
        if [[ -z "$hostname" ]] && timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/389" 2>/dev/null; then
            local ldap_out
            ldap_out=$(nmap -Pn -n -p 389 --script ldap-rootdse "$ip" 2>/dev/null)
            hostname=$(echo "$ldap_out" | grep "dnsHostName" | awk -F': ' '{print $2}' | xargs 2>/dev/null)
            [[ -n "$hostname" ]] && method="ldap-rootdse"
        fi

        # 10. rpcclient srvinfo (null session)
        if [[ -z "$hostname" ]] && command -v rpcclient &>/dev/null; then
            if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/445" 2>/dev/null; then
                local rpc_hn
                rpc_hn=$(rpcclient -U '' -N "$ip" -c 'srvinfo' 2>/dev/null | head -1 | awk '{print $1}')
                rpc_hn=$(echo "$rpc_hn" | xargs 2>/dev/null)
                if [[ -n "$rpc_hn" && "$rpc_hn" != "Could" && "$rpc_hn" != "result" ]]; then
                    hostname="$rpc_hn"
                    method="rpcclient"
                fi
            fi
        fi

        # 11. Reverse DNS as last resort
        if [[ -z "$hostname" ]]; then
            if command -v host &>/dev/null; then
                hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
            elif command -v dig &>/dev/null; then
                hostname=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//')
            fi
            [[ -n "$hostname" ]] && method="reverse-dns"
        fi

    # ------------------------------------------------------------------
    # LINUX hostname methods
    # ------------------------------------------------------------------
    elif [[ "$os" == "linux" ]]; then

        # 1. Reverse DNS — cheapest, most reliable for Linux in internal nets
        if [[ -z "$hostname" ]]; then
            if command -v host &>/dev/null; then
                hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
            elif command -v dig &>/dev/null; then
                hostname=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//')
            fi
            [[ -n "$hostname" ]] && method="reverse-dns"
        fi

        # 2. SMB if 445 is open (Samba)
        if [[ -z "$hostname" ]] && timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/445" 2>/dev/null; then
            # nbtscan
            if command -v nbtscan &>/dev/null; then
                hostname=$(nbtscan -q "$ip" 2>/dev/null | awk '{print $2}' | head -1)
                [[ -n "$hostname" ]] && method="nbtscan"
            fi
            # nxc/cme also works on Samba
            if [[ -z "$hostname" ]]; then
                local cme_cmd=""
                command -v nxc &>/dev/null && cme_cmd="nxc"
                [[ -z "$cme_cmd" ]] && command -v crackmapexec &>/dev/null && cme_cmd="crackmapexec"
                if [[ -n "$cme_cmd" ]]; then
                    local cme_out
                    cme_out=$($cme_cmd smb "$ip" --timeout "$TIMEOUT" 2>/dev/null | head -1)
                    hostname=$(echo "$cme_out" | grep -oP '(?<=name:)\S+' 2>/dev/null)
                    [[ -z "$hostname" ]] && hostname=$(echo "$cme_out" | awk -F'[][]' '{print $2}' | xargs 2>/dev/null)
                    [[ -n "$hostname" ]] && method="$cme_cmd"
                fi
            fi
            # smb-os-discovery
            if [[ -z "$hostname" ]]; then
                local smb_out
                smb_out=$(nmap -Pn -n -p 445 --script smb-os-discovery "$ip" 2>/dev/null)
                hostname=$(echo "$smb_out" | grep "Computer name:" | awk -F': ' '{print $2}' | xargs 2>/dev/null)
                [[ -n "$hostname" ]] && method="smb-os-discovery"
            fi
        fi

        # 3. SSL certificate CN
        if [[ -z "$hostname" ]]; then
            local ssl_ports=(443 8443 9443)
            for sp in "${ssl_ports[@]}"; do
                hostname=$(try_ssl_cn "$ip" "$sp")
                if [[ -n "$hostname" ]]; then
                    method="ssl-cn:${sp}"
                    break
                fi
            done
        fi

        # 4. HTTP headers — X-Served-By, Server, or redirect location
        if [[ -z "$hostname" ]] && command -v curl &>/dev/null; then
            local web_ports=(80 8080 443 8443 9000)
            for wp in "${web_ports[@]}"; do
                if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$wp" 2>/dev/null; then
                    local scheme="http"
                    [[ "$wp" == 443 || "$wp" == 8443 || "$wp" == 9443 ]] && scheme="https"
                    local headers
                    headers=$(timeout "$((TIMEOUT+2))" curl -skI "${scheme}://${ip}:${wp}" 2>/dev/null | head -20)
                    # X-Served-By often contains hostname
                    local served_by
                    served_by=$(echo "$headers" | grep -i "^X-Served-By:" | awk -F': ' '{print $2}' | tr -d '\r' | xargs 2>/dev/null)
                    if [[ -n "$served_by" && "$served_by" != "$ip" ]]; then
                        hostname="$served_by"
                        method="http-X-Served-By:${wp}"
                        break
                    fi
                    # Location redirect might contain a hostname
                    local location
                    location=$(echo "$headers" | grep -i "^Location:" | head -1 | grep -oP 'https?://[^/:]+' | sed 's|https\?://||' | xargs 2>/dev/null)
                    if [[ -n "$location" && "$location" != "$ip" && ! "$location" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                        hostname="$location"
                        method="http-redirect:${wp}"
                        break
                    fi
                fi
            done
        fi

        # 5. SNMP sysName (community string 'public')
        if [[ -z "$hostname" ]] && command -v snmpwalk &>/dev/null; then
            hostname=$(timeout "$((TIMEOUT+3))" snmpwalk -v2c -c public "$ip" sysName.0 2>/dev/null \
                | awk -F'"' '{print $2}' | head -1)
            [[ -n "$hostname" ]] && method="snmp-sysName"
        fi

    # ------------------------------------------------------------------
    # UNKNOWN OS — try common methods from both
    # ------------------------------------------------------------------
    else
        # Reverse DNS
        if command -v host &>/dev/null; then
            hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
        elif command -v dig &>/dev/null; then
            hostname=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//')
        fi
        [[ -n "$hostname" ]] && method="reverse-dns"

        # nbtscan
        if [[ -z "$hostname" ]] && command -v nbtscan &>/dev/null; then
            hostname=$(nbtscan -q "$ip" 2>/dev/null | awk '{print $2}' | head -1)
            [[ -n "$hostname" ]] && method="nbtscan"
        fi

        # SSL CN on 443
        if [[ -z "$hostname" ]]; then
            hostname=$(try_ssl_cn "$ip" 443)
            [[ -n "$hostname" ]] && method="ssl-cn:443"
        fi
    fi

    # --- Clean up ---
    hostname=$(echo "$hostname" | xargs 2>/dev/null)
    [[ -z "$hostname" || "$hostname" == " " ]] && hostname=""

    if [[ -n "$hostname" ]]; then
        echo "${hostname}|${method}"
    else
        echo "|"
    fi
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
        # Unknown OS: merge both, deduplicate
        ports=($(echo "${WIN_PORTS[@]} ${LIN_PORTS[@]}" | tr ' ' '\n' | sort -nu))
    fi

    [[ "$QUIET" -eq 0 ]] && log "  ${BLU}[*]${RST} Scanning ${#ports[@]} ports (connect scan)..."

    # --- Fast TCP connect scan using /dev/tcp ---
    for port in "${ports[@]}"; do
        if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            open_ports+=("$port")
        fi
    done

    if [[ ${#open_ports[@]} -eq 0 ]]; then
        log "  ${YLW}[!]${RST} No open ports found from curated list"
        return
    fi

    # --- Single targeted nmap on discovered open ports only ---
    local port_csv
    port_csv=$(IFS=,; echo "${open_ports[*]}")

    log "  ${GRN}[+]${RST} Open ports: ${port_csv}"
    log ""
    log "  ${CYN}PORT         STATE   SERVICE${RST}"
    log "  ${CYN}----         -----   -------${RST}"

    local nmap_out
    nmap_out=$(nmap -Pn -n -sV --version-intensity 0 -p "$port_csv" --open "$ip" 2>/dev/null)

    for port in "${open_ports[@]}"; do
        local svc
        svc=$(echo "$nmap_out" | grep "^${port}/tcp" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}' | xargs 2>/dev/null)

        # Fallback: if nmap returned junk, use our known label
        if [[ -z "$svc" || "$svc" == "?" || "$svc" =~ ^unknown$ || "$svc" =~ ^tcpwrapped ]]; then
            local label="${PORT_LABELS[$port]:-unknown}"
            svc="${label} ${YLW}(assumed)${RST}"
        fi

        printf -v line "  %-13s%-8s%s" "${port}/tcp" "open" "$svc"
        log "$line"
    done
}

# ============================================================================
# Main
# ============================================================================
SCAN_START=$(date +%s)

log ""
log "╔══════════════════════════════════════════════════════════════╗"
log "║          ${CYN}light_recon.sh v2${RST} — Tunnel-Safe Scanner            ║"
log "╚══════════════════════════════════════════════════════════════╝"
log ""
log "  Targets: ${#TARGETS[@]} | Timeout: ${TIMEOUT}s | $(date)"

if [[ -n "$OUTFILE" ]]; then
    echo "" > "$OUTFILE"
    log "  Logging to: $OUTFILE"
fi

# --- Phase 0: Tool check ---
check_tools

# Register Ctrl+C handler
trap handle_interrupt SIGINT

# Track hosts with no hostname for final summary
NO_HOSTNAME_HOSTS=()

for ip in "${TARGETS[@]}"; do
    [[ -z "$ip" || "$ip" =~ ^# ]] && continue

    HOST_START=$(date +%s)
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "  ${YLW}TARGET:${RST} $ip"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # --- Phase 1: OS ---
    log "  ${BLU}[*]${RST} Phase 1: OS Fingerprinting..."
    os=$(fingerprint_os "$ip")
    if [[ "$os" == "windows" ]]; then
        log "  ${GRN}[+]${RST} OS: ${RED}Windows${RST}"
    elif [[ "$os" == "linux" ]]; then
        log "  ${GRN}[+]${RST} OS: ${GRN}Linux${RST}"
    else
        log "  ${YLW}[!]${RST} OS: ${YLW}Unknown${RST} (scanning all ports)"
    fi

    # --- Phase 2: Hostname ---
    log "  ${BLU}[*]${RST} Phase 2: Hostname Extraction..."
    hn_result=$(get_hostname "$ip" "$os")
    hostname="${hn_result%%|*}"
    hn_method="${hn_result##*|}"

    if [[ -n "$hostname" ]]; then
        log "  ${GRN}[+]${RST} Hostname: ${CYN}${BOLD}${hostname}${RST}  ${MAG}(via ${hn_method})${RST}"
    else
        log ""
        log "  ${BYELLOW_BG}                                                          ${RST}"
        log "  ${BYELLOW_BG}   ⚠  NO HOSTNAME FOUND — NEEDS MANUAL INVESTIGATION     ${RST}"
        log "  ${BYELLOW_BG}                                                          ${RST}"
        log ""
        NO_HOSTNAME_HOSTS+=("$ip")
    fi

    # --- Phase 3: Ports ---
    log "  ${BLU}[*]${RST} Phase 3: Service Discovery..."
    scan_ports "$ip" "$os"

    HOSTS_COMPLETED=$((HOSTS_COMPLETED + 1))

    HOST_END=$(date +%s)
    log ""
    log "  ${BLU}[i]${RST} Host completed in $((HOST_END - HOST_START))s"
    log ""
done

# ============================================================================
# Final Summary
# ============================================================================
print_summary
