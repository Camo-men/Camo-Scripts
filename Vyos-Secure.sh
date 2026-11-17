#!/bin/sh
# ==============================================================================
# Cyber Lab - VyOS iptables hardening + per-box outbound control + Suricata IPS
# Runs on the Debian layer of VyOS 1.4 (as root). Touches ONLY the iptables
# filter table. VyOS NAT / nftables firewall are never modified.
#
#   INPUT   : default DROP. SSH (rate limited) from SSH_SRC (Kali) only, plus
#             DHCP for the workstation subnet (ALLOW_DHCP).
#   OUTPUT  : default DROP. VyOS itself cannot beacon out.  vyos-out on|off
#   FORWARD : default DROP.
#     - Published services are open to ANY source (scoring-engine IPs rotate and
#       the red team shares their subnet, so no source allowlist is used).
#       Protection = per-source rate limits + Suricata IPS + auto-ban.
#     - Palo Alto: reachable ONLY by Kali, only on its WAN IP (172.16.0.1) with
#       HTTPS + ping; mgmt/inside IPs ping only; everyone else is dropped.
#     - IPv6 is blocked completely (ip6tables DROP + sysctl disable).
#     - Kali: DNS to the AD DNS server,
#       HTTPS to chosen servers, port-scan access to the server LAN (kali-scan).
#     - Outbound (to the internet) is controlled PER BOX: off | web | all
#       (servers AND the Ubuntu/Windows workstations on 172.20.240.2/.3)
#       Run:  egress      (interactive menu)   egress <box> <mode>
# ==============================================================================

# --- PATHS --------------------------------------------------------------------
BACKUP_DIR="/config/iptables"
DEFAULT_BACKUP="${BACKUP_DIR}/rules.v4.backup"
AUTO_PRE_RESTORE="${BACKUP_DIR}/auto_pre_restore.v4"
STATE_FILE="${BACKUP_DIR}/lab.state"          # remembers toggles / box modes
IPS_DIR="/config/suricata"
IPS_RULES="${IPS_DIR}/local.rules"
SURICATA_PID="/run/suricata.pid"
BAN_PID="/run/lab-banloop.pid"
EVE_LOG="/var/log/suricata/eve.json"

# --- NETWORK CONFIG -----------------------------------------------------------
TEAM="${TEAM:-4}"                             # public range 172.25.(20+TEAM).0/24

WKST_NET="172.17.0.0/24"
KALI_IP="${KALI_IP:-172.17.0.2}"
SSH_SRC="${SSH_SRC:-$KALI_IP}"                # only this source may SSH to VyOS

# Workstation VMs sit on the server LAN (behind the Palo Alto), reserved/static:
#   Windows 11 = 172.20.240.2   Ubuntu = 172.20.240.3
# (swap with WKST_WIN_IP / WKST_UBUNTU_IP if you reserve them the other way round)
# Kali (172.17.0.2) is the only host on WKST_NET.
WKST_WIN_IP="${WKST_WIN_IP:-172.20.240.2}"
WKST_UBUNTU_IP="${WKST_UBUNTU_IP:-172.20.240.3}"

# Interfaces are auto-detected from their addresses; override if needed
WKST_ADDR="172.17.0.1/"
INT_ADDR="172.16.0.254/"
EXT_ADDR="172.31."

INT_NET="172.20.240"
SERVER_SUBNET="${INT_NET}.0/24"
PALO_FW_IP="172.16.0.1"                       # Palo Alto outside interface
PALO_MGMT="172.20.240.200"                    # Palo Alto management IP (ping-only profile)
PALO_INSIDE="172.20.240.254"                  # Palo Alto inside interface (ping-only profile)
# Kali -> Palo WAN IP (172.16.0.1): only these TCP ports (+ ping). CLI is via the
# Palo VNC console. Add 22 here only for a deliberate, temporary SSH session.
PALO_KALI_PORTS="${PALO_KALI_PORTS:-443}"

ECOM_ID=10; EMAIL_ID=15; SPLUNK_ID=20; AD_ID=100; MSSQL_ID=120
DNS_ID="$AD_ID"                               # AD is the DNS server

# Published services are open to any source (see header). Narrow only if allowed.
SERVICE_SRC="${SERVICE_SRC:-0.0.0.0/0}"

# Kali -> HTTPS (443) to these server last octets (always on)
KALI_HTTPS_TARGETS="${KALI_HTTPS_TARGETS:-10 15}"

# Optional narrow server egress (leave empty = none)
UPSTREAM_DNS="${UPSTREAM_DNS:-}"              # AD may query this resolver
NTP_SERVER="${NTP_SERVER:-}"                  # servers may sync time from this

# IPs/CIDRs the IPS must never ban (Kali, servers, Palo are added automatically)
WHITELIST="${WHITELIST:-}"
BAN_SECS="${BAN_SECS:-900}"                   # short bans: scoring IPs rotate
BAN_SEVERITY="${BAN_SEVERITY:-1}"             # ban only on severity <= this (1 = high)

# --- TOGGLES (defaults; saved values in $STATE_FILE override) -----------------
KALI_SCAN=1             # Kali may scan/reach the whole server LAN (competition task)
AUTOBAN=1               # IPS auto-ban on/off  (autoban on|off)
VYOS_OUT=0              # VyOS itself may reach internet 53/80/443/123 (apt etc.)
ALLOW_DHCP=0            # UDP 67 into VyOS (only if something on 172.17.0.0/24 uses VyOS DHCP)
ALLOW_VYOS_DNS=0        # DNS forwarding by VyOS for workstations (not needed: they use AD)
PERMISSIVE_BASELINE=0   # 1 = log+pass unclassified inbound (discovery)
FLUSH_CONNTRACK=1       # on apply: kill existing sessions (cuts running beacons)
STRICT_CONNTRACK=1      # drop mid-stream packets with no conntrack entry

mkdir -p "${BACKUP_DIR}" 2>/dev/null
[ -f "$STATE_FILE" ] && . "$STATE_FILE"

# --- ENVIRONMENT CHECKS -------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then echo "[!] Run as root (sudo $0 ...)"; exit 1; fi
command -v iptables >/dev/null 2>&1 || { echo "[!] iptables not found"; exit 1; }
modprobe nf_conntrack 2>/dev/null
modprobe ip_tables 2>/dev/null

# --- HELPERS ------------------------------------------------------------------
host_ip() { echo "${INT_NET}.$1"; }

set_state() {   # set_state KEY VALUE
    touch "$STATE_FILE"
    grep -v "^$1=" "$STATE_FILE" > "$STATE_FILE.tmp" 2>/dev/null
    echo "$1=$2" >> "$STATE_FILE.tmp"
    mv "$STATE_FILE.tmp" "$STATE_FILE"
}

validate_team() { case "$TEAM" in ''|*[!0-9]*) echo "[!] TEAM must be a number"; exit 1 ;; esac; }
detect_if() { ip -o -4 addr show | awk -v p="$1" 'index($4,p)==1 {print $2; exit}'; }

detect_ifs() {
    WKST_IF="${WKST_IF:-$(detect_if "$WKST_ADDR")}"
    INT_IF="${INT_IF:-$(detect_if "$INT_ADDR")}"
    EXT_IF="${EXT_IF:-$(detect_if "$EXT_ADDR")}"
    if [ -z "$WKST_IF" ] || [ -z "$INT_IF" ] || [ -z "$EXT_IF" ]; then
        echo "[!] Could not detect interfaces (wkst='$WKST_IF' int='$INT_IF' ext='$EXT_IF')."
        echo "    Run 'ip -br a', then e.g.  WKST_IF=eth1 INT_IF=eth0 EXT_IF=eth2 $0 apply"
        exit 1
    fi
}

have_ipset() { command -v ipset >/dev/null 2>&1; }
chain_exists() { iptables -n -L "$1" >/dev/null 2>&1; }
need_applied() { chain_exists BOX_EGRESS || { echo "[!] Run '$0 apply' first."; exit 1; }; }
ips_running() { [ -f "$SURICATA_PID" ] && kill -0 "$(cat "$SURICATA_PID" 2>/dev/null)" 2>/dev/null; }
onoff() { case "$1" in on|1) echo 1 ;; off|0) echo 0 ;; *) echo "[!] use on|off" >&2; exit 1 ;; esac; }

# Everything allowed in FORWARD jumps to IPS_ACCEPT (inspected by Suricata when
# it is running, plain ACCEPT otherwise). NFQUEUE is terminating so it goes last.
ACC="IPS_ACCEPT"

allow_tcp() { iptables -A FORWARD -s "$SERVICE_SRC" -d "$(host_ip "$1")" -p tcp -m multiport --dports "$2" -j $ACC; }
allow_udp() { iptables -A FORWARD -s "$SERVICE_SRC" -d "$(host_ip "$1")" -p udp -m multiport --dports "$2" -j $ACC; }

# --- PER-BOX OUTBOUND TABLE ---------------------------------------------------
# name:ip-or-cidr:default-mode      (names: letters/digits/underscore only)
# Workstations live in the server subnet, so their outbound is controlled here too.
build_boxes() {
    BOXES="kali:${KALI_IP}:off"
    BOXES="$BOXES ecom:$(host_ip $ECOM_ID):off email:$(host_ip $EMAIL_ID):off splunk:$(host_ip $SPLUNK_ID):off"
    BOXES="$BOXES ad:$(host_ip $AD_ID):off mssql:$(host_ip $MSSQL_ID):off"
    BOXES="$BOXES wkst_win:${WKST_WIN_IP}:web wkst_ubuntu:${WKST_UBUNTU_IP}:web"
}

box_mode() {    # box_mode name default
    eval "_m=\${EG_$1:-$2}"
    echo "$_m"
}

# Modes: off = nothing out | web = tcp 80,443,53 + udp 53 | all = any new connection
fill_box_egress() {
    iptables -F BOX_EGRESS
    for entry in $BOXES; do
        name=${entry%%:*}; rest=${entry#*:}; ip=${rest%%:*}; def=${rest#*:}
        mode=$(box_mode "$name" "$def")
        case "$mode" in
            all)
                iptables -A BOX_EGRESS -s "$ip" -o "$EXT_IF" -m conntrack --ctstate NEW -j $ACC ;;
            web)
                iptables -A BOX_EGRESS -s "$ip" -o "$EXT_IF" -p tcp -m multiport --dports 53,80,443 -m conntrack --ctstate NEW -j $ACC
                iptables -A BOX_EGRESS -s "$ip" -o "$EXT_IF" -p udp --dport 53 -m conntrack --ctstate NEW -j $ACC
                iptables -A BOX_EGRESS -s "$ip" -o "$EXT_IF" -m conntrack --ctstate NEW \
                    -m limit --limit 10/min -j LOG --log-prefix "FW-EG-DROP $name: "
                iptables -A BOX_EGRESS -s "$ip" -o "$EXT_IF" -m conntrack --ctstate NEW -j DROP ;;
            *)
                iptables -A BOX_EGRESS -s "$ip" -o "$EXT_IF" -m conntrack --ctstate NEW \
                    -m limit --limit 10/min -j LOG --log-prefix "FW-EG-DROP $name: "
                iptables -A BOX_EGRESS -s "$ip" -o "$EXT_IF" -m conntrack --ctstate NEW -j DROP ;;
        esac
    done
}

set_box_mode() {    # set_box_mode name mode
    set_state "EG_$1" "$2"
    eval "EG_$1=$2"
}

egress_list() {
    printf "%-4s %-14s %-18s %s\n" "#" "BOX" "IP" "OUTBOUND"
    n=0
    for entry in $BOXES; do
        n=$((n+1)); name=${entry%%:*}; rest=${entry#*:}; ip=${rest%%:*}; def=${rest#*:}
        printf "%-4s %-14s %-18s %s\n" "$n" "$name" "$ip" "$(box_mode "$name" "$def")"
    done
    echo "off = no outbound | web = DNS/HTTP/HTTPS | all = any outbound"
}

# Summarise what blocked boxes tried to reach: this exposes hidden dependencies
egress_report() {
    echo "Blocked outbound attempts (count  box  src  dst  proto  port) - sampled, 10/min per box"
    if command -v journalctl >/dev/null 2>&1; then SRC_LOG="journalctl -k --no-pager"; else SRC_LOG="dmesg"; fi
    $SRC_LOG 2>/dev/null | grep "FW-EG-DROP" | awk '{
        b=""; s=""; d=""; p=""; t="";
        for(i=1;i<=NF;i++){
            if($i=="FW-EG-DROP") b=$(i+1);
            if($i ~ /^SRC=/) s=$i; if($i ~ /^DST=/) d=$i;
            if($i ~ /^PROTO=/) p=$i; if($i ~ /^DPT=/) t=$i }
        print b, s, d, p, t }' | sort | uniq -c | sort -rn | head -40
}

egress_menu() {
    need_applied; detect_ifs
    while true; do
        echo; egress_list
        printf "Box number, 'a' = all boxes, 'r' = blocked-attempt report, 'q' = quit: "
        read SEL
        case "$SEL" in
            q|Q|'') break ;;
            r|R) egress_report; continue ;;
            a|A) PICK="ALL" ;;
            *[!0-9]*) echo "Invalid"; continue ;;
            *)  set -- $BOXES
                if [ "$SEL" -lt 1 ] || [ "$SEL" -gt "$#" ]; then echo "Invalid"; continue; fi
                eval "ENTRY=\${$SEL}"; PICK=${ENTRY%%:*} ;;
        esac
        printf "Mode for %s [off/web/all]: " "$PICK"; read M
        case "$M" in off|web|all) ;; *) echo "Invalid mode"; continue ;; esac
        if [ "$PICK" = "ALL" ]; then
            for entry in $BOXES; do set_box_mode "${entry%%:*}" "$M"; done
        else
            set_box_mode "$PICK" "$M"
        fi
        fill_box_egress
        echo "[+] Updated."
    done
}

# --- KALI ACCESS --------------------------------------------------------------
fill_kali_access() {
    iptables -F KALI_ACCESS
    # Palo Alto WAN IP: HTTPS (+ ping) only
    iptables -A KALI_ACCESS -s "$KALI_IP" -d "$PALO_FW_IP" -p icmp --icmp-type echo-request -j $ACC
    iptables -A KALI_ACCESS -s "$KALI_IP" -d "$PALO_FW_IP" -p tcp -m multiport --dports "$PALO_KALI_PORTS" -j $ACC
    # Palo mgmt + inside IPs: ping only (the scan rule below must not reach them)
    for d in "$PALO_MGMT" "$PALO_INSIDE"; do
        iptables -A KALI_ACCESS -s "$KALI_IP" -d "$d" -p icmp --icmp-type echo-request -j $ACC
        iptables -A KALI_ACCESS -s "$KALI_IP" -d "$d" -j DROP
    done
    # DNS to the DNS server (AD)
    iptables -A KALI_ACCESS -s "$KALI_IP" -d "$(host_ip $DNS_ID)" -p udp --dport 53 -j $ACC
    iptables -A KALI_ACCESS -s "$KALI_IP" -d "$(host_ip $DNS_ID)" -p tcp --dport 53 -j $ACC
    # HTTPS to chosen servers
    for id in $KALI_HTTPS_TARGETS; do
        iptables -A KALI_ACCESS -s "$KALI_IP" -d "$(host_ip "$id")" -p tcp --dport 443 -j $ACC
    done
    # Competition task: port scans of the environment
    if [ "$KALI_SCAN" = "1" ]; then
        iptables -A KALI_ACCESS -s "$KALI_IP" -d "$SERVER_SUBNET" -j $ACC
    fi
}

fill_vyos_out() {
    iptables -F VYOS_OUT
    if [ "$VYOS_OUT" = "1" ]; then
        iptables -A VYOS_OUT -o "$EXT_IF" -p tcp -m multiport --dports 53,80,443 -j ACCEPT
        iptables -A VYOS_OUT -o "$EXT_IF" -p udp -m multiport --dports 53,123 -j ACCEPT
    fi
}

fill_ips_accept() {
    iptables -F IPS_ACCEPT
    if ips_running; then
        iptables -A IPS_ACCEPT -j NFQUEUE --queue-num 0 --queue-bypass
    fi
    iptables -A IPS_ACCEPT -j ACCEPT
}

# --- SAVE / RESTORE / SHOW ----------------------------------------------------
show_rules() { echo "iptables backend: $(iptables -V)"; iptables -L -v -n --line-numbers; }

save_rules() {
    TARGET_FILE="${1:-$DEFAULT_BACKUP}"
    iptables-save > "${TARGET_FILE}" && echo "[+] Saved to ${TARGET_FILE}" || { echo "[!] Save failed"; exit 1; }
}

restore_rules() {
    TARGET_FILE="${1:-$DEFAULT_BACKUP}"
    [ -f "${TARGET_FILE}" ] || { echo "[!] '${TARGET_FILE}' does not exist"; exit 1; }
    printf "Restore rules from '%s'? (y/N): " "${TARGET_FILE}"
    read -r choice
    case "$choice" in
        y|Y)
            iptables-save > "${AUTO_PRE_RESTORE}"
            if iptables-restore < "${TARGET_FILE}"; then echo "[+] Restored."
            else echo "[!] Restore failed, reverting..."; iptables-restore < "${AUTO_PRE_RESTORE}"; exit 1; fi ;;
        *) echo "Cancelled." ;;
    esac
}

clear_filter_rules() {
    iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT
    iptables -F; iptables -X; iptables -Z
}

# --- IPv6: blocked everywhere ---------------------------------------------------
ipv6_lockdown() {
    sysctl -qw net.ipv6.conf.all.disable_ipv6=1 \
               net.ipv6.conf.default.disable_ipv6=1 \
               net.ipv6.conf.all.forwarding=0 2>/dev/null
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP; ip6tables -P OUTPUT DROP
        ip6tables -F; ip6tables -X
        ip6tables -A INPUT -i lo -j ACCEPT
        ip6tables -A OUTPUT -o lo -j ACCEPT
        echo "[+] IPv6 blocked (ip6tables policies DROP, sysctl disable_ipv6=1)"
    else
        echo "[!] ip6tables not found: IPv6 only disabled via sysctl (re-run apply if a config commit re-enables it)."
    fi
}

# --- MAIN FIREWALL ------------------------------------------------------------
apply_firewall() {
    validate_team
    detect_ifs
    build_boxes
    PUB_NET="172.25.$((20 + TEAM)).0/24"
    echo "[+] servers ${SERVER_SUBNET} | public ${PUB_NET} | wkst_if=${WKST_IF} int_if=${INT_IF} ext_if=${EXT_IF}"
    echo "[+] SSH to VyOS allowed only from ${SSH_SRC} on ${WKST_IF}"

    clear_filter_rules > /dev/null 2>&1

    sysctl -qw net.ipv4.tcp_syncookies=1 \
               net.ipv4.conf.all.accept_redirects=0 \
               net.ipv4.conf.all.send_redirects=0 \
               net.ipv4.conf.all.accept_source_route=0 2>/dev/null
    [ "$STRICT_CONNTRACK" = "1" ] && sysctl -qw net.netfilter.nf_conntrack_tcp_loose=0 2>/dev/null

    ipv6_lockdown

    iptables -N BOX_EGRESS
    iptables -N KALI_ACCESS
    iptables -N VYOS_OUT
    iptables -N IPS_ACCEPT

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # ---------------- INPUT: the router itself --------------------------------
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i "$WKST_IF" -s "$SSH_SRC" -p tcp --dport 22 -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-name vyos_ssh --hashlimit-mode srcip \
        --hashlimit-above 10/minute --hashlimit-burst 6 -j DROP
    iptables -A INPUT -i "$WKST_IF" -s "$SSH_SRC" -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A INPUT -i "$WKST_IF" -s "$SSH_SRC" -p icmp --icmp-type echo-request -j ACCEPT
    if [ "$ALLOW_DHCP" = "1" ]; then
        iptables -A INPUT -i "$WKST_IF" -p udp --dport 67 -j ACCEPT
    fi
    if [ "$ALLOW_VYOS_DNS" = "1" ]; then
        iptables -A INPUT -i "$WKST_IF" -s "$WKST_NET" -p udp --dport 53 -j ACCEPT
        iptables -A INPUT -i "$WKST_IF" -s "$WKST_NET" -p tcp --dport 53 -j ACCEPT
    fi
    iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "FW-VYOS-IN-DROP: "

    # ---------------- OUTPUT: VyOS itself cannot beacon -----------------------
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -o "$WKST_IF" -d "$SSH_SRC" -p icmp -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    if [ "$ALLOW_DHCP" = "1" ]; then
        iptables -A OUTPUT -o "$WKST_IF" -p udp --sport 67 --dport 68 -j ACCEPT
    fi
    if [ "$ALLOW_VYOS_DNS" = "1" ]; then
        iptables -A OUTPUT -o "$WKST_IF" -p udp --sport 53 -j ACCEPT
    fi
    iptables -A OUTPUT -j VYOS_OUT
    iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "FW-VYOS-OUT-DROP: "

    # ---------------- FORWARD --------------------------------------------------
    # 1. banned attackers (filled by the IPS auto-ban)
    if have_ipset; then
        ipset create lab_block hash:ip timeout "$BAN_SECS" -exist
        iptables -A FORWARD -m set --match-set lab_block src -j DROP
    fi
    # 2. invalid / established (established is inspected by the IPS too)
    iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j $ACC
    # 3. Kali (before the flood limits so port scans are not throttled)
    iptables -A FORWARD -s "$KALI_IP" -j KALI_ACCESS
    # 4. (workstations and AD share the 172.20.240.0/24 LAN, so their DNS to AD
    #    never crosses VyOS; nothing to allow here)
    # 5. ICMP: echo only, rate limited toward servers; Kali may ping out
    iptables -A FORWARD -d "$SERVER_SUBNET" -p icmp --icmp-type echo-request \
        -m hashlimit --hashlimit-name srv_icmp --hashlimit-mode srcip \
        --hashlimit-above 20/second --hashlimit-burst 40 -j DROP
    iptables -A FORWARD -d "$SERVER_SUBNET" -p icmp --icmp-type echo-request -j $ACC
    iptables -A FORWARD -s "$KALI_IP" -p icmp --icmp-type echo-request -j $ACC
    # 6. untranslated public range = no port-forward matched
    iptables -A FORWARD -d "${PUB_NET}" -j DROP
    # 7. flood protection toward servers (per source IP)
    iptables -A FORWARD -d "$SERVER_SUBNET" -p tcp --syn -m connlimit --connlimit-above 200 --connlimit-mask 32 -j DROP
    iptables -A FORWARD -d "$SERVER_SUBNET" -p tcp --dport 22 -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-name srv_ssh --hashlimit-mode srcip \
        --hashlimit-above 30/minute --hashlimit-burst 10 -j DROP
    iptables -A FORWARD -d "$SERVER_SUBNET" -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-name srv_new --hashlimit-mode srcip \
        --hashlimit-above 100/second --hashlimit-burst 200 -j DROP
    # 8. Palo Alto: nobody except Kali (handled above) may touch any Palo IP
    for d in "$PALO_FW_IP" "$PALO_MGMT" "$PALO_INSIDE"; do
        iptables -A FORWARD -d "$d" -m limit --limit 5/min -j LOG --log-prefix "FW-PALO-DENIED: "
        iptables -A FORWARD -d "$d" -j DROP
    done
    # 9. published services (any source - scoring IPs rotate)
    allow_tcp "$ECOM_ID"   "80,443"
    allow_tcp "$EMAIL_ID"  "25,22,143,443,80"
    allow_tcp "$SPLUNK_ID" "22,8000,8089,9997"
    allow_udp "$SPLUNK_ID" "123"
    allow_tcp "$AD_ID"     "5985,5986"
    allow_udp "$AD_ID"     "53"
    allow_tcp "$MSSQL_ID"  "3389,445,1433"
    # 10. narrow server egress
    if [ -n "$UPSTREAM_DNS" ]; then
        iptables -A FORWARD -s "$(host_ip "$AD_ID")" -d "$UPSTREAM_DNS" -p udp --dport 53 -m conntrack --ctstate NEW -j $ACC
        iptables -A FORWARD -s "$(host_ip "$AD_ID")" -d "$UPSTREAM_DNS" -p tcp --dport 53 -m conntrack --ctstate NEW -j $ACC
    fi
    if [ -n "$NTP_SERVER" ]; then
        iptables -A FORWARD -s "$SERVER_SUBNET" -d "$NTP_SERVER" -p udp --dport 123 -m conntrack --ctstate NEW -j $ACC
    fi
    # 11. per-box outbound (off | web | all)
    iptables -A FORWARD -j BOX_EGRESS
    # 12. catch-alls: anything else new from servers / workstations is blocked+logged
    iptables -A FORWARD -s "$SERVER_SUBNET" -m conntrack --ctstate NEW \
        -m limit --limit 20/min -j LOG --log-prefix "FW-C2-EGRESS-BLOCK: "
    iptables -A FORWARD -s "$SERVER_SUBNET" -m conntrack --ctstate NEW -j DROP
    iptables -A FORWARD -s "$WKST_NET" -o "$EXT_IF" -m conntrack --ctstate NEW -j DROP
    # 13. tail
    if [ "$PERMISSIVE_BASELINE" = "1" ]; then
        echo "[!] PERMISSIVE BASELINE: logging & passing unclassified inbound traffic"
        iptables -A FORWARD -m conntrack --ctstate NEW -m limit --limit 10/min -j LOG --log-prefix "FW-BASELINE-PASS: "
        iptables -A FORWARD -j $ACC
    else
        iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "FW-FORWARD-DROPPED: "
        iptables -A FORWARD -j DROP
    fi

    fill_kali_access
    fill_box_egress
    fill_vyos_out
    fill_ips_accept

    if [ "$FLUSH_CONNTRACK" = "1" ]; then
        if command -v conntrack >/dev/null 2>&1; then conntrack -F >/dev/null 2>&1
        else echo f > /proc/net/nf_conntrack 2>/dev/null; fi
        echo "[+] Conntrack flushed (existing sessions reset)."
    fi

    echo "[+] Firewall loaded. ips=$(ips_running && echo on || echo off)  kali-scan=$KALI_SCAN  autoban=$AUTOBAN"
    egress_list
    echo "[i] Not persistent. Copy this script to /config/scripts/ and add to /config/scripts/vyos-postconfig-bootup.script:"
    echo "    /config/scripts/$(basename "$0") apply $TEAM   then   /config/scripts/$(basename "$0") ips start"
}

# --- IPS (Suricata inline via NFQUEUE) ----------------------------------------
ips_write_rules() {
    mkdir -p "$IPS_DIR"
    cat > "$IPS_RULES" <<'EOF'
# Local rules. HOME_NET = server subnet (private, post-NAT).
drop tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"LOCAL SSH brute force"; flow:to_server; flags:S; threshold:type both, track by_src, count 20, seconds 60; classtype:attempted-admin; priority:1; sid:9000001; rev:1;)
drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL log4shell in URI"; flow:established,to_server; http.uri; content:"${jndi:"; nocase; classtype:web-application-attack; priority:1; sid:9000002; rev:1;)
drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL log4shell in header"; flow:established,to_server; http.header; content:"${jndi:"; nocase; classtype:web-application-attack; priority:1; sid:9000003; rev:1;)
drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL shellshock"; flow:established,to_server; http.header; content:"() {"; classtype:web-application-attack; priority:1; sid:9000004; rev:1;)
drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL path traversal"; flow:established,to_server; http.uri; content:"../.."; classtype:web-application-attack; priority:1; sid:9000005; rev:1;)
drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL command injection in URI"; flow:established,to_server; http.uri; pcre:"/(?:;|\||%3b|%7c|`)(?:\s|%20|\+)*(?:wget|curl|nc|bash|sh|python|perl)\b/i"; classtype:web-application-attack; priority:1; sid:9000006; rev:1;)
drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL reverse shell output (id)"; flow:established,to_server; content:"uid="; content:"gid="; distance:0; classtype:trojan-activity; priority:1; sid:9000010; rev:1;)
drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL reverse shell bash -i"; flow:established,to_server; content:"bash -i"; classtype:trojan-activity; priority:1; sid:9000011; rev:1;)
EOF
    echo "[+] Wrote $IPS_RULES"
}

ips_deps() {
    MISSING=""
    for c in suricata ipset jq; do command -v $c >/dev/null 2>&1 || MISSING="$MISSING $c"; done
    if [ -n "$MISSING" ]; then
        echo "[!] Missing:$MISSING"
        echo "    $0 vyos-out on ; apt update && apt install -y suricata ipset jq conntrack ; $0 vyos-out off"
        return 1
    fi
}

ips_allowlist() {
    have_ipset || return
    ipset create lab_allow hash:net -exist
    for ip in "$SERVER_SUBNET" "$KALI_IP" "$PALO_FW_IP" "$PALO_MGMT" "172.17.0.1" "172.16.0.254" $WHITELIST; do
        ipset add lab_allow "$ip" -exist
    done
}

ips_start() {
    need_applied
    ips_deps || exit 1
    ips_running && { echo "[i] Suricata already running"; return; }
    [ -f "$IPS_RULES" ] || ips_write_rules
    ipset create lab_block hash:ip timeout "$BAN_SECS" -exist
    ips_allowlist
    if ! suricata -T -c /etc/suricata/suricata.yaml -s "$IPS_RULES" \
         --set vars.address-groups.HOME_NET="[${SERVER_SUBNET}]" >/tmp/suricata-test.log 2>&1; then
        echo "[!] Suricata config test failed, see /tmp/suricata-test.log"; exit 1
    fi
    suricata -c /etc/suricata/suricata.yaml -q 0 -D --pidfile "$SURICATA_PID" -s "$IPS_RULES" \
        --set vars.address-groups.HOME_NET="[${SERVER_SUBNET}]"
    sleep 3
    if ips_running; then
        fill_ips_accept
        echo "[+] Suricata inline (NFQUEUE 0, fail-open via --queue-bypass)"
        ban_start
    else
        echo "[!] Suricata failed to start. Check /var/log/suricata/suricata.log"; exit 1
    fi
}

ips_stop() {
    ban_stop
    [ -f "$SURICATA_PID" ] && kill "$(cat "$SURICATA_PID")" 2>/dev/null
    sleep 1
    fill_ips_accept
    echo "[+] IPS stopped; traffic passes uninspected."
}

# Auto-ban: alert with severity <= BAN_SEVERITY -> source IP into ipset lab_block.
# Never bans anything in lab_allow. Honors `autoban off` live (re-reads state).
ban_loop() {
    tail -n0 -F "$EVE_LOG" 2>/dev/null \
      | jq --unbuffered -r --argjson sev "$BAN_SEVERITY" 'select(.event_type=="alert" and .alert.severity<=$sev) | .src_ip' \
      | while read -r ip; do
            [ -z "$ip" ] && continue
            [ -f "$STATE_FILE" ] && . "$STATE_FILE"
            [ "${AUTOBAN:-1}" = "1" ] || continue
            ipset test lab_allow "$ip" 2>/dev/null && continue
            if ipset add lab_block "$ip" timeout "$BAN_SECS" -exist 2>/dev/null; then
                logger -t lab-ips "banned $ip for ${BAN_SECS}s"
                command -v conntrack >/dev/null 2>&1 && conntrack -D -s "$ip" >/dev/null 2>&1
            fi
        done
}

ban_start() {
    if [ -f "$BAN_PID" ] && kill -0 "$(cat "$BAN_PID")" 2>/dev/null; then return; fi
    nohup "$0" _banloop >/dev/null 2>&1 &
    echo $! > "$BAN_PID"
    echo "[+] Auto-ban loop running (severity<=${BAN_SEVERITY}, bans last ${BAN_SECS}s)"
}

ban_stop() {
    if [ -f "$BAN_PID" ]; then
        pkill -P "$(cat "$BAN_PID")" 2>/dev/null
        kill "$(cat "$BAN_PID")" 2>/dev/null
        rm -f "$BAN_PID"
    fi
    pkill -f "tail -n0 -F $EVE_LOG" 2>/dev/null
}

status() {
    build_boxes
    echo "kali-scan: $KALI_SCAN   autoban: $AUTOBAN   vyos-out: $VYOS_OUT   dhcp: $ALLOW_DHCP   SSH from: $SSH_SRC"
    echo "suricata : $(ips_running && echo RUNNING || echo stopped)"
    echo "ipv6     : $(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null | sed 's/1/disabled/;s/0/ENABLED/')  ip6tables FORWARD policy: $(ip6tables -S FORWARD 2>/dev/null | head -n1)"
    have_ipset && echo "banned IPs: $(ipset list lab_block 2>/dev/null | awk '/^Number of entries/ {print $4}')"
    echo; egress_list
}

# --- INTERACTIVE RULE GENERATOR -----------------------------------------------
interactive_rule_generator() {
    echo "=== Interactive iptables Rule Generator (Multiport) ==="
    while true; do
        echo; echo "Chain: 1) INPUT  2) OUTPUT  3) FORWARD"
        printf "Selection [1-3]: "; read CHOICE
        case "$CHOICE" in 1) CHAIN="INPUT" ;; 2) CHAIN="OUTPUT" ;; 3) CHAIN="FORWARD" ;; *) echo "Invalid"; continue ;; esac
        iptables -L "$CHAIN" -v -n --line-numbers | head -n 12
        printf "Line number to INSERT at (blank = APPEND): "; read POS
        if [ -z "$POS" ]; then TARGET_ACTION="-A $CHAIN"
        else case "$POS" in *[!0-9]*) echo "Invalid position"; continue ;; *) TARGET_ACTION="-I $CHAIN $POS" ;; esac; fi
        printf "IP (PRIVATE 172.20.240.x for FORWARD): "; read IPADDR
        [ -z "$IPADDR" ] && { echo "IP required"; continue; }
        printf "Protocol (tcp/udp): "; read PROTO; PROTO=$(echo "$PROTO" | tr 'A-Z' 'a-z')
        [ "$PROTO" = "tcp" ] || [ "$PROTO" = "udp" ] || { echo "tcp or udp"; continue; }
        printf "IP is source or destination? (s/d): "; read DIR
        case "$DIR" in s) IPFLAG="-s $IPADDR" ;; d) IPFLAG="-d $IPADDR" ;; *) echo "s or d"; continue ;; esac
        echo "1) Single port  2) Multiple ports"; printf "Choice: "; read PORTMODE
        if [ "$PORTMODE" = "1" ]; then
            printf "Port: "; read PORT
            case "$PORT" in ''|*[!0-9]*) echo "Invalid"; continue ;; esac
            MODULES=""; PORTFLAG="--dport $PORT"
        elif [ "$PORTMODE" = "2" ]; then
            printf "Ports (22,80,443): "; read PORTS
            case "$PORTS" in ''|*[!0-9,]*) echo "Invalid"; continue ;; esac
            MODULES="-m multiport"; PORTFLAG="--dports $PORTS"
        else echo "Invalid"; continue; fi
        CMD="iptables $TARGET_ACTION -p $PROTO $MODULES $IPFLAG $PORTFLAG -j ACCEPT"
        echo "Executing: $CMD"
        if $CMD; then echo "[+] Added"; iptables -L "$CHAIN" -v -n --line-numbers
        else echo "ERROR: failed"; fi
        printf "Add another? (y/n): "; read AGAIN
        case "$AGAIN" in y|Y) ;; *) break ;; esac
    done
}

# --- CLI ----------------------------------------------------------------------
build_boxes
case "$1" in
    apply)    [ -n "$2" ] && TEAM="$2"; apply_firewall ;;
    strict)   PERMISSIVE_BASELINE=0; [ -n "$2" ] && TEAM="$2"; apply_firewall ;;
    baseline) PERMISSIVE_BASELINE=1; [ -n "$2" ] && TEAM="$2"; apply_firewall ;;

    egress)
        need_applied; detect_ifs
        case "$2" in
            '')     egress_menu ;;
            list)   egress_list ;;
            report) egress_report ;;
            *)
                case "$3" in off|web|all) ;; *) echo "Usage: $0 egress <box|all> <off|web|all>"; exit 1 ;; esac
                if [ "$2" = "all" ]; then
                    for entry in $BOXES; do set_box_mode "${entry%%:*}" "$3"; done
                else
                    FOUND=0
                    for entry in $BOXES; do [ "${entry%%:*}" = "$2" ] && FOUND=1; done
                    [ "$FOUND" = "1" ] || { echo "[!] Unknown box '$2'"; egress_list; exit 1; }
                    set_box_mode "$2" "$3"
                fi
                fill_box_egress; egress_list ;;
        esac ;;
    internet)  V=$(onoff "$2"); need_applied; detect_ifs
               [ "$V" = "1" ] && M=web || M=off
               set_box_mode kali "$M"; fill_box_egress; echo "[+] Kali outbound: $M" ;;
    updates)   V=$(onoff "$2"); need_applied; detect_ifs
               [ "$V" = "1" ] && M=web || M=off
               for b in ecom email splunk ad mssql; do set_box_mode "$b" "$M"; done
               fill_box_egress; echo "[+] Server outbound: $M (a C2 channel while on)" ;;
    kali-scan) V=$(onoff "$2"); need_applied; detect_ifs
               KALI_SCAN=$V; set_state KALI_SCAN "$V"; fill_kali_access; echo "[+] Kali scan access to server LAN: $2" ;;
    autoban)   V=$(onoff "$2"); AUTOBAN=$V; set_state AUTOBAN "$V"; echo "[+] Auto-ban: $2" ;;
    vyos-out)  V=$(onoff "$2"); need_applied; detect_ifs
               VYOS_OUT=$V; set_state VYOS_OUT "$V"; fill_vyos_out; echo "[+] VyOS outbound (53/80/443/123): $2" ;;

    ips)
        case "$2" in
            setup)  ips_write_rules ;;
            start)  ips_start ;;
            stop)   need_applied; ips_stop ;;
            status) status ;;
            *) echo "Usage: $0 ips {setup|start|stop|status}"; exit 1 ;;
        esac ;;
    ban)       have_ipset || { echo "[!] ipset missing"; exit 1; }
               ipset create lab_block hash:ip timeout "$BAN_SECS" -exist
               ipset add lab_block "$2" timeout "${3:-$BAN_SECS}" -exist && echo "[+] banned $2" ;;
    unban)     ipset del lab_block "$2" && echo "[+] unbanned $2" ;;
    unban-all) ipset flush lab_block && echo "[+] all bans cleared" ;;
    bans)      ipset list lab_block ;;
    _banloop)  ban_loop ;;
    status)    status ;;
    add|interactive) interactive_rule_generator ;;
    save)      save_rules "$2" ;;
    restore|rollback) restore_rules "$2" ;;
    clear)
        printf "Clear iptables FILTER rules (policies go ACCEPT)? (y/N): "; read -r choice
        case "$choice" in y|Y) ips_running && ban_stop; clear_filter_rules; echo "[+] Cleared." ;; *) echo "Aborted." ;; esac ;;
    show)      show_rules ;;
    *)
        echo "Usage: sudo $0 <command> [arg]"
        echo "  apply [TEAM#] | strict [TEAM#] | baseline [TEAM#]   load the firewall"
        echo "  egress                      interactive per-box outbound menu (off/web/all)"
        echo "  egress <box|all> <mode>     set one box, e.g.  egress ad web"
        echo "  egress list | egress report show modes | what blocked boxes tried to reach"
        echo "  internet on|off             shortcut: Kali outbound web"
        echo "  updates on|off              shortcut: all servers outbound web"
        echo "  kali-scan on|off            Kali access to the whole server LAN"
        echo "  vyos-out on|off             temporary VyOS outbound (apt install etc.)"
        echo "  ips setup|start|stop|status Suricata inline IPS + auto-ban"
        echo "  autoban on|off | ban IP [secs] | unban IP | unban-all | bans"
        echo "  status | show | add | save [f] | restore [f] | clear"
        echo "Env: TEAM SSH_SRC KALI_IP WKST_WIN_IP WKST_UBUNTU_IP WHITELIST UPSTREAM_DNS NTP_SERVER"
        echo "     WKST_IF INT_IF EXT_IF KALI_HTTPS_TARGETS BAN_SECS BAN_SEVERITY"
        exit 1 ;;
esac