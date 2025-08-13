#!/usr/bin/env bash
set -euo pipefail

# ========= Pretty output =========
RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; CYAN="\e[36m"; RESET="\e[0m"
say() { echo -e "${CYAN}[*]${RESET} $*"; }
ok()  { echo -e "${GREEN}[ok]${RESET} $*"; }
warn(){ echo -e "${YELLOW}[!]${RESET} $*"; }
err() { echo -e "${RED}[x]${RESET} $*"; }

# ========= Helpers =========
valid_ip() {
  local ip=$1
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<<"$ip"
  for n in $a $b $c $d; do [[ $n -ge 0 && $n -le 255 ]] || return 1; done
  return 0
}
valid_cidr() { [[ "$1" =~ ^([0-9]|[12][0-9]|3[0-2])$ ]]; }
ip_to_int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24) + (b<<16) + (c<<8) + d )); }
int_to_ip() { printf "%d.%d.%d.%d" $(( ($1>>24)&255 )) $(( ($1>>16)&255 )) $(( ($1>>8)&255 )) $(( $1&255 )); }
cidr_netmask() { local m=$1; local n=$(( 0xffffffff << (32-m) & 0xffffffff )); int_to_ip $n; }
in_subnet() { # ip cidr_ip cidr
  local ipi=$(ip_to_int "$1"); local neti=$(ip_to_int "$2")
  local maski=$(( 0xffffffff << (32-$3) & 0xffffffff ))
  [[ $(( ipi & maski )) -eq $(( neti & maski )) ]]
}
range_valid_in_subnet() { # start end gw /mask
  local start=$1 end=$2 gw=$3 mask=$4
  valid_ip "$start" && valid_ip "$end" && valid_ip "$gw" && valid_cidr "$mask" || return 1
  in_subnet "$start" "$gw" "$mask" && in_subnet "$end" "$gw" "$mask" || return 1
  # start <= end
  [[ $(ip_to_int "$start") -le $(ip_to_int "$end") ]]
}
strong_password() {
  local p=$1
  [[ ${#p} -ge 12 && "$p" =~ [a-z] && "$p" =~ [A-Z] && "$p" =~ [0-9] && "$p" =~ [^a-zA-Z0-9] ]]
}

# ========= Discover interfaces =========
say "Available network interfaces:"
while IFS= read -r line; do
  ifname=$(awk -F': ' '{print $2}' <<<"$line")
  mac=$(cat "/sys/class/net/$ifname/address" 2>/dev/null || echo "unknown")
  echo "  - $ifname  (MAC: $mac)"
done < <(ip -o link show | sort -k2)

# ========= Gather inputs =========
read -rp "Hostname for this firewall: " HOSTNAME

read -rp "WAN interface name (e.g., eth0): " WAN_IF
read -rp "WAN type [Static/DHCP/PPPoE]: " WAN_TYPE
WAN_TYPE=$(tr '[:upper:]' '[:lower:]' <<<"$WAN_TYPE")

WAN_IP=""; WAN_CIDR=""; WAN_GW=""; WAN_DNS=""; PPP_USER=""; PPP_PASS=""
case "$WAN_TYPE" in
  static)
    while true; do read -rp "Static IP (e.g., 10.10.10.11): " WAN_IP; valid_ip "$WAN_IP" && break || err "Invalid IP"; done
    while true; do read -rp "Netmask CIDR (e.g., 24): " WAN_CIDR; valid_cidr "$WAN_CIDR" && break || err "Invalid CIDR"; done
    while true; do read -rp "Gateway: " WAN_GW; valid_ip "$WAN_GW" && break || err "Invalid GW"; done
    while true; do read -rp "DNS Server: " WAN_DNS; valid_ip "$WAN_DNS" && break || err "Invalid DNS"; done
    ;;
  dhcp)
    ok "WAN will use DHCPv4"
    ;;
  pppoe)
    read -rp "PPPoE username: " PPP_USER
    read -rsp "PPPoE password: " PPP_PASS; echo
    # Upstream DNS for forwarding (optional)
    while true; do read -rp "Upstream DNS server for forwarding (e.g., 1.1.1.1): " WAN_DNS; valid_ip "$WAN_DNS" && break || err "Invalid DNS"; done
    ;;
  *) err "WAN type must be Static/DHCP/PPPoE"; exit 1;;
esac

read -rp "LAN interface name (e.g., eth1): " LAN_IF

LAN_IP=""; LAN_CIDR=""
while true; do read -rp "LAN gateway IP (e.g., 192.168.25.1): " LAN_IP; valid_ip "$LAN_IP" && break || err "Invalid IP"; done
while true; do read -rp "LAN netmask CIDR (e.g., 24): " LAN_CIDR; valid_cidr "$LAN_CIDR" && break || err "Invalid CIDR"; done

# DHCP on LAN?
read -rp "Run DHCP server on LAN? [yes/no]: " DHCP_LAN
DHCP_LAN=$(tr '[:upper:]' '[:lower:]' <<<"$DHCP_LAN")
LAN_DHCP_START=""; LAN_DHCP_END=""
if [[ "$DHCP_LAN" == "yes" ]]; then
  while true; do read -rp "DHCP start IP (e.g., 192.168.25.101): " LAN_DHCP_START; valid_ip "$LAN_DHCP_START" && break || err "Invalid IP"; done
  while true; do read -rp "DHCP end IP (e.g., 192.168.25.200): " LAN_DHCP_END; valid_ip "$LAN_DHCP_END" && break || err "Invalid IP"; done
  range_valid_in_subnet "$LAN_DHCP_START" "$LAN_DHCP_END" "$LAN_IP" "$LAN_CIDR" || { err "DHCP range not in LAN subnet or start>end"; exit 1; }
fi

# VLANs (repeat)
declare -a VLAN_IDS VLAN_DESC VLAN_IPS VLAN_CIDRS VLAN_DHCP_START VLAN_DHCP_END
say "Add VLANs on $LAN_IF (optional)."
while true; do
  read -rp "Add a VLAN? [yes/no]: " ADDV; ADDV=$(tr '[:upper:]' '[:lower:]' <<<"$ADDV")
  [[ "$ADDV" == "yes" ]] || break
  read -rp "  VLAN ID (e.g., 100): " vid
  read -rp "  Description: " vdesc
  # Ask if we set IP/Netmask (for DHCP/DNS redirection)
  read -rp "  Assign gateway IP/netmask on VLAN $vid? [yes/no]: " have_ip; have_ip=$(tr '[:upper:]' '[:lower:]' <<<"$have_ip")
  if [[ "$have_ip" == "yes" ]]; then
    while true; do read -rp "  VLAN $vid gateway IP: " vip; valid_ip "$vip" && break || err "Invalid IP"; done
    while true; do read -rp "  VLAN $vid netmask CIDR: " vmask; valid_cidr "$vmask" && break || err "Invalid CIDR"; done
    # DHCP?
    read -rp "  DHCP on VLAN $vid? [yes/no]: " vdhcp; vdhcp=$(tr '[:upper:]' '[:lower:]' <<<"$vdhcp")
    if [[ "$vdhcp" == "yes" ]]; then
      while true; do read -rp "    DHCP start IP: " vds; valid_ip "$vds" && break || err "Invalid IP"; done
      while true; do read -rp "    DHCP end IP: " vde; valid_ip "$vde" && break || err "Invalid IP"; done
      range_valid_in_subnet "$vds" "$vde" "$vip" "$vmask" || { err "DHCP range invalid for VLAN $vid"; exit 1; }
    else vds=""; vde=""; fi
  else
    vip=""; vmask=""; vds=""; vde=""
  fi
  VLAN_IDS+=("$vid"); VLAN_DESC+=("$vdesc"); VLAN_IPS+=("$vip"); VLAN_CIDRS+=("$vmask"); VLAN_DHCP_START+=("$vds"); VLAN_DHCP_END+=("$vde")
done

# Admin user
while true; do
  read -rp "Admin username (not 'admin' or 'vyos'): " ADMIN_USER
  [[ "$ADMIN_USER" != "admin" && "$ADMIN_USER" != "vyos" && -n "$ADMIN_USER" ]] && break || err "Invalid username"
done
while true; do
  read -rsp "Admin password (min 12 chars, upper/lower/number/special): " ADMIN_PASS; echo
  strong_password "$ADMIN_PASS" && break || err "Weak password"
done

# ========= Build config.boot =========
OUT="config.boot"
say "Generating $OUT ..."

# Decide WAN egress iface for NAT
WAN_EGRESS_IF="$WAN_IF"
[[ "$WAN_TYPE" == "pppoe" ]] && WAN_EGRESS_IF="pppoe0"

{
echo "system {"
echo "  host-name $HOSTNAME"
echo "  time-zone Asia/Kolkata"
echo "  login {"
echo "    user $ADMIN_USER {"
echo "      authentication {"
echo "        plaintext-password \"$ADMIN_PASS\""
echo "      }"
echo "      level admin"
echo "    }"
echo "  }"
# set system resolver to upstream (helps box resolve even if dns-forwarding down)
[[ -n "$WAN_DNS" ]] && echo "  name-server $WAN_DNS"
echo "  syslog {"
echo "    global { facility all { level notice } facility kern { level info } }"
echo "    file firewall.log { facility kern { level info } }"
echo "  }"
echo "  config-management { commit-revisions 20 }"
echo "}"

echo "interfaces {"
# WAN
if [[ "$WAN_TYPE" == "static" ]]; then
  echo "  ethernet $WAN_IF {"
  echo "    description WAN"
  echo "    address $WAN_IP/$WAN_CIDR"
  echo "    firewall { in { name WAN-IN } local { name WAN-LOCAL } }"
  echo "  }"
elif [[ "$WAN_TYPE" == "dhcp" ]]; then
  echo "  ethernet $WAN_IF {"
  echo "    description WAN"
  echo "    dhcpv4 { client-id }"
  echo "    firewall { in { name WAN-IN } local { name WAN-LOCAL } }"
  echo "  }"
else
  # PPPoE over $WAN_IF
  echo "  ethernet $WAN_IF { description WAN pppoe 0 { default-route auto user-id \"$PPP_USER\" password \"$PPP_PASS\" }"
  echo "    firewall { in { name WAN-IN } local { name WAN-LOCAL } }"
  echo "  }"
fi

# LAN
echo "  ethernet $LAN_IF {"
echo "    description LAN"
echo "    address $LAN_IP/$LAN_CIDR"
echo "    firewall { local { name LAN-LOCAL } out { name LAN-OUT } }"
# VLAN subinterfaces
for i in "${!VLAN_IDS[@]}"; do
  vid="${VLAN_IDS[$i]}"; vdesc="${VLAN_DESC[$i]}"; vip="${VLAN_IPS[$i]}"; vmask="${VLAN_CIDRS[$i]}"
  echo "    vif $vid { description \"$vdesc\""
  if [[ -n "$vip" && -n "$vmask" ]]; then
    echo "      address $vip/$vmask"
    echo "      firewall { local { name LAN-LOCAL } out { name LAN-OUT } }"
  fi
  echo "    }"
done
echo "  }"
echo "}"

# Default route
echo "protocols {"
echo "  static {"
if [[ "$WAN_TYPE" == "static" ]]; then
  echo "    route 0.0.0.0/0 { next-hop $WAN_GW }"
elif [[ "$WAN_TYPE" == "dhcp" ]]; then
  echo "    # Default route via DHCP on $WAN_IF (installed dynamically)"
else
  echo "    # Default route via PPPoE"
fi
echo "  }"
echo "}"

# Services: DHCP & DNS forwarding
echo "service {"
# DHCP LAN
if [[ "$DHCP_LAN" == "yes" ]]; then
  echo "  dhcp-server {"
  echo "    shared-network-name LAN {"
  echo "      authoritative"
  echo "      subnet $(ipcalc -nb "$LAN_IP/$LAN_CIDR" 2>/dev/null | awk '/Network:/ {print $2}' || echo "$LAN_IP/$LAN_CIDR") {"
  echo "        default-router $LAN_IP"
  echo "        dns-server $LAN_IP"
  echo "        range 0 { start $LAN_DHCP_START; stop $LAN_DHCP_END }"
  echo "      }"
  echo "    }"
  # DHCP VLANs with IP+range
  for i in "${!VLAN_IDS[@]}"; do
    vid="${VLAN_IDS[$i]}"; vip="${VLAN_IPS[$i]}"; vmask="${VLAN_CIDRS[$i]}"; vds="${VLAN_DHCP_START[$i]}"; vde="${VLAN_DHCP_END[$i]}"
    [[ -n "$vip" && -n "$vmask" && -n "$vds" && -n "$vde" ]] || continue
    echo "    shared-network-name VLAN$vid {"
    echo "      authoritative"
    echo "      subnet $(ipcalc -nb "$vip/$vmask" 2>/dev/null | awk '/Network:/ {print $2}' || echo "$vip/$vmask") {"
    echo "        default-router $vip"
    echo "        dns-server $vip"
    echo "        range 0 { start $vds; stop $vde }"
    echo "      }"
    echo "    }"
  done
  echo "  }"
fi

# DNS forwarding (listen on all gateway IPs; forward to upstream)
echo "  dns {"
echo "    forwarding {"
echo "      listen-address $LAN_IP"
[[ -n "$WAN_DNS" ]] && echo "      name-server $WAN_DNS"
# Add per-VLAN listeners
for i in "${!VLAN_IDS[@]}"; do
  vip="${VLAN_IPS[$i]}"; vmask="${VLAN_CIDRS[$i]}"
  [[ -n "$vip" && -n "$vmask" ]] && echo "      listen-address $vip"
done
echo "      cache-size 300"
echo "      allow-from $(cut -d. -f1-3 <<<"$LAN_IP").0/24"
for i in "${!VLAN_IDS[@]}"; do
  vip="${VLAN_IPS[$i]}"; vmask="${VLAN_CIDRS[$i]}"
  [[ -n "$vip" && -n "$vmask" ]] && echo "      allow-from $(cut -d. -f1-3 <<<"$vip").0/24"
done
echo "    }"
echo "  }"

# SSH service
echo "  ssh { port 22222 listen-address 0.0.0.0 }"
echo "}"
# NAT
echo "nat {"
echo "  source {"
echo "    rule 100 { description \"NAT LAN -> WAN\" outbound-interface $WAN_EGRESS_IF source { address $(cut -d. -f1-3 <<<"$LAN_IP").0/24 } translation { address masquerade } }"
# VLAN SNATs where IP assigned
r=110
for i in "${!VLAN_IDS[@]}"; do
  vid="${VLAN_IDS[$i]}"; vip="${VLAN_IPS[$i]}"; vmask="${VLAN_CIDRS[$i]}"
  [[ -n "$vip" && -n "$vmask" ]] || continue
  echo "    rule $r { description \"NAT VLAN$vid -> WAN\" outbound-interface $WAN_EGRESS_IF source { address $(cut -d. -f1-3 <<<"$vip").0/24 } translation { address masquerade } }"
  r=$((r+10))
done
echo "  }"
echo "  destination {"
# DNS redirection (force plaintext DNS to local resolver) on LAN
echo "    rule 300 { description \"Redirect LAN DNS -> local\" inbound-interface $LAN_IF protocol tcp_udp destination { port 53 } translation { address $LAN_IP port 53 } }"
# VLAN DNS redirection for addressed VLANs
s=310
for i in "${!VLAN_IDS[@]}"; do
  vid="${VLAN_IDS[$i]}"; vip="${VLAN_IPS[$i]}"; vmask="${VLAN_CIDRS[$i]}"
  [[ -n "$vip" && -n "$vmask" ]] || continue
  echo "    rule $s { description \"Redirect VLAN$vid DNS -> local\" inbound-interface ${LAN_IF}.$vid protocol tcp_udp destination { port 53 } translation { address $vip port 53 } }"
  s=$((s+10))
done
echo "  }"
echo "}"

# Firewall + hardening
echo "firewall {"
echo "  options { mss-clamp { mss 1452 } }"
# WAN-IN (forwarded)
echo "  name WAN-IN {"
echo "    default-action drop"
echo "    rule 10 { description \"Allow established/related\" action accept state { established enable related enable } }"
echo "    rule 50 { description \"Drop NULL\" action drop protocol tcp tcp { flags \"!syn,!ack,!fin,!rst\" } log enable }"
echo "    rule 51 { description \"Drop Xmas\" action drop protocol tcp tcp { flags fin,psh,urg } log enable }"
echo "    rule 52 { description \"Drop fragments\" action drop fragment enable log enable }"
echo "  }"
# WAN-LOCAL (to the router)
echo "  name WAN-LOCAL {"
echo "    default-action drop"
echo "    rule 10 { description \"Allow established/related\" action accept state { established enable related enable } }"
echo "    # No SSH from WAN. mgmt via LAN only."
echo "    rule 50 { description \"Drop NULL\" action drop protocol tcp tcp { flags \"!syn,!ack,!fin,!rst\" } log enable }"
echo "    rule 51 { description \"Drop Xmas\" action drop protocol tcp tcp { flags fin,psh,urg } log enable }"
echo "    rule 52 { description \"Drop fragments\" action drop fragment enable log enable }"
echo "  }"
# LAN-LOCAL (to router from LAN/VLANs) : DNS/DoT enforcement
echo "  name LAN-LOCAL {"
echo "    default-action accept"
# Belt-and-suspenders: block direct DNS to non-local
echo "    rule 10 { description \"Block direct DNS to non-local\" action drop protocol tcp_udp destination { port 53 address !${LAN_IP} } log enable }"
echo "    rule 11 { description \"Allow DNS to router\" action accept protocol tcp_udp destination { port 53 address ${LAN_IP} } }"
# Allow DoT only to Cloudflare; block the rest
echo "    rule 20 { description \"Allow DoT to 1.1.1.1\" action accept protocol tcp destination { port 853 address 1.1.1.1 } }"
echo "    rule 21 { description \"Allow DoT to 1.0.0.1\" action accept protocol tcp destination { port 853 address 1.0.0.1 } }"
echo "    rule 25 { description \"Block DoT elsewhere\" action drop protocol tcp destination { port 853 } log enable }"
echo "  }"
# LAN-OUT (egress anti-flood / anti-scan / allowlist)
echo "  name LAN-OUT {"
echo "    default-action drop"
echo "    rule 5  { description \"Allow established/related\" action accept state { established enable related enable } }"
echo "    rule 10 { description \"Allow HTTP/HTTPS\" action accept protocol tcp destination { port 80,443 } }"
echo "    rule 11 { description \"Allow ICMP\" action accept protocol icmp }"
echo "    rule 15 { description \"Block plaintext DNS\" action drop protocol tcp_udp destination { port 53 } log enable }"
# DoT only to Cloudflare; block others
echo "    rule 20 { description \"Allow DoT to 1.1.1.1\" action accept protocol tcp destination { port 853 address 1.1.1.1 } }"
echo "    rule 21 { description \"Allow DoT to 1.0.0.1\" action accept protocol tcp destination { port 853 address 1.0.0.1 } }"
echo "    rule 25 { description \"Block DoT elsewhere\" action drop protocol tcp destination { port 853 } log enable }"
# SYN flood control per source
echo "    rule 50 { description \"Permit limited SYN rate\" action accept protocol tcp tcp { flags syn } limit { rate 20/second burst 40 } }"
echo "    rule 51 { description \"Drop excessive SYN\" action drop protocol tcp tcp { flags syn } log enable }"
# Port-scan hardening
echo "    rule 60 { description \"Drop NULL\" action drop protocol tcp tcp { flags \"!syn,!ack,!fin,!rst\" } log enable }"
echo "    rule 61 { description \"Drop Xmas\" action drop protocol tcp tcp { flags fin,psh,urg } log enable }"
echo "    rule 70 { description \"Drop fragments\" action drop fragment enable log enable }"
echo "  }"
echo "}"
} > "$OUT"

ok "Generated $OUT"

# ========= Post script hints =========
cat <<'NOTE'

Next steps:
  1) Copy config to VyOS:
       scp config.boot vyos@<vyos-ip>:/config/config.boot
  2) On VyOS:
       configure
       load /config/config.boot
       commit
       save
       exit
  3) Verify:
       show interfaces
       show configuration commands
       show log tail

Notes:
  - DNS redirection forces clients to use the firewall's resolver (service dns forwarding).
  - DoT is allowed ONLY to Cloudflare (1.1.1.1 / 1.0.0.1) and blocked elsewhere.
  - DoH (HTTPS/443) cannot be reliably blocked without TLS/SNI DPI; this config avoids breaking normal HTTPS.
  - SSH listens on port 22222 and is reachable from LAN; WAN is default-drop.

NOTE
