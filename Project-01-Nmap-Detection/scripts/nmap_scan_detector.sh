#!/bin/bash
###############################################################################
# nmap_scan_detector.sh
#
# Purpose:  Detect TCP SYN port-scan patterns in a packet capture (.pcap).
# Author:   James Williams (WiLL75G)
# Project:  CorpOps-Shell-Suite / Project 01 - Nmap Detection
# MITRE:    T1046 - Network Service Discovery
#
# Usage:    ./nmap_scan_detector.sh <path-to-pcap-file>
# Example:  ./nmap_scan_detector.sh ../logs/nmap_scan_capture.pcap
###############################################################################

set -u

# ----- CONFIG -----
PCAP_FILE="${1:-}"
SCAN_THRESHOLD=100              # >=100 distinct dst ports from one src = scan
EXCLUDE_PORTS="1514|1515"       # Wazuh agent traffic (legitimate baseline)
ALERT_LOG="$(dirname "$0")/../logs/scan_alerts.log"

# ----- INPUT VALIDATION -----
if [[ -z "$PCAP_FILE" ]]; then
    echo "[ERROR] No pcap file specified."
    echo "Usage: $0 <path-to-pcap-file>"
    exit 1
fi

if [[ ! -f "$PCAP_FILE" ]]; then
    echo "[ERROR] File not found: $PCAP_FILE"
    exit 1
fi

# ----- ANALYSIS -----
echo "============================================================"
echo "  NMAP SCAN DETECTOR -- CorpOps SOC Tier 1"
echo "  MITRE ATT&CK: T1046 (Network Service Discovery)"
echo "============================================================"
echo "[INFO] Analyzing:  $PCAP_FILE"
echo "[INFO] Threshold:  $SCAN_THRESHOLD distinct destination ports"
echo "[INFO] Exclude:    Ports $EXCLUDE_PORTS (known baseline traffic)"
echo ""

# Extract all SYN-only packets (exclude noise)
SYN_PACKETS=$(tcpdump -n -r "$PCAP_FILE" 2>/dev/null \
    | grep -v -E "$EXCLUDE_PORTS" \
    | grep "Flags \[S\]," || true)

if [[ -z "$SYN_PACKETS" ]]; then
    echo "[OK] No SYN packets found after noise filter. No scan detected."
    exit 0
fi

# Count distinct destination ports
DISTINCT_PORTS=$(echo "$SYN_PACKETS" \
    | awk '{print $5}' \
    | awk -F. '{print $NF}' \
    | tr -d ':' \
    | sort -u \
    | wc -l)

# Count total SYN probes
TOTAL_SYNS=$(echo "$SYN_PACKETS" | wc -l)

# Extract source IP (v1: assumes single attacker)
SOURCE_IP=$(echo "$SYN_PACKETS" \
    | head -1 \
    | awk '{print $3}' \
    | awk -F. '{print $1"."$2"."$3"."$4}')

# Extract time window
FIRST_TS=$(echo "$SYN_PACKETS" | head -1 | awk '{print $1}')
LAST_TS=$(echo "$SYN_PACKETS"  | tail -1 | awk '{print $1}')

# ----- FINDINGS -----
echo "[FINDING] Source IP:          $SOURCE_IP"
echo "[FINDING] Total SYN probes:   $TOTAL_SYNS"
echo "[FINDING] Distinct dst ports: $DISTINCT_PORTS"
echo "[FINDING] First probe:        $FIRST_TS"
echo "[FINDING] Last probe:         $LAST_TS"
echo ""

# ----- VERDICT -----
if [[ "$DISTINCT_PORTS" -ge "$SCAN_THRESHOLD" ]]; then
    echo "============================================================"
    echo "  [ALERT] PORT SCAN DETECTED -- MITRE T1046"
    echo "============================================================"
    echo "  Attacker IP:   $SOURCE_IP"
    echo "  Probe count:   $TOTAL_SYNS"
    echo "  Port count:    $DISTINCT_PORTS (threshold: $SCAN_THRESHOLD)"
    echo "  Window:        $FIRST_TS  ->  $LAST_TS"
    echo "============================================================"

    # Append structured alert to log
    mkdir -p "$(dirname "$ALERT_LOG")"
    echo "$(date -Iseconds) | ALERT | T1046 | src=$SOURCE_IP | probes=$TOTAL_SYNS | ports=$DISTINCT_PORTS | window=$FIRST_TS-$LAST_TS" >> "$ALERT_LOG"
    echo ""
    echo "[INFO] Alert appended to: $ALERT_LOG"
    exit 1  # Non-zero exit for SIEM/orchestration integration
else
    echo "[OK] Activity below scan threshold. No alert raised."
    exit 0
fi
