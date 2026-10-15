#!/usr/bin/env bash
# Sentinel SOC Lab control (Azure CLI). Requires: az login, correct subscription selected.
# Usage: ./lab-control.sh {start|stop|status|myip|query "<KQL>"}

set -euo pipefail

VM_RG="SC-200"
VM_NAME="SC200-WS22"
SOC_RG="Rg-soc-lab"
WORKSPACE="law-soc-lab"
NSG_NAME="SC200-WS22-nsg"
NSG_RULE="Allow-RDP-MyIP"

case "${1:-}" in
  start)
    az vm start -g "$VM_RG" -n "$VM_NAME"
    az vm show -d -g "$VM_RG" -n "$VM_NAME" --query "{state:powerState, ip:publicIps}" -o table
    ;;
  stop)
    # Deallocate (not just stop) so compute billing ends. Auto-shutdown is unavailable in this region.
    az vm deallocate -g "$VM_RG" -n "$VM_NAME"
    az vm get-instance-view -g "$VM_RG" -n "$VM_NAME" \
      --query "instanceView.statuses[?starts_with(code,'PowerState')].displayStatus" -o tsv
    ;;
  status)
    az vm get-instance-view -g "$VM_RG" -n "$VM_NAME" \
      --query "instanceView.statuses[?starts_with(code,'PowerState')].displayStatus" -o tsv
    ;;
  myip)
    # Updates the RDP rule to your current public IP (home IP changes).
    MYIP="$(curl -s https://api.ipify.org)"
    echo "Current public IP: $MYIP"
    az network nsg rule update -g "$VM_RG" --nsg-name "$NSG_NAME" -n "$NSG_RULE" \
      --source-address-prefixes "${MYIP}/32" \
      --query "{rule:name, source:sourceAddressPrefix, port:destinationPortRange, access:access}" -o table
    ;;
  query)
    # Runs a KQL query against the Sentinel workspace (Log Analytics tables only, e.g. SecurityEvent).
    # Defender Device* tables are queried in the Defender portal Advanced hunting, not here.
    : "${2:?Provide a KQL query string}"
    WS_ID="$(az monitor log-analytics workspace show -g "$SOC_RG" -n "$WORKSPACE" --query customerId -o tsv)"
    az monitor log-analytics query -w "$WS_ID" --analytics-query "$2" -o table
    ;;
  *)
    echo "Usage: $0 {start|stop|status|myip|query \"<KQL>\"}"
    exit 1
    ;;
esac
