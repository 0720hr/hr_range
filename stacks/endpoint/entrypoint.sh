#!/bin/bash
set -e
AGENT_NAME="${WAZUH_AGENT_NAME:-endpoint01}"
MANAGER="${WAZUH_MANAGER:-wazuh.manager}"

# Idempotent safety: make sure the agent points at the right manager
sed -i "s|<address>.*</address>|<address>${MANAGER}</address>|" /var/ossec/etc/ossec.conf || true

# Enroll only if we have no key yet (identity persists in the volume)
if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[entrypoint] No client.keys - enrolling with ${MANAGER} as ${AGENT_NAME}"
    /var/ossec/bin/agent-auth -m "${MANAGER}" -A "${AGENT_NAME}"
    sleep 3
else
    echo "[entrypoint] Existing identity found - reusing client.keys"
fi

term_handler() { echo "[entrypoint] stopping agent"; /var/ossec/bin/wazuh-control stop || true; exit 0; }
trap term_handler SIGTERM SIGINT

/var/ossec/bin/wazuh-control restart

# Supervisor: relaunch the agent if it ever dies; keeps PID 1 alive
while true; do
    if ! /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-agentd is running"; then
        echo "[entrypoint] agentd down - restarting"
        /var/ossec/bin/wazuh-control restart || true
    fi
    sleep 30
done
