#!/bin/bash
set -e
AGENT_NAME="${WAZUH_AGENT_NAME:-ssh-victim}"
MANAGER="${WAZUH_MANAGER:-wazuh.manager}"

# --- logging + SSH: start rsyslog (writes /var/log/auth.log) then sshd ---
mkdir -p /run/sshd
rsyslogd
/usr/sbin/sshd

# --- Wazuh agent: same as-code pattern as endpoint01 ---
sed -i "s|<address>.*</address>|<address>${MANAGER}</address>|" /var/ossec/etc/ossec.conf || true

# --- ensure the agent forwards SSH auth events (idempotent) ---
if ! grep -q "/var/log/auth.log" /var/ossec/etc/ossec.conf; then
    echo "[entrypoint] adding /var/log/auth.log to agent monitoring"
    cat >> /var/ossec/etc/ossec.conf <<'CONF'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</ossec_config>
CONF
fi

if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[entrypoint] No client.keys - enrolling ${AGENT_NAME} with ${MANAGER}"
    /var/ossec/bin/agent-auth -m "${MANAGER}" -A "${AGENT_NAME}"
    sleep 3
else
    echo "[entrypoint] Existing identity found - reusing client.keys"
fi

term_handler() { echo "[entrypoint] stopping"; /var/ossec/bin/wazuh-control stop || true; exit 0; }
trap term_handler SIGTERM SIGINT

/var/ossec/bin/wazuh-control restart

# Supervisor: keep rsyslog, sshd, and the agent alive
while true; do
    pgrep -x rsyslogd >/dev/null || rsyslogd
    pgrep -x sshd >/dev/null || /usr/sbin/sshd
    if ! /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-agentd is running"; then
        /var/ossec/bin/wazuh-control restart || true
    fi
    sleep 30
done
