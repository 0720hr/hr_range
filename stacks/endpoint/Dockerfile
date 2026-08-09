FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
ENV WAZUH_MANAGER="wazuh.manager"
ENV WAZUH_AGENT_NAME="endpoint01"

RUN apt-get update && \
    apt-get install -y curl gnupg2 lsb-release procps iproute2 iputils-ping && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent=4.14.5-1 && \
    echo "wazuh-agent hold" | dpkg --set-selections && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
