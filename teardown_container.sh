#!/bin/bash
# =============================================================================
# teardown_container.sh  --  STOP AND REMOVE THE POLARIS CLOUD CONSOLE LAB
# =============================================================================
main() {
    set -e
    cd "$(dirname "$0")"

    if docker compose version >/dev/null 2>&1; then
        DC=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        DC=(docker-compose)
    else
        echo "[!] Docker Compose not found; nothing to do."
        exit 1
    fi

    echo -e "\033[1;93m\$ \033[1;96m${DC[*]} down\033[0m"
    "${DC[@]}" down
    echo -e "\033[1;92m[+] Lab stopped and container removed.\033[0m"
}
main "$@"
