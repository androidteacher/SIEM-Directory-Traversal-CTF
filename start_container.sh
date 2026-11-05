#!/bin/bash
# =============================================================================
# start_container.sh  --  STAND UP THE POLARIS CLOUD CONSOLE LAB
#
# Builds and starts the one container that runs the vulnerable web console on
# http://localhost:12334. Each docker command is printed right before it runs.
#
# Works with either Docker Compose version:
#   * "docker compose"  (v2 plugin, newer Docker)
#   * "docker-compose"  (v1 standalone, older systems)
# =============================================================================

main() {
    set -e
    cd "$(dirname "$0")"

    # Make sure Docker itself is installed; if not, say how to install it.
    if ! command -v docker >/dev/null 2>&1; then
        say_no_docker
        exit 1
    fi

    # Pick whichever Docker Compose this machine has.
    if docker compose version >/dev/null 2>&1; then
        DC=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        DC=(docker-compose)
    else
        say_no_compose
        exit 1
    fi

    say_intro
    run "${DC[@]}" build
    run "${DC[@]}" up -d
    run "${DC[@]}" ps
    say_done
}

# =============================================================================
#  >>>  RUNTIME ECHO COMMANDS  <<<
# =============================================================================
CYAN='\033[1;96m'; GREEN='\033[1;92m'; YEL='\033[1;93m'; RST='\033[0m'

run() {
    echo -e "${YEL}\$ ${CYAN}$*${RST}"
    "$@"
    echo
}
say_no_docker() {
    msg="*  docker not installed. Please install it with  apt install docker.io docker-compose  *"
    bar="$(printf '%*s' "${#msg}" '' | tr ' ' '*')"
    echo -e "${CYAN}${bar}${RST}"
    echo -e "${CYAN}${msg}${RST}"
    echo -e "${CYAN}${bar}${RST}"
}
say_no_compose() {
    echo -e "${YEL}[!] Could not find Docker Compose on this system.${RST}"
    echo -e "${YEL}    Install Docker with the Compose plugin, or the standalone docker-compose.${RST}"
}
say_intro() {
    echo -e "${GREEN}[*] Building and starting the Polaris Cloud console...${RST}"
    echo -e "${GREEN}    Using Compose command: ${CYAN}${DC[*]}${RST}"
    echo
}
say_done() {
    echo -e "${GREEN}[+] Lab is up.${RST}"
    echo -e "${GREEN}    Console     : ${CYAN}http://localhost:12334${RST}"
    echo -e "${GREEN}    Objective   : ${CYAN}capture the flag at /private_folder/flag.txt${RST}"
    echo -e "${GREEN}    Stop later  : ${CYAN}./teardown_container.sh${RST}"
}

main "$@"
