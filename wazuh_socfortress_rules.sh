#!/bin/bash
# Install this repository's rules, decoders and CDB lists on a Wazuh manager.
#
#   sudo ./wazuh_socfortress_rules.sh [-y] [-d] [-r <git url>] [-b <branch>]
#
# What it does:
#   1. Backs up /var/ossec/etc/{rules,decoders,lists} and ossec.conf.
#   2. Clones the repository (this fork by default) and copies every rule XML
#      into etc/rules and every decoder into etc/decoders.
#   3. Copies each CDB list the rules reference into etc/lists and registers it
#      in ossec.conf's <ruleset> block if it isn't there yet.
#   4. Validates the configuration with wazuh-analysisd -t, then restarts the
#      manager. On any failure everything from step 1 is restored.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Default configuration
SKIP_CONFIRMATION=false
DEBUG=false
REPO_URL="${WAZUH_RULES_REPO:-https://github.com/joe85black/wazuh-rules.git}"
REPO_BRANCH="${WAZUH_RULES_BRANCH:-main}"
OSSEC=/var/ossec
WORKDIR=/tmp/wazuh-rules-install
BACKUP_DIR=/tmp/wazuh_rules_backup

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Install the wazuh-rules ruleset on a Wazuh manager"
    echo ""
    echo "Options:"
    echo "  -y, --yes            Skip confirmation prompt"
    echo "  -d, --debug          Enable debug output"
    echo "  -r, --repo <url>     Git repository to install from (default: $REPO_URL)"
    echo "  -b, --branch <name>  Branch to install (default: $REPO_BRANCH)"
    echo "  -h, --help           Display this help message"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes) SKIP_CONFIRMATION=true; shift ;;
        -d|--debug) DEBUG=true; shift ;;
        -r|--repo) REPO_URL="$2"; shift 2 ;;
        -b|--branch) REPO_BRANCH="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

[[ "$DEBUG" == true ]] && set -x

logger() {
    local now mtype="INFO:" message="$1"
    now=$(date +'%m/%d/%Y %H:%M:%S')
    if [[ "$1" == "-e" ]]; then
        mtype="ERROR:"; message="$2"
    elif [[ "$1" == "-w" ]]; then
        mtype="WARNING:"; message="$2"
    fi
    echo "$now $mtype $message"
}

detect_package_manager() {
    if command -v yum &>/dev/null; then
        echo "yum"
    elif command -v zypper &>/dev/null; then
        echo "zypper"
    elif command -v apt-get &>/dev/null; then
        echo "apt-get"
    else
        logger -e "Unable to determine package manager. Exiting."
        exit 1
    fi
}

check_dependencies() {
    if ! command -v git &>/dev/null; then
        logger -e "git could not be found. Please install it with: ${SYS_TYPE} install git"
        exit 1
    fi
    logger "Git found. Continuing..."
}

check_architecture() {
    if [[ "$(uname -m)" != "x86_64" && "$(uname -m)" != "aarch64" ]]; then
        logger -e "Unsupported architecture $(uname -m)."
        exit 1
    fi
}

check_manager_installed() {
    local installed=false
    case "$SYS_TYPE" in
        yum|zypper) rpm -qa | grep -q wazuh-manager && installed=true ;;
        apt-get) dpkg -s wazuh-manager &>/dev/null && installed=true ;;
    esac
    if [[ "$installed" != "true" ]]; then
        logger -e "wazuh-manager is not installed on this host"
        exit 1
    fi
}

restart_service() {
    local service_name="$1"
    if systemctl --version &>/dev/null; then
        logger "Restarting $service_name using systemd..."
        systemctl restart "$service_name.service"
    elif service --version &>/dev/null; then
        logger "Restarting $service_name using service..."
        service "$service_name" restart
    elif [[ -x "/etc/rc.d/init.d/$service_name" ]]; then
        logger "Restarting $service_name using init script..."
        "/etc/rc.d/init.d/$service_name" restart
    else
        logger -e "${service_name} could not restart. No service manager found on the system."
        return 1
    fi
    if [[ $? -ne 0 ]]; then
        logger -e "${service_name} could not be restarted. Check ${OSSEC}/logs/ossec.log for details."
        return 1
    fi
    logger "${service_name} restarted successfully"
}

backup() {
    rm -rf "$BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    logger "Backing up rules, decoders, lists and ossec.conf into $BACKUP_DIR"
    cp -a "$OSSEC/etc/rules" "$OSSEC/etc/decoders" "$OSSEC/etc/lists" "$BACKUP_DIR/"
    cp -a "$OSSEC/etc/ossec.conf" "$BACKUP_DIR/ossec.conf"
}

restore_backup() {
    logger -e "Restoring the backup from $BACKUP_DIR..."
    for dir in rules decoders lists; do
        rm -rf "${OSSEC:?}/etc/$dir"
        cp -a "$BACKUP_DIR/$dir" "$OSSEC/etc/$dir"
    done
    cp -a "$BACKUP_DIR/ossec.conf" "$OSSEC/etc/ossec.conf"
    restart_service "wazuh-manager"
    rm -rf "$WORKDIR"
}

# Decoder files live next to the rules in the repo; route them by content.
install_rules_and_decoders() {
    local count_rules=0 count_decoders=0
    while IFS= read -r -d '' file; do
        if grep -q '<decoder' "$file" && ! grep -q '<rule ' "$file"; then
            cp "$file" "$OSSEC/etc/decoders/"
            count_decoders=$((count_decoders + 1))
        else
            cp "$file" "$OSSEC/etc/rules/"
            count_rules=$((count_rules + 1))
        fi
    done < <(find "$WORKDIR" -path "$WORKDIR/.git" -prune -o -path "$WORKDIR/tools" -prune -o -name '*.xml' -type f -print0)
    logger "Installed $count_rules rule files and $count_decoders decoder files"
}

# Copy every CDB list the rules reference and register it in ossec.conf.
install_lists() {
    local name src
    mkdir -p "$OSSEC/etc/lists"
    for ref in $(grep -rhoE 'etc/lists/[A-Za-z0-9._/-]+' "$OSSEC/etc/rules" --include='*.xml' | sort -u); do
        name="${ref#etc/lists/}"
        src=$(find "$WORKDIR" -path "$WORKDIR/.git" -prune -o -type f -name "$(basename "$name")" -print | head -1)
        if [[ -n "$src" ]]; then
            mkdir -p "$OSSEC/etc/lists/$(dirname "$name")"
            cp "$src" "$OSSEC/etc/lists/$name"
            logger "Installed list $ref"
        elif [[ ! -f "$OSSEC/etc/lists/$name" ]]; then
            logger -w "List $ref is referenced by a rule but is neither in the repo nor on this manager"
        fi
        if ! grep -q "<list>$ref</list>" "$OSSEC/etc/ossec.conf"; then
            sed -i "0,/<ruleset>/s||<ruleset>\n    <list>$ref</list>|" "$OSSEC/etc/ossec.conf"
            logger "Registered $ref in ossec.conf"
        fi
    done
}

install() {
    logger "Cloning $REPO_URL ($REPO_BRANCH)"
    rm -rf "$WORKDIR"
    if ! git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$WORKDIR"; then
        logger -e "Failed to clone $REPO_URL"
        exit 1
    fi

    backup
    install_rules_and_decoders
    install_lists

    chown -R wazuh:wazuh "$OSSEC/etc/rules" "$OSSEC/etc/decoders" "$OSSEC/etc/lists"
    find "$OSSEC/etc/rules" "$OSSEC/etc/decoders" "$OSSEC/etc/lists" -type f -exec chmod 660 {} +
    "$OSSEC/bin/wazuh-control" info 2>&1 | tee /tmp/version.txt

    logger "Validating the configuration with wazuh-analysisd -t"
    if ! "$OSSEC/bin/wazuh-analysisd" -t; then
        logger -e "Configuration test failed (see output above)."
        restore_backup
        exit 1
    fi

    if ! restart_service "wazuh-manager"; then
        restore_backup
        exit 1
    fi
}

health_check() {
    logger "Performing a health check"
    sleep 20
    if "$OSSEC/bin/wazuh-control" status | grep -q 'wazuh-analysisd not running'; then
        logger -e "wazuh-analysisd is not running. Check $OSSEC/logs/ossec.log for details."
        restore_backup
        exit 1
    fi
    logger "Wazuh manager is healthy. Test new rules with $OSSEC/bin/wazuh-logtest."
    rm -rf "$WORKDIR"
}

main() {
    if [[ "$EUID" -ne 0 ]]; then
        logger -e "This script must be run as root."
        exit 1
    fi

    SYS_TYPE=$(detect_package_manager)

    if [[ "$SKIP_CONFIRMATION" != "true" ]]; then
        while true; do
            read -r -p "Install the ruleset from $REPO_URL? Rule files with the same name will be overwritten (a backup is kept in $BACKUP_DIR). Continue? (y/n) " yn
            case $yn in
                [Yy]* ) break ;;
                [Nn]* ) exit ;;
                * ) echo "Please answer yes or no." ;;
            esac
        done
    else
        logger "Confirmation skipped with -y flag"
    fi

    check_dependencies
    check_architecture
    check_manager_installed
    install
    health_check
    logger "Installation process completed"
}

main "$@"
