#!/usr/bin/env bash
# blockip.sh - IPv4 country/manual firewall manager for Debian/Ubuntu.
# The script owns only the BLOCKIP_INPUT iptables chain.

set -u

readonly APP_NAME="blockip"
readonly VERSION="2.1.0"
readonly CHAIN="BLOCKIP_INPUT"
readonly STAGING_CHAIN="BLOCKIP_STAGE"
readonly BIN_PATH="/usr/local/sbin/blockip"
readonly SCRIPT_URL="https://raw.githubusercontent.com/hiapb/ip_amange/main/install.sh"
readonly STATE_DIR="/etc/blockip"
readonly CN_ZONE="${STATE_DIR}/cn.zone"
readonly MODE_FILE="${STATE_DIR}/mode"
readonly WHITELIST_FILE="${STATE_DIR}/whitelist.conf"
readonly BLOCKLIST_FILE="${STATE_DIR}/blocklist.conf"
readonly UPDATE_MAX_AGE=604800
# Domain records are refreshed at most once per hour when rules are applied.
readonly DNS_CACHE_TTL=3600
readonly DNS_CACHE_DIR="${STATE_DIR}/dns-cache"
readonly DEPENDENCY_MARKER="${STATE_DIR}/.dependencies-ok"
readonly SERVICE_FILE="/etc/systemd/system/blockip.service"
readonly REFRESH_SERVICE_FILE="/etc/systemd/system/blockip-refresh.service"
readonly TIMER_FILE="/etc/systemd/system/blockip-refresh.timer"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    readonly C_RED=$'\033[31m'
    readonly C_GREEN=$'\033[32m'
    readonly C_YELLOW=$'\033[33m'
    readonly C_CYAN=$'\033[36m'
    readonly C_BOLD=$'\033[1m'
    readonly C_RESET=$'\033[0m'
else
    readonly C_RED='' C_GREEN='' C_YELLOW='' C_CYAN='' C_BOLD='' C_RESET=''
fi

red() { printf '%s%s%s\n' "$C_RED" "$*" "$C_RESET"; }
green() { printf '%s%s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
yellow() { printf '%s%s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
die() { red "$*"; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "请使用 root 运行：sudo bash $0"
}

ensure_state() {
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    [ -f "$MODE_FILE" ] || printf 'none\n' > "$MODE_FILE"
    [ -f "$WHITELIST_FILE" ] || : > "$WHITELIST_FILE"
    [ -f "$BLOCKLIST_FILE" ] || : > "$BLOCKLIST_FILE"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

ipt() {
    iptables -w 10 "$@"
}

runtime_dependencies_ready() {
    have_cmd iptables &&
    have_cmd iptables-restore &&
    { have_cmd curl || have_cmd wget; } &&
    have_cmd getent &&
    have_cmd awk &&
    have_cmd sed &&
    have_cmd grep &&
    have_cmd nl &&
    have_cmd wc &&
    have_cmd mktemp &&
    have_cmd stat &&
    have_cmd date &&
    have_cmd readlink &&
    have_cmd sort &&
    have_cmd tr &&
    have_cmd install &&
    have_cmd cp &&
    have_cmd cmp &&
    have_cmd flock &&
    { have_cmd sha256sum || have_cmd cksum; }
}

install_dependencies() {
    local packages=() unique_packages=() package
    require_root
    have_cmd apt-get || die "未找到 apt-get，请手动安装 iptables。"
    have_cmd iptables || packages+=(iptables)
    have_cmd iptables-restore || packages+=(iptables)
    have_cmd curl || have_cmd wget || packages+=(wget)
    have_cmd getent || packages+=(libc-bin)
    have_cmd clear || packages+=(ncurses-bin)
    have_cmd awk || packages+=(mawk)
    have_cmd sed || packages+=(sed)
    have_cmd grep || packages+=(grep)
    have_cmd nl || packages+=(coreutils)
    have_cmd wc || packages+=(coreutils)
    have_cmd mktemp || packages+=(coreutils)
    have_cmd stat || packages+=(coreutils)
    have_cmd date || packages+=(coreutils)
    have_cmd readlink || packages+=(coreutils)
    have_cmd sort || packages+=(coreutils)
    have_cmd tr || packages+=(coreutils)
    have_cmd install || packages+=(coreutils)
    have_cmd cp || packages+=(coreutils)
    have_cmd cmp || packages+=(diffutils)
    have_cmd flock || packages+=(util-linux)
    have_cmd sha256sum || have_cmd cksum || packages+=(coreutils)
    if have_cmd dpkg-query && ! dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null | grep -q 'install ok installed'; then
        packages+=(ca-certificates)
    fi
    for package in "${packages[@]}"; do
        [[ " ${unique_packages[*]} " == *" $package "* ]] || unique_packages+=("$package")
    done
    packages=("${unique_packages[@]}")
    if [ "${#packages[@]}" -eq 0 ]; then
        runtime_dependencies_ready && { touch "$DEPENDENCY_MARKER"; return 0; }
        die "依赖状态异常：必要命令不可用，但未找到可补装的软件包。"
    fi
    yellow "正在自动安装缺少的依赖：${packages[*]}"
    apt-get update || die "apt-get update 失败。"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" || \
        die "依赖安装失败。"
    runtime_dependencies_ready || die "依赖安装完成，但仍有必要命令不可用，请检查系统软件源。"
    touch "$DEPENDENCY_MARKER"
}

ensure_dependencies() {
    if [ -f "$DEPENDENCY_MARKER" ] && runtime_dependencies_ready; then
        return 0
    fi
    if runtime_dependencies_ready; then
        touch "$DEPENDENCY_MARKER"
        return 0
    fi
    install_dependencies
}

valid_ipv4_or_cidr() {
    local value=$1 octet
    [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || return 1
    local address=${value%%/*}
    IFS=. read -r -a octets <<< "$address"
    for octet in "${octets[@]}"; do
        [ "$octet" -le 255 ] || return 1
    done
    if [[ "$value" == */* ]]; then
        local prefix=${value##*/}
        [ "$prefix" -le 32 ] || return 1
    fi
}

valid_ipv4() {
    [[ "$1" != */* ]] && valid_ipv4_or_cidr "$1"
}

valid_cidr() {
    [[ "$1" == */* ]] && valid_ipv4_or_cidr "$1"
}

valid_domain() {
    [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

validate_cn_zone_file() {
    local input=$1 output=$2
    # Portable validation for mawk/busybox awk; do not rely on {n} regex intervals.
    awk '
        function valid_cidr(value, parts, ip, octets, i) {
            parts = split(value, cidr, "/")
            if (parts != 2 || cidr[2] !~ /^[0-9]+$/ || cidr[2] < 0 || cidr[2] > 32) return 0
            ip = split(cidr[1], octets, ".")
            if (ip != 4) return 0
            for (i = 1; i <= 4; i++) {
                if (octets[i] !~ /^[0-9]+$/ || octets[i] < 0 || octets[i] > 255) return 0
            }
            return 1
        }
        {
            sub(/\r$/, "", $1)
        }
        NF == 1 && valid_cidr($1) { print $1; ok++ }
        END { if (ok < 100) exit 1 }
    ' "$input" > "$output"
}

download_cn_zone() {
    require_root
    ensure_state
    local tmp="${CN_ZONE}.tmp" clean="${CN_ZONE}.clean" url
    local urls=(
        'https://www.ipdeny.com/ipblocks/data/countries/cn.zone'
        'http://www.ipdeny.com/ipblocks/data/countries/cn.zone'
        'https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone'
        'http://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone'
    )
    have_cmd curl || have_cmd wget || { red "需要 curl 或 wget。"; return 1; }
    for url in "${urls[@]}"; do
        rm -f "$tmp" "$clean"
        if have_cmd curl; then
            curl -fsSL --connect-timeout 15 --max-time 120 "$url" -o "$tmp" 2>/dev/null || continue
        else
            wget -q --timeout=15 -O "$tmp" "$url" 2>/dev/null || continue
        fi
        [ -s "$tmp" ] || continue
        validate_cn_zone_file "$tmp" "$clean" || continue
        [ -s "$clean" ] || continue
        mv "$clean" "$CN_ZONE"
        rm -f "$tmp"
        chmod 600 "$CN_ZONE"
        green "国内 IP 列表已更新：$(wc -l < "$CN_ZONE") 个网段。"
        return 0
    done
    rm -f "$tmp" "$clean"
    red "国内 IP 列表下载或校验失败，已尝试 HTTPS、HTTP 和聚合列表。"
    red "未修改现有规则，请稍后重试。"
    return 1
}

ensure_cn_zone() {
    local now modified age
    [ -s "$CN_ZONE" ] || { download_cn_zone; return $?; }
    modified=$(stat -c %Y "$CN_ZONE" 2>/dev/null || printf 0)
    now=$(date +%s)
    age=$((now - modified))
    if [ "$age" -ge "$UPDATE_MAX_AGE" ]; then
        yellow "国内 IP 列表已超过 7 天，正在自动更新。"
        if ! download_cn_zone; then
            yellow "更新失败，继续使用已有列表。"
        fi
    fi
}

install_self() {
    local source_path resolved_path install_source tmp='' target_tmp
    source_path=${BASH_SOURCE[0]}
    resolved_path=$(readlink -f "$source_path" 2>/dev/null || printf '%s' "$source_path")
    if [ "$resolved_path" != "$BIN_PATH" ]; then
        install_source=$source_path
        case "$source_path" in
            /dev/fd/*|/proc/self/fd/*)
                tmp=$(mktemp)
                if have_cmd curl; then
                    curl -fsSL --connect-timeout 15 --max-time 120 "$SCRIPT_URL" -o "$tmp" || {
                        rm -f "$tmp"
                        die "完整脚本下载失败，未执行安装。"
                    }
                elif have_cmd wget; then
                    wget -q --timeout=15 -O "$tmp" "$SCRIPT_URL" || {
                        rm -f "$tmp"
                        die "完整脚本下载失败，未执行安装。"
                    }
                else
                    rm -f "$tmp"
                    die "在线安装需要 curl 或 wget。"
                fi
                bash -n "$tmp" || { rm -f "$tmp"; die "下载的脚本语法校验失败，未执行安装。"; }
                [ -s "$tmp" ] || { rm -f "$tmp"; die "下载的脚本为空，未执行安装。"; }
                install_source=$tmp
                ;;
        esac
        target_tmp="${BIN_PATH}.new.$$"
        install -m 755 "$install_source" "$target_tmp" || {
            [ -n "$tmp" ] && rm -f "$tmp"
            die "无法安装到 $BIN_PATH"
        }
        [ -n "$tmp" ] && rm -f "$tmp"
        bash -n "$target_tmp" || { rm -f "$target_tmp"; die "下载的程序校验失败，原版本未被修改。"; }
        mv -f "$target_tmp" "$BIN_PATH" || { rm -f "$target_tmp"; die "无法更新 $BIN_PATH"; }
        green "程序已安装/更新：$BIN_PATH"
        green "以后直接运行：blockip"
        exec bash "$BIN_PATH" "$@"
    fi
}

install_systemd_units() {
    local changed=0 tmp
    PERSISTENCE_ENABLED=0
    if ! have_cmd systemctl || [ ! -d /run/systemd/system ]; then
        return 0
    fi
    tmp=$(mktemp)
    printf '%s\n' \
        '[Unit]' \
        'Description=blockip inbound firewall' \
        'After=network-online.target' \
        'Wants=network-online.target' \
        '' \
        '[Service]' \
        'Type=oneshot' \
        "ExecStart=$BIN_PATH --apply" \
        'RemainAfterExit=yes' \
        '' \
        '[Install]' \
        'WantedBy=multi-user.target' > "$tmp"
    cmp -s "$tmp" "$SERVICE_FILE" 2>/dev/null || { install -m 644 "$tmp" "$SERVICE_FILE"; changed=1; }

    printf '%s\n' \
        '[Unit]' \
        'Description=Refresh blockip country and domain data' \
        'After=network-online.target' \
        'Wants=network-online.target' \
        '' \
        '[Service]' \
        'Type=oneshot' \
        "ExecStart=$BIN_PATH --maintenance" > "$tmp"
    cmp -s "$tmp" "$REFRESH_SERVICE_FILE" 2>/dev/null || { install -m 644 "$tmp" "$REFRESH_SERVICE_FILE"; changed=1; }

    printf '%s\n' \
        '[Unit]' \
        'Description=Run blockip maintenance hourly' \
        '' \
        '[Timer]' \
        'OnBootSec=10min' \
        'OnUnitActiveSec=1h' \
        'Persistent=true' \
        'RandomizedDelaySec=5min' \
        '' \
        '[Install]' \
        'WantedBy=timers.target' > "$tmp"
    cmp -s "$tmp" "$TIMER_FILE" 2>/dev/null || { install -m 644 "$tmp" "$TIMER_FILE"; changed=1; }
    rm -f "$tmp"
    rm -f /etc/cron.d/blockip
    [ "$changed" -eq 0 ] || systemctl daemon-reload
    systemctl enable blockip.service blockip-refresh.timer >/dev/null 2>&1 || { red "systemd 服务启用失败。"; return 1; }
    systemctl start blockip-refresh.timer >/dev/null 2>&1 || { red "systemd 定时器启动失败。"; return 1; }
    PERSISTENCE_ENABLED=1
}

check_firewall_access() {
    if ! ipt -L INPUT -n >/dev/null 2>&1; then
        red '当前系统无法操作 iptables。'
        red '如果这是 Docker/LXC 容器，需要宿主机授予 NET_ADMIN 权限；普通容器内无法管理入口防火墙。'
        return 1
    fi
}

append_sources_from_file() {
    local file=$1 target=$2 kind value ip
    shift 2
    while IFS='|' read -r kind value; do
        [ -n "${kind:-}" ] || continue
        case "$kind" in
            IP|NET)
                if valid_ipv4_or_cidr "$value"; then
                    append_rule "$@" -s "$value" -j "$target" || return 1
                fi
                ;;
            DOMAIN)
                while read -r ip; do
                    append_rule "$@" -s "$ip" -j "$target" || return 1
                done < <(resolve_domain "$value")
                ;;
        esac
    done < "$file"
}

append_cn_sources() {
    local target=$1 network
    shift
    [ -s "$CN_ZONE" ] || return 0
    while read -r network; do
        if valid_ipv4_or_cidr "$network"; then
            append_rule "$@" -s "$network" -j "$target" || return 1
        fi
    done < "$CN_ZONE"
}

resolve_domain() {
    local domain=$1 ip now modified age cache_file cache_key ips tmp
    have_cmd getent || return 0
    mkdir -p "$DNS_CACHE_DIR"
    if have_cmd sha256sum; then
        cache_key=$(printf '%s' "$domain" | sha256sum | awk '{print $1}')
    else
        cache_key=$(printf '%s' "$domain" | cksum | awk '{print $1}')
    fi
    cache_file="${DNS_CACHE_DIR}/${cache_key}.ipv4"
    now=$(date +%s)
    if [ -s "$cache_file" ]; then
        modified=$(stat -c %Y "$cache_file" 2>/dev/null || printf 0)
        age=$((now - modified))
        if [ "$age" -lt "$DNS_CACHE_TTL" ]; then
            cat "$cache_file"
            return 0
        fi
    fi
    ips=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u)
    tmp="${cache_file}.tmp"
    : > "$tmp"
    while read -r ip; do
        valid_ipv4_or_cidr "$ip" && printf '%s\n' "$ip" >> "$tmp"
    done <<< "$ips"
    if [ -s "$tmp" ]; then
        mv "$tmp" "$cache_file"
    else
        rm -f "$tmp"
    fi
    [ -s "$cache_file" ] && cat "$cache_file"
}

remove_chain() {
    local name=$1
    while ipt -C INPUT -j "$name" 2>/dev/null; do
        ipt -D INPUT -j "$name" || return 1
    done
    if ipt -S "$name" >/dev/null 2>&1; then
        ipt -F "$name" || return 1
        ipt -X "$name" || return 1
    fi
}

prepare_staging_chain() {
    remove_chain "$STAGING_CHAIN" || return 1
    RULES_FILE=$(mktemp) || return 1
    printf '*filter\n:%s - [0:0]\n' "$STAGING_CHAIN" > "$RULES_FILE" || {
        rm -f "$RULES_FILE"
        unset RULES_FILE
        return 1
    }
    BUILD_CHAIN=$STAGING_CHAIN
}

discard_staging_rules() {
    if [ -n "${RULES_FILE:-}" ]; then
        rm -f "$RULES_FILE"
        unset RULES_FILE
    fi
}

commit_staging_rules() {
    [ -n "${RULES_FILE:-}" ] || return 1
    printf 'COMMIT\n' >> "$RULES_FILE" || { discard_staging_rules; return 1; }
    if ! iptables-restore -w 10 --noflush < "$RULES_FILE"; then
        red "iptables 批量提交失败，未替换原有规则。"
        discard_staging_rules
        remove_chain "$STAGING_CHAIN" >/dev/null 2>&1 || true
        return 1
    fi
    discard_staging_rules
}

activate_staging_chain() {
    ipt -I INPUT 1 -j "$STAGING_CHAIN" || return 1
    while ipt -C INPUT -j "$CHAIN" 2>/dev/null; do
        ipt -D INPUT -j "$CHAIN" || return 1
    done
    if ipt -S "$CHAIN" >/dev/null 2>&1; then
        ipt -F "$CHAIN" || return 1
        ipt -X "$CHAIN" || return 1
    fi
    ipt -E "$STAGING_CHAIN" "$CHAIN" || return 1
    BUILD_CHAIN=$CHAIN
    ipt -C INPUT -j "$CHAIN" >/dev/null 2>&1 || return 1
    ipt -S "$CHAIN" >/dev/null 2>&1 || return 1
}

append_rule() {
    local argument
    if [ -n "${RULES_FILE:-}" ]; then
        printf -- '-A %s' "${BUILD_CHAIN:-$CHAIN}" >> "$RULES_FILE" || return 1
        for argument in "$@"; do
            printf ' %s' "$argument" >> "$RULES_FILE" || return 1
        done
        printf '\n' >> "$RULES_FILE" || return 1
    else
        ipt -A "${BUILD_CHAIN:-$CHAIN}" "$@" || {
            red "iptables 规则写入失败。"
            return 1
        }
    fi
}

apply_rules_unlocked() {
    require_root
    ensure_dependencies
    ensure_state
    check_firewall_access || return 1
    local mode
    mode=$(tr -d '[:space:]' < "$MODE_FILE")
    case "$mode" in
        block_cn|block_foreign)
            ensure_cn_zone || return 1
            ;;
    esac
    prepare_staging_chain || return 1
    if ! build_staging_rules "$mode"; then
        discard_staging_rules
        remove_chain "$STAGING_CHAIN" >/dev/null 2>&1 || true
        unset BUILD_CHAIN
        red "规则构建失败，原有防火墙规则保持不变。"
        return 1
    fi
    if ! commit_staging_rules; then
        unset BUILD_CHAIN
        return 1
    fi
    if ! activate_staging_chain; then
        red "规则切换失败，请执行 blockip --apply 重试。"
        return 1
    fi
    green "规则已应用，当前模式：$(mode_label "$mode")"
}

build_staging_rules() {
    local mode=$1
    append_rule -i lo -j ACCEPT || return 1
    append_sources_from_file "$WHITELIST_FILE" ACCEPT || return 1
    # Existing TCP/UDP sessions and replies to pings initiated by this server
    # remain available. Inbound echo requests still pass through blocking rules.
    append_rule -p icmp --icmp-type echo-reply -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
    append_rule -p icmp --icmp-type destination-unreachable -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
    append_rule -p icmp --icmp-type time-exceeded -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
    append_rule -p icmp --icmp-type parameter-problem -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
    append_rule ! -p icmp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
    append_sources_from_file "$BLOCKLIST_FILE" DROP || return 1
    case "$mode" in
        block_cn)
            append_cn_sources DROP || return 1
            ;;
        block_foreign)
            append_cn_sources ACCEPT || return 1
            append_rule -j DROP || return 1
            ;;
        both)
            append_rule -j DROP || return 1
            ;;
        none|*)
            ;;
    esac
}

apply_rules() {
    mkdir -p /run/lock
    (
        flock -x 9
        apply_rules_unlocked
    ) 9>/run/lock/blockip.lock
}

apply_and_save() {
    apply_rules || return 1
    if ! install_systemd_units; then
        yellow "当前规则已生效，但开机恢复和自动维护设置失败。"
        return 0
    fi
    if [ "${PERSISTENCE_ENABLED:-0}" -eq 1 ]; then
        green "开机恢复和自动维护已启用。"
    else
        yellow "当前系统未运行 systemd，本次规则已生效，但无法自动恢复和定时更新。"
    fi
}

reapply_after_rollback() {
    apply_rules >/dev/null 2>&1
}

mode_label() {
    case "$1" in
        block_cn) printf '屏蔽国内 IP（允许其他来源）' ;;
        block_foreign) printf '屏蔽国外 IP（仅允许国内 IP）' ;;
        both) printf '同时屏蔽国内和国外 IP（仅白名单）' ;;
        *) printf '关闭地域屏蔽（仅手工屏蔽）' ;;
    esac
}

set_mode() {
    local mode=$1 previous
    ensure_state
    previous=$(tr -d '[:space:]' < "$MODE_FILE")
    printf '%s\n' "$mode" > "$MODE_FILE"
    if ! apply_and_save; then
        printf '%s\n' "$previous" > "$MODE_FILE"
        if reapply_after_rollback; then
            red "操作失败，已恢复之前的开关状态。"
        else
            red "操作失败，配置已恢复，但防火墙回滚未完成；请执行 blockip --apply。"
        fi
        return 1
    fi
}

toggle_region() {
    local region=$1 action current next
    action=$2
    current=$(tr -d '[:space:]' < "$MODE_FILE")
    case "$current" in
        none|block_cn|block_foreign|both) ;;
        *) current=none ;;
    esac
    if [ "$region" = cn ]; then
        if [ "$action" = on ]; then
            case "$current" in
                block_foreign|both) next=both ;;
                *) next=block_cn ;;
            esac
        else
            case "$current" in
                both) next=block_foreign ;;
                block_cn) next=none ;;
                *) next=$current ;;
            esac
        fi
    else
        if [ "$action" = on ]; then
            case "$current" in
                block_cn|both) next=both ;;
                *) next=block_foreign ;;
            esac
        else
            case "$current" in
                both) next=block_cn ;;
                block_foreign) next=none ;;
                *) next=$current ;;
            esac
        fi
    fi
    set_mode "$next"
}

screen_title() {
    clear 2>/dev/null || true
    printf '%s%s%s\n' "$C_CYAN" '==================================================' "$C_RESET"
    printf '  %s%s%s\n' "$C_BOLD" "$1" "$C_RESET"
    printf '%s%s%s\n\n' "$C_CYAN" '==================================================' "$C_RESET"
}

menu_item() {
    printf '  %s%s.%s %s\n' "$C_CYAN" "$1" "$C_RESET" "$2"
}

choose_entry_type() {
    local choice=''
    printf '%s\n\n' '请选择规则类型：'
    menu_item 1 '单个 IPv4 地址'
    menu_item 2 'IPv4 网段（CIDR）'
    menu_item 3 '域名'
    printf '\n'
    menu_item 0 '返回'
    read -r -p '请输入选项 [0-3]：' choice || return 1
    case "$choice" in
        1) SELECTED_KIND=IP ;;
        2) SELECTED_KIND=NET ;;
        3) SELECTED_KIND=DOMAIN ;;
        0) return 1 ;;
        *) red '请输入 0 到 3 之间的数字。'; return 1 ;;
    esac
}

read_entry_value() {
    local kind=$1 value=''
    case "$kind" in
        IP) read -r -p '请输入 IPv4 地址（例如 203.0.113.10）：' value || return 1 ;;
        NET) read -r -p '请输入 IPv4 网段（例如 203.0.113.0/24）：' value || return 1 ;;
        DOMAIN) read -r -p '请输入域名（例如 example.com）：' value || return 1 ;;
    esac
    value=$(printf '%s' "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -n "$value" ] || { red '输入不能为空。'; return 1; }
    case "$kind" in
        IP)
            valid_ipv4 "$value" || { red 'IPv4 地址格式不正确，请不要填写网段。'; return 1; }
            ;;
        NET)
            valid_cidr "$value" || { red 'IPv4 网段格式不正确，必须包含 /0 到 /32。'; return 1; }
            ;;
        DOMAIN)
            value=${value,,}
            valid_domain "$value" || { red '域名格式不正确。'; return 1; }
            resolve_domain "$value" | grep -q . || { red '域名没有解析到 IPv4 地址，请检查域名或 DNS。'; return 1; }
            ;;
    esac
    ENTRY_VALUE=$value
}

add_entry() {
    local file=$1 title=$2 backup
    screen_title "$title / 添加"
    choose_entry_type || return
    printf '\n'
    read_entry_value "$SELECTED_KIND" || return
    if grep -Fxq "$SELECTED_KIND|$ENTRY_VALUE" "$file" 2>/dev/null; then
        yellow '这条规则已经存在，无需重复添加。'
        return
    fi
    backup=$(mktemp)
    cp "$file" "$backup" || { rm -f "$backup"; red '无法备份规则文件。'; return; }
    printf '%s|%s\n' "$SELECTED_KIND" "$ENTRY_VALUE" >> "$file" || {
        cp "$backup" "$file" 2>/dev/null || true
        rm -f "$backup"
        red '无法写入规则文件。'
        return
    }
    if ! apply_and_save; then
        cp "$backup" "$file"
        rm -f "$backup"
        if reapply_after_rollback; then
            red '规则未生效，添加操作已回滚。'
        else
            red '配置已回滚，但防火墙回滚未完成；请执行 blockip --apply。'
        fi
        return
    fi
    rm -f "$backup"
    green "添加成功：$ENTRY_VALUE"
}

list_entries() {
    local file=$1
    if [ ! -s "$file" ]; then
        printf '%s\n' '暂无记录。'
        return
    fi
    printf '%-6s %-14s %s\n' '编号' '类型' '内容'
    printf '%s\n' '--------------------------------------------------'
    awk -F'|' '{ type=$1; if (type=="IP") type="单个 IPv4"; else if (type=="NET") type="IPv4 网段"; else if (type=="DOMAIN") type="域名"; printf "%-6d %-14s %s\n", NR, type, $2 }' "$file"
}

delete_entry() {
    local file=$1 title=$2 line='' tmp current='' confirm='' backup
    screen_title "$title / 删除"
    list_entries "$file"
    [ -s "$file" ] || return
    printf '\n'
    read -r -p '请输入要删除的编号 [0=返回]：' line || return
    [ "$line" = 0 ] && return
    [[ "$line" =~ ^[0-9]+$ ]] || { red '请输入有效的编号。'; return; }
    current=$(sed -n "${line}p" "$file")
    [ -n "$current" ] || { red '找不到这个编号。'; return; }
    printf '即将删除：%s\n' "${current#*|}"
    read -r -p '确认删除？[y/N]（回车默认 y）：' confirm || { yellow '输入已结束，取消删除。'; return; }
    [[ -z "$confirm" || "$confirm" =~ ^[Yy]$ ]] || { yellow '已取消删除。'; return; }
    backup=$(mktemp)
    cp "$file" "$backup" || { rm -f "$backup"; red '无法备份规则文件。'; return; }
    tmp=$(mktemp)
    if ! awk -v n="$line" 'NR != n' "$file" > "$tmp" || ! mv "$tmp" "$file"; then
        rm -f "$tmp" "$backup"
        red '无法更新规则文件。'
        return
    fi
    if ! apply_and_save; then
        cp "$backup" "$file"
        rm -f "$backup"
        if reapply_after_rollback; then
            red '规则未生效，删除操作已回滚。'
        else
            red '配置已回滚，但防火墙回滚未完成；请执行 blockip --apply。'
        fi
        return
    fi
    rm -f "$backup"
    green '删除成功。'
}

edit_entry() {
    local file=$1 title=$2 line='' tmp current='' backup
    screen_title "$title / 修改"
    list_entries "$file"
    [ -s "$file" ] || return
    printf '\n'
    read -r -p '请输入要修改的编号 [0=返回]：' line || return
    [ "$line" = 0 ] && return
    [[ "$line" =~ ^[0-9]+$ ]] || { red '请输入有效的编号。'; return; }
    current=$(sed -n "${line}p" "$file")
    [ -n "$current" ] || { red '找不到这个编号。'; return; }
    printf '当前内容：%s\n\n' "${current#*|}"
    choose_entry_type || return
    printf '\n'
    read_entry_value "$SELECTED_KIND" || return
    if awk -F'|' -v value="$ENTRY_VALUE" '$2 == value { found=1 } END { exit found ? 0 : 1 }' "$file"; then
        yellow '这条规则已经存在，无需重复添加。'
        return
    fi
    backup=$(mktemp)
    cp "$file" "$backup" || { rm -f "$backup"; red '无法备份规则文件。'; return; }
    tmp=$(mktemp)
    if ! awk -v n="$line" -v replacement="$SELECTED_KIND|$ENTRY_VALUE" 'NR == n { print replacement; next } { print }' "$file" > "$tmp" || ! mv "$tmp" "$file"; then
        rm -f "$tmp" "$backup"
        red '无法更新规则文件。'
        return
    fi
    if ! apply_and_save; then
        cp "$backup" "$file"
        rm -f "$backup"
        if reapply_after_rollback; then
            red '规则未生效，修改操作已回滚。'
        else
            red '配置已回滚，但防火墙回滚未完成；请执行 blockip --apply。'
        fi
        return
    fi
    rm -f "$backup"
    green "修改成功：$ENTRY_VALUE"
}

pause_menu() {
    local _=''
    printf '\n'
    read -r -p '按 Enter 键继续...' _ || true
}

manage_entries() {
    local file=$1 title=$2 choice=''
    while true; do
        screen_title "$title"
        menu_item 1 '添加规则'
        menu_item 2 '删除规则'
        menu_item 3 '修改规则'
        menu_item 4 '查看规则'
        menu_item 0 '返回主菜单'
        read -r -p '请输入选项 [0-4]：' choice || return
        case "$choice" in
            1) add_entry "$file" "$title"; pause_menu ;;
            2) delete_entry "$file" "$title"; pause_menu ;;
            3) edit_entry "$file" "$title"; pause_menu ;;
            4) screen_title "$title / 查看"; list_entries "$file"; pause_menu ;;
            0) return ;;
            *) red '请输入 0 到 4 之间的数字。'; sleep 1 ;;
        esac
    done
}

uninstall_cleanup() {
    local confirm='' firewall_cleanup_ok=1
    screen_title '一键卸载清理'
    printf '%s\n' '此操作会删除 blockip 创建的防火墙链、定时任务和配置。'
    printf '不会卸载系统的 iptables 软件包，也不会修改其他防火墙链。\n'
    read -r -p '确认卸载清理？[y/N]：' confirm || { yellow '输入已结束，取消卸载。'; return; }
    [[ "$confirm" =~ ^[Yy]$ ]] || { yellow '已取消卸载。'; pause_menu; return; }

    if have_cmd systemctl && [ -d /run/systemd/system ]; then
        systemctl disable --now blockip-refresh.timer blockip.service >/dev/null 2>&1 || true
    fi
    rm -f "$SERVICE_FILE" "$REFRESH_SERVICE_FILE" "$TIMER_FILE"
    if have_cmd systemctl && [ -d /run/systemd/system ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed blockip.service blockip-refresh.service blockip-refresh.timer >/dev/null 2>&1 || true
    fi
    if have_cmd iptables; then
        remove_chain "$STAGING_CHAIN" >/dev/null 2>&1 || firewall_cleanup_ok=0
        remove_chain "$CHAIN" >/dev/null 2>&1 || firewall_cleanup_ok=0
    else
        firewall_cleanup_ok=0
    fi
    rm -f /etc/cron.d/blockip
    rm -rf -- "$STATE_DIR"
    rm -f "$BIN_PATH"
    if [ "$firewall_cleanup_ok" -eq 1 ]; then
        green 'blockip 程序、规则、配置和 systemd 自动任务已清理。'
    else
        yellow '程序和配置已删除，但防火墙链未能完全移除；请检查 iptables 权限后手工清理 BLOCKIP_INPUT。'
    fi
    exit 0
}

menu() {
    local mode cn_enabled foreign_enabled cn_action foreign_action choice='' confirm=''
    while true; do
        screen_title "BlockIP 防火墙管理"
        mode=$(tr -d '[:space:]' < "$MODE_FILE")
        cn_enabled=0
        foreign_enabled=0
        case "$mode" in
            block_cn) cn_enabled=1 ;;
            block_foreign) foreign_enabled=1 ;;
            both) cn_enabled=1; foreign_enabled=1 ;;
        esac
        [ "$cn_enabled" -eq 1 ] && cn_action='关闭屏蔽国内 IP' || cn_action='开启屏蔽国内 IP'
        [ "$foreign_enabled" -eq 1 ] && foreign_action='关闭屏蔽国外 IP' || foreign_action='开启屏蔽国外 IP'
        menu_item 1 "$cn_action"
        menu_item 2 "$foreign_action"
        menu_item 3 '白名单管理'
        menu_item 4 '手工屏蔽管理'
        menu_item 5 '一键卸载清理'
        menu_item 0 '退出'
        read -r -p '请输入选项 [0-5]：' choice || { printf '\n'; return; }
        case "$choice" in
            1)
                if [ "$cn_enabled" -eq 1 ]; then toggle_region cn off; else toggle_region cn on; fi
                pause_menu
                ;;
            2)
                if [ "$foreign_enabled" -eq 1 ]; then
                    toggle_region foreign off
                else
                    yellow '警告：开启后，国外来源的新连接会被拒绝；如果当前已开启国内屏蔽，则两边都会被拒绝。'
                    read -r -p '确认开启？[y/N]（回车默认 y）：' confirm || confirm='n'
                    [[ -z "$confirm" || "$confirm" =~ ^[Yy]$ ]] && toggle_region foreign on
                fi
                pause_menu
                ;;
            3) manage_entries "$WHITELIST_FILE" '白名单' ;;
            4) manage_entries "$BLOCKLIST_FILE" '手工屏蔽' ;;
            5) uninstall_cleanup ;;
            0) exit 0 ;;
            *) red '无效选项。'; sleep 1 ;;
        esac
    done
}

main() {
    # Launching without sudo should still show the menu: re-run this same
    # script through sudo instead of making the user remember the prefix.
    if [ "$(id -u)" -ne 0 ]; then
        exec sudo -E bash "$0" "$@"
    fi
    ensure_state
    ensure_dependencies
    install_self "$@"
    case "${1:-}" in
        --version)
            printf '%s %s\n' "$APP_NAME" "$VERSION"
            exit 0
            ;;
        --apply)
            apply_rules
            exit $?
            ;;
        --maintenance)
            apply_rules
            exit $?
            ;;
    esac
    if ! install_systemd_units; then
        yellow "自动恢复服务设置失败，仍可使用菜单管理当前防火墙规则。"
        pause_menu
    fi
    menu
}

main "$@"
