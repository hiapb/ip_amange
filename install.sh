#!/usr/bin/env bash
# blockip.sh - IPv4 country/manual firewall manager for Debian/Ubuntu.
# The script owns only the BLOCKIP_INPUT chain and its ipsets.

set -u

readonly APP_NAME="blockip"
readonly CHAIN="BLOCKIP_INPUT"
readonly CN_URL="https://www.ipdeny.com/ipblocks/data/countries/cn.zone"
readonly STATE_DIR="/etc/blockip"
readonly CN_ZONE="${STATE_DIR}/cn.zone"
readonly MODE_FILE="${STATE_DIR}/mode"
readonly WHITELIST_FILE="${STATE_DIR}/whitelist.conf"
readonly BLOCKLIST_FILE="${STATE_DIR}/blocklist.conf"
readonly IPSET_WHITELIST="blockip_whitelist"
readonly IPSET_BLOCKLIST="blockip_blocklist"
readonly IPSET_CN="blockip_cn"
readonly UPDATE_MAX_AGE=604800
# Domain records are refreshed at most once per hour when rules are applied.
readonly DNS_CACHE_TTL=3600
readonly CRON_FILE="/etc/cron.d/blockip"
readonly DNS_CACHE_DIR="${STATE_DIR}/dns-cache"
readonly DEPENDENCY_MARKER="${STATE_DIR}/.dependencies-ok"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
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

ipset_persistence_ready() {
    compgen -G '/usr/share/netfilter-persistent/plugins.d/*ipset*' >/dev/null 2>&1
}

runtime_dependencies_ready() {
    have_cmd iptables &&
    have_cmd iptables-save &&
    have_cmd ipset &&
    have_cmd netfilter-persistent &&
    ipset_persistence_ready &&
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
    { have_cmd sha256sum || have_cmd cksum; } &&
    { have_cmd cron || have_cmd crond; }
}

install_dependencies() {
    local packages=()
    require_root
    have_cmd apt-get || die "未找到 apt-get，请手动安装 iptables 和 ipset。"
    have_cmd iptables || packages+=(iptables)
    have_cmd iptables-save || packages+=(iptables)
    have_cmd ipset || packages+=(ipset)
    have_cmd netfilter-persistent || packages+=(iptables-persistent)
    have_cmd cron || have_cmd crond || packages+=(cron)
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
    have_cmd sha256sum || have_cmd cksum || packages+=(coreutils)
    if have_cmd dpkg-query && ! dpkg-query -W -f='${Status}' ca-certificates 2>/dev/null | grep -q 'install ok installed'; then
        packages+=(ca-certificates)
    fi
    # ipset-persistent is a plugin, so it does not provide a command to test.
    if have_cmd dpkg-query && ! dpkg-query -W -f='${Status}' ipset-persistent 2>/dev/null | grep -q 'install ok installed'; then
        if ! have_cmd apt-cache || apt-cache show ipset-persistent >/dev/null 2>&1; then
            packages+=(ipset-persistent)
        fi
    fi
    if [ "${#packages[@]}" -eq 0 ]; then
        runtime_dependencies_ready && { touch "$DEPENDENCY_MARKER"; return 0; }
        die "依赖状态异常：命令或 ipset 持久化插件不可用，但未找到可补装的软件包。"
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

valid_domain() {
    [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

download_cn_zone() {
    require_root
    ensure_state
    local tmp="${CN_ZONE}.tmp"
    if have_cmd curl; then
        curl -fsSL --connect-timeout 15 --max-time 120 "$CN_URL" -o "$tmp"
    elif have_cmd wget; then
        wget -q --timeout=15 -O "$tmp" "$CN_URL"
    else
        red "需要 curl 或 wget。"
        return 1
    fi || { rm -f "$tmp"; red "国内 IP 列表下载失败，请检查网络后重试。"; return 1; }
    [ -s "$tmp" ] || { rm -f "$tmp"; red "下载的国内 IP 列表为空。"; return 1; }
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
        NF == 1 && valid_cidr($1) { print $1; ok++ }
        END { if (ok < 10) exit 1 }
    ' "$tmp" > "${tmp}.clean" || {
        rm -f "$tmp" "${tmp}.clean"
        red "国内 IP 列表格式异常，未修改现有规则。"
        return 1
    }
    mv "${tmp}.clean" "$CN_ZONE"
    rm -f "$tmp"
    chmod 600 "$CN_ZONE"
    green "国内 IP 列表已更新：$(wc -l < "$CN_ZONE") 个网段。"
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

install_update_schedule() {
    local script_path
    have_cmd readlink || return 0
    script_path=$(readlink -f "$0" 2>/dev/null || true)
    [ -n "$script_path" ] || return 0
    mkdir -p /etc/cron.d
    printf '# Managed by blockip.sh\n17 4 * * 1 root %s --refresh >/dev/null 2>&1\n' "$script_path" > "$CRON_FILE"
    chmod 644 "$CRON_FILE"
    if have_cmd systemctl; then
        systemctl enable --now cron >/dev/null 2>&1 || systemctl enable --now crond >/dev/null 2>&1 || true
    elif have_cmd service; then
        service cron start >/dev/null 2>&1 || service crond start >/dev/null 2>&1 || true
    fi
}

create_set() {
    local name=$1
    ipset create "$name" hash:net family inet hashsize 4096 maxelem 1048576 -exist
}

resolve_domain() {
    local domain=$1 ip now modified age cache_file cache_key ips
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
    : > "$cache_file"
    while read -r ip; do
        valid_ipv4_or_cidr "$ip" && printf '%s\n' "$ip" >> "$cache_file"
    done <<< "$ips"
    cat "$cache_file"
}

populate_set_from_file() {
    local set_name=$1 file=$2 line kind value ip
    ipset flush "$set_name"
    while IFS='|' read -r kind value; do
        [ -n "${kind:-}" ] || continue
        [[ "$kind" == \#* ]] && continue
        value=${value%%[[:space:]]*}
        case "$kind" in
            IP|NET)
                valid_ipv4_or_cidr "$value" && ipset add "$set_name" "$value" -exist
                ;;
            DOMAIN)
                while read -r ip; do ipset add "$set_name" "$ip" -exist; done < <(resolve_domain "$value")
                ;;
        esac
    done < "$file"
}

populate_cn_set() {
    ipset flush "$IPSET_CN"
    [ -s "$CN_ZONE" ] || return 0
    while read -r network; do
        valid_ipv4_or_cidr "$network" && ipset add "$IPSET_CN" "$network" -exist
    done < "$CN_ZONE"
}

ensure_chain() {
    iptables -N "$CHAIN" 2>/dev/null || true
    # Remove duplicate jumps, then put exactly one jump at INPUT's head.
    while iptables -C INPUT -j "$CHAIN" 2>/dev/null; do iptables -D INPUT -j "$CHAIN"; done
    iptables -I INPUT 1 -j "$CHAIN"
}

apply_rules() {
    require_root
    ensure_dependencies
    ensure_state
    local mode
    mode=$(tr -d '[:space:]' < "$MODE_FILE")
    case "$mode" in
        block_cn|block_foreign)
            ensure_cn_zone || return 1
            install_update_schedule
            ;;
    esac
    create_set "$IPSET_WHITELIST"
    create_set "$IPSET_BLOCKLIST"
    create_set "$IPSET_CN"
    populate_set_from_file "$IPSET_WHITELIST" "$WHITELIST_FILE"
    populate_set_from_file "$IPSET_BLOCKLIST" "$BLOCKLIST_FILE"
    populate_cn_set
    ensure_chain
    iptables -F "$CHAIN"
    iptables -A "$CHAIN" -i lo -j ACCEPT
    iptables -A "$CHAIN" -m set --match-set "$IPSET_WHITELIST" src -j ACCEPT
    iptables -A "$CHAIN" -p icmp --icmp-type echo-request -m set --match-set "$IPSET_BLOCKLIST" src -j DROP
    # Evaluate new inbound ping requests before conntrack so an already-running
    # ping reflects a region switch immediately, while established TCP survives.
    case "$mode" in
        block_cn)
            iptables -A "$CHAIN" -p icmp --icmp-type echo-request -m set --match-set "$IPSET_CN" src -j DROP
            ;;
        block_foreign)
            iptables -A "$CHAIN" -p icmp --icmp-type echo-request -m set --match-set "$IPSET_CN" src -j ACCEPT
            iptables -A "$CHAIN" -p icmp --icmp-type echo-request -j DROP
            ;;
        both)
            iptables -A "$CHAIN" -p icmp --icmp-type echo-request -j DROP
            ;;
    esac
    iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A "$CHAIN" -m set --match-set "$IPSET_BLOCKLIST" src -j DROP
    case "$mode" in
        block_cn)
            iptables -A "$CHAIN" -m set --match-set "$IPSET_CN" src -j DROP
            ;;
        block_foreign)
            iptables -A "$CHAIN" -m set --match-set "$IPSET_CN" src -j ACCEPT
            iptables -A "$CHAIN" -j DROP
            ;;
        both)
            # In both mode only the established/local/whitelisted sources survive.
            iptables -A "$CHAIN" -j DROP
            ;;
        none|*)
            ;;
    esac
    green "规则已应用，当前模式：$(mode_label "$mode")"
}

save_rules() {
    require_root
    mkdir -p /etc/iptables
    if have_cmd ipset; then
        ipset save > /etc/iptables/ipsets || die "ipset 规则保存失败。"
    fi
    if have_cmd netfilter-persistent; then
        netfilter-persistent save >/dev/null 2>&1 && netfilter-persistent reload >/dev/null 2>&1 || \
            die "netfilter-persistent 保存或加载失败。"
        green "iptables/ipset 规则已持久化。"
        return 0
    fi
    have_cmd iptables-save || die "未找到 iptables-save。"
    iptables-save > /etc/iptables/rules.v4 || die "规则保存失败。"
    green "iptables 规则已保存到 /etc/iptables/rules.v4（请安装 ipset-persistent 以恢复 ipset）。"
}

apply_and_save() {
    apply_rules && save_rules
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
        red "操作失败，已恢复之前的开关状态。"
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
    printf '%s\n' '--------------------------------------------------'
    printf '  %s\n' "$1"
    printf '%s\n\n' '--------------------------------------------------'
}

choose_entry_type() {
    local choice
    printf '%s\n' '请选择规则类型：'
    printf '%s\n' '  1. 单个 IPv4 地址'
    printf '%s\n' '  2. IPv4 网段（CIDR）'
    printf '%s\n' '  3. 域名'
    printf '%s\n\n' '  0. 返回'
    read -r -p '请输入选项 [0-3]：' choice
    case "$choice" in
        1) SELECTED_KIND=IP ;;
        2) SELECTED_KIND=NET ;;
        3) SELECTED_KIND=DOMAIN ;;
        0) return 1 ;;
        *) red '请输入 0 到 3 之间的数字。'; return 1 ;;
    esac
}

read_entry_value() {
    local kind=$1 value
    case "$kind" in
        IP) read -r -p '请输入 IPv4 地址（例如 203.0.113.10）：' value ;;
        NET) read -r -p '请输入 IPv4 网段（例如 203.0.113.0/24）：' value ;;
        DOMAIN) read -r -p '请输入域名（例如 example.com）：' value ;;
    esac
    value=$(printf '%s' "$value" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -n "$value" ] || { red '输入不能为空。'; return 1; }
    if [ "$kind" = DOMAIN ]; then
        valid_domain "$value" || { red '域名格式不正确。'; return 1; }
        resolve_domain "$value" | grep -q . || { red '域名没有解析到 IPv4 地址，请检查域名或 DNS。'; return 1; }
    else
        valid_ipv4_or_cidr "$value" || { red 'IPv4 地址或网段格式不正确。'; return 1; }
    fi
    ENTRY_VALUE=$value
}

add_entry() {
    local file=$1 title=$2
    screen_title "$title / 添加"
    choose_entry_type || return
    printf '\n'
    read_entry_value "$SELECTED_KIND" || return
    if grep -Fxq "$SELECTED_KIND|$ENTRY_VALUE" "$file" 2>/dev/null; then
        yellow '这条规则已经存在，无需重复添加。'
        return
    fi
    printf '%s|%s\n' "$SELECTED_KIND" "$ENTRY_VALUE" >> "$file"
    apply_and_save
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
    local file=$1 title=$2 line tmp current confirm
    screen_title "$title / 删除"
    list_entries "$file"
    [ -s "$file" ] || return
    printf '\n'
    read -r -p '请输入要删除的编号 [0=返回]：' line
    [ "$line" = 0 ] && return
    [[ "$line" =~ ^[0-9]+$ ]] || { red '请输入有效的编号。'; return; }
    current=$(sed -n "${line}p" "$file")
    [ -n "$current" ] || { red '找不到这个编号。'; return; }
    printf '即将删除：%s\n' "${current#*|}"
    read -r -p '确认删除？[y/N]（回车默认 y）：' confirm
    [[ -z "$confirm" || "$confirm" =~ ^[Yy]$ ]] || { yellow '已取消删除。'; return; }
    tmp=$(mktemp)
    awk -v n="$line" 'NR != n' "$file" > "$tmp" && mv "$tmp" "$file"
    apply_and_save
    green '删除成功。'
}

edit_entry() {
    local file=$1 title=$2 line tmp current
    screen_title "$title / 修改"
    list_entries "$file"
    [ -s "$file" ] || return
    printf '\n'
    read -r -p '请输入要修改的编号 [0=返回]：' line
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
    tmp=$(mktemp)
    awk -v n="$line" -v replacement="$SELECTED_KIND|$ENTRY_VALUE" 'NR == n { print replacement; next } { print }' "$file" > "$tmp" && mv "$tmp" "$file"
    apply_and_save
    green "修改成功：$ENTRY_VALUE"
}

show_status() {
    local mode cn_status foreign_status
    mode=$(tr -d '[:space:]' < "$MODE_FILE" 2>/dev/null || printf none)
    case "$mode" in
        block_cn) cn_status='开启'; foreign_status='关闭' ;;
        block_foreign) cn_status='关闭'; foreign_status='开启' ;;
        both) cn_status='开启'; foreign_status='开启' ;;
        *) cn_status='关闭'; foreign_status='关闭' ;;
    esac
    printf '\n国内 IP 屏蔽：%s    国外 IP 屏蔽：%s\n' "$cn_status" "$foreign_status"
    printf '白名单：%s 条    手工屏蔽：%s 条\n' "$(grep -c . "$WHITELIST_FILE" 2>/dev/null || true)" "$(grep -c . "$BLOCKLIST_FILE" 2>/dev/null || true)"
}

pause_menu() {
    printf '\n'
    read -r -p '按 Enter 键继续...' _
}

manage_entries() {
    local file=$1 title=$2 choice
    while true; do
        screen_title "$title"
        list_entries "$file"
        printf '\n%s\n' '  1. 添加规则'
        printf '%s\n' '  2. 删除规则'
        printf '%s\n' '  3. 修改规则'
        printf '%s\n\n' '  0. 返回主菜单'
        read -r -p '请输入选项 [0-3]：' choice
        case "$choice" in
            1) add_entry "$file" "$title"; pause_menu ;;
            2) delete_entry "$file" "$title"; pause_menu ;;
            3) edit_entry "$file" "$title"; pause_menu ;;
            0) return ;;
            *) red '请输入 0 到 3 之间的数字。'; sleep 1 ;;
        esac
    done
}

uninstall_cleanup() {
    local confirm
    screen_title '一键卸载清理'
    printf '%s\n' '此操作会删除 blockip 创建的防火墙链、ipset、定时任务和配置。'
    printf '不会卸载系统的 iptables/ipset 软件包，也不会修改其他防火墙链。\n'
    read -r -p '确认卸载清理？[y/N]：' confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { yellow '已取消卸载。'; pause_menu; return; }

    if have_cmd iptables; then
        while iptables -C INPUT -j "$CHAIN" 2>/dev/null; do iptables -D INPUT -j "$CHAIN"; done
        iptables -F "$CHAIN" 2>/dev/null || true
        iptables -X "$CHAIN" 2>/dev/null || true
    fi
    if have_cmd ipset; then
        ipset destroy "$IPSET_WHITELIST" 2>/dev/null || true
        ipset destroy "$IPSET_BLOCKLIST" 2>/dev/null || true
        ipset destroy "$IPSET_CN" 2>/dev/null || true
    fi
    rm -f "$CRON_FILE" "$MODE_FILE" "$WHITELIST_FILE" "$BLOCKLIST_FILE" "$CN_ZONE" "$DEPENDENCY_MARKER"
    rm -f "$DNS_CACHE_DIR"/* 2>/dev/null || true
    rmdir "$DNS_CACHE_DIR" 2>/dev/null || true
    rmdir "$STATE_DIR" 2>/dev/null || true
    if have_cmd netfilter-persistent; then
        netfilter-persistent save >/dev/null 2>&1 || true
        netfilter-persistent reload >/dev/null 2>&1 || true
    elif have_cmd iptables-save; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    green 'blockip 规则、配置和自动更新任务已清理。'
    exit 0
}

menu() {
    local mode cn_enabled foreign_enabled cn_action foreign_action choice confirm
    while true; do
        screen_title 'blockip 防火墙管理'
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
        printf '\n%s\n' "1. $cn_action"
        printf '%s\n' "2. $foreign_action"
        printf '%s\n' '3. 白名单管理'
        printf '%s\n' '4. 手工屏蔽管理'
        printf '%s\n' '5. 查看当前规则'
        printf '%s\n' '6. 一键卸载清理'
        printf '%s\n\n' '0. 退出'
        read -r -p '请输入选项 [0-6]：' choice
        case "$choice" in
            1)
                if [ "$cn_enabled" -eq 1 ]; then toggle_region cn off; else toggle_region cn on; fi
                ;;
            2)
                if [ "$foreign_enabled" -eq 1 ]; then
                    toggle_region foreign off
                else
                    yellow '警告：开启后，国外来源的新连接会被拒绝；如果当前已开启国内屏蔽，则两边都会被拒绝。'
                    read -r -p '确认开启？[y/N]（回车默认 y）：' confirm
                    [[ -z "$confirm" || "$confirm" =~ ^[Yy]$ ]] && toggle_region foreign on
                fi
                ;;
            3) manage_entries "$WHITELIST_FILE" '白名单' ;;
            4) manage_entries "$BLOCKLIST_FILE" '手工屏蔽' ;;
            5)
                screen_title '当前规则'
                show_status
                printf '\n实际防火墙链规则：\n'
                iptables -S "$CHAIN" 2>/dev/null || yellow '当前还没有应用 blockip 规则。'
                pause_menu
                ;;
            6) uninstall_cleanup ;;
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
    case "${1:-}" in
        --refresh)
            mode=$(tr -d '[:space:]' < "$MODE_FILE")
            case "$mode" in
                block_cn|block_foreign) download_cn_zone; apply_and_save ;;
                *) exit 0 ;;
            esac
            exit 0
            ;;
    esac
    menu
}

main "$@"
