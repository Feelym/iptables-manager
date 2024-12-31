###################
# 颜色定义
###################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # 无颜色

###################
# 全局变量
###################
FORWARD_RULES_FILE="/etc/iptables-forward-rules.conf"
FORWARD_RULES_FILE_IPV6="/etc/ip6tables-forward-rules.conf"
BACKUP_DIR="/root/iptables_backups"
BACKUP_FILE="${BACKUP_DIR}/iptables_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
SYSCTL_CONF="/etc/sysctl.conf"

###################
# 辅助函数
###################
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误：此脚本需要root权限运行${NC}"
        exit 1
    fi
}

print_banner() {
    clear
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}                        IPTables 端口转发管理工具                           ${NC}"
    echo -e "${CYAN}                        作者: 路飞    版本: 3.2                           ${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

backup_rules() {
    mkdir -p "$BACKUP_DIR"
    temp_rules="/tmp/iptables_rules.v4"
    temp_rules_ipv6="/tmp/iptables_rules.v6"
    iptables-save > "$temp_rules"
    ip6tables-save > "$temp_rules_ipv6"
    tar -czf "$BACKUP_FILE" -C /tmp iptables_rules.v4 iptables_rules.v6 -C /etc iptables-forward-rules.conf ip6tables-forward-rules.conf
    rm -f "$temp_rules" "$temp_rules_ipv6"
    echo -e "${GREEN}规则已备份到: $BACKUP_FILE${NC}"
}

enable_ip_forward() {
    local tmp_sysctl="/tmp/sysctl_temp.conf"
    cat > "$tmp_sysctl" << EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
vm.swappiness = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 212992 16777216
net.ipv4.tcp_wmem = 4096 212992 16777216
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
EOF
    if [ -f "$SYSCTL_CONF" ]; then
        cp "$SYSCTL_CONF" "${SYSCTL_CONF}.bak"
        grep -v -F -f <(grep -v '^#' "$tmp_sysctl" | cut -d= -f1 | tr -d ' ') "$SYSCTL_CONF" > "${SYSCTL_CONF}.tmp"
        mv "${SYSCTL_CONF}.tmp" "$SYSCTL_CONF"
    fi
    cat "$tmp_sysctl" >> "$SYSCTL_CONF"
    sysctl -p "$SYSCTL_CONF"
    rm -f "$tmp_sysctl"
    create_startup_script
    echo -e "${GREEN}IP转发已启用、系统参数已优化，并已创建开机自启动脚本${NC}"
}

add_forward_rule() {
    echo -e "${YELLOW}请输入源端口：${NC}"
    read -p "> " src_port
    echo -e "${YELLOW}请输入目标服务器IP：${NC}"
    read -p "> " target_ip
    echo -e "${YELLOW}请输入目标端口：${NC}"
    read -p "> " target_port
    if [[ ! $src_port =~ ^[0-9]+$ ]] || [[ ! $target_port =~ ^[0-9]+$ ]] || [[ ! $target_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo -e "${RED}无效的输入格式${NC}"
        return 1
    fi
    if grep -q "^$src_port " "$FORWARD_RULES_FILE"; then
        echo -e "${RED}源端口 $src_port 已被使用${NC}"
        return 1
    fi
    echo "$src_port both $target_ip $target_port" >> "$FORWARD_RULES_FILE"
    iptables -t nat -A PREROUTING -p tcp --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}"
    iptables -t nat -A PREROUTING -p udp --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}"
    iptables -t nat -A POSTROUTING -p tcp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
    iptables -t nat -A POSTROUTING -p udp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
    iptables -A FORWARD -p tcp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
    iptables -A FORWARD -p udp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
    iptables -A FORWARD -p tcp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
    iptables -A FORWARD -p udp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
    echo -e "${GREEN}转发规则添加成功${NC}"
    optimize_rules
    sleep 1
}

delete_forward_rule() {
    if [ ! -f "$FORWARD_RULES_FILE" ]; then
        echo -e "${RED}没有可删除的规则${NC}"
        sleep 1
        return
    fi
    echo -e "${YELLOW}请选择要删除的规则编号：${NC}"
    awk '{printf "%d. %s -> %s:%s (%s)\n", NR, $1, $3, $4, $2}' "$FORWARD_RULES_FILE"
    read -p "> " rule_num
    if [[ ! $rule_num =~ ^[0-9]+$ ]]; then
        echo -e "${RED}无效的输入${NC}"
        sleep 1
        return
    fi
    rule=$(sed -n "${rule_num}p" "$FORWARD_RULES_FILE")
    if [ -n "$rule" ]; then
        read -r src_port protocol target_ip target_port <<< "$rule"
        echo -e "${YELLOW}正在清除所有与 ${target_ip}:${target_port} 相关的规则...${NC}"
        if [ "$protocol" = "both" ] || [ "$protocol" = "tcp" ]; then
            iptables -t nat -D PREROUTING -p tcp --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}" 2>/dev/null
            iptables -t nat -D POSTROUTING -p tcp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE 2>/dev/null
            iptables -D FORWARD -p tcp -d "${target_ip}" --dport "${target_port}" -j ACCEPT 2>/dev/null
            iptables -D FORWARD -p tcp -s "${target_ip}" --sport "${target_port}" -j ACCEPT 2>/dev/null
        fi
        if [ "$protocol" = "both" ] || [ "$protocol" = "udp" ]; then
            iptables -t nat -D PREROUTING -p udp --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}" 2>/dev/null
            iptables -t nat -D POSTROUTING -p udp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE 2>/dev/null
            iptables -D FORWARD -p udp -d "${target_ip}" --dport "${target_port}" -j ACCEPT 2>/dev/null
            iptables -D FORWARD -p udp -s "${target_ip}" --sport "${target_port}" -j ACCEPT 2>/dev/null
        fi
        sed -i "${rule_num}d" "$FORWARD_RULES_FILE"
        echo -e "${GREEN}已清除与 ${target_ip}:${target_port} 相关的规则${NC}"
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save
            netfilter-persistent reload
            echo -e "${GREEN}规则已保存并重新加载${NC}"
        else
            echo -e "${YELLOW}请注意：系统未安装 netfilter-persistent，规则可能需要手动保存${NC}"
            echo -e "${YELLOW}建议安装：apt-get install iptables-persistent${NC}"
        fi
    else
        echo -e "${RED}无效的规则编号${NC}"
    fi
    sleep 1
}

add_ipv6_forward_rule() {
    echo -e "${YELLOW}请输入源端口：${NC}"
    read -p "> " src_port
    echo -e "${YELLOW}请输入目标服务器IPv6地址：${NC}"
    read -p "> " target_ip
    echo -e "${YELLOW}请输入目标端口：${NC}"
    read -p "> " target_port
    if [[ ! $src_port =~ ^[0-9]+$ ]] || [[ ! $target_port =~ ^[0-9]+$ ]] || ! valid_ipv6 "$target_ip"; then
        echo -e "${RED}无效的输入格式${NC}"
        return 1
    fi
    if grep -q "^$src_port " "$FORWARD_RULES_FILE_IPV6"; then
        echo -e "${RED}源端口 $src_port 已被使用${NC}"
        return 1
    fi
    echo "$src_port both $target_ip $target_port" >> "$FORWARD_RULES_FILE_IPV6"
    ip6tables -t nat -A PREROUTING -p tcp --dport "$src_port" -j DNAT --to-destination "[${target_ip}]:${target_port}"
    ip6tables -t nat -A PREROUTING -p udp --dport "$src_port" -j DNAT --to-destination "[${target_ip}]:${target_port}"
    ip6tables -t nat -A POSTROUTING -p tcp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -p udp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
    ip6tables -A FORWARD -p tcp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
    ip6tables -A FORWARD -p udp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
    ip6tables -A FORWARD -p tcp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
    ip6tables -A FORWARD -p udp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
    echo -e "${GREEN}IPv6转发规则添加成功${NC}"
    optimize_ipv6_rules
    sleep 1
}

valid_ipv6() {
    local ip=$1
    if [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
        return 0
    else
        return 1
    fi
}

save_rules() {
    backup_rules
    sleep 1
}

create_startup_script() {
    cat > /usr/local/bin/iptables-forward.sh << 'EOF'
#!/bin/bash
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
sysctl -w net.ipv6.conf.all.forwarding=1
FORWARD_RULES_FILE="/etc/iptables-forward-rules.conf"
if [ -f "$FORWARD_RULES_FILE" ]; then
    while read -r src_port protocol target_ip target_port; do
        if [ "$protocol" = "both" ] || [ "$protocol" = "tcp" ]; then
            iptables -t nat -A PREROUTING -p tcp --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}"
            iptables -t nat -A POSTROUTING -p tcp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
            iptables -A FORWARD -p tcp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
            iptables -A FORWARD -p tcp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
        fi
        if [ "$protocol" = "both" ] || [ "$protocol" = "udp" ]; then
            iptables -t nat -A PREROUTING -p udp --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}"
            iptables -t nat -A POSTROUTING -p udp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
            iptables -A FORWARD -p udp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
            iptables -A FORWARD -p udp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
        fi
    done < "$FORWARD_RULES_FILE"
fi
FORWARD_RULES_FILE_IPV6="/etc/ip6tables-forward-rules.conf"
if [ -f "$FORWARD_RULES_FILE_IPV6" ]; then
    while read -r src_port protocol target_ip target_port; do
        if [ "$protocol" = "both" ] || [ "$protocol" = "tcp" ]; then
            ip6tables -t nat -A PREROUTING -p tcp --dport "$src_port" -j DNAT --to-destination "[${target_ip}]:${target_port}"
            ip6tables -t nat -A POSTROUTING -p tcp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
            ip6tables -A FORWARD -p tcp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
            ip6tables -A FORWARD -p tcp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
        fi
        if [ "$protocol" = "both" ] || [ "$protocol" = "udp" ]; then
            ip6tables -t nat -A PREROUTING -p udp --dport "$src_port" -j DNAT --to-destination "[${target_ip}]:${target_port}"
            ip6tables -t nat -A POSTROUTING -p udp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
            ip6tables -A FORWARD -p udp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
            ip6tables -A FORWARD -p udp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
        fi
    done < "$FORWARD_RULES_FILE_IPV6"
fi
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
EOF
    chmod +x /usr/local/bin/iptables-forward.sh
    if [ -d /etc/systemd/system ]; then
        cat > /etc/systemd/system/iptables-forward.service << EOF
[Unit]
Description=IPTables Forward Rules
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/iptables-forward.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable iptables-forward.service
        echo -e "${GREEN}已创建并启用systemd服务${NC}"
    elif [ -f /etc/crontab ]; then
        echo "@reboot root /usr/local/bin/iptables-forward.sh" >> /etc/crontab
        echo -e "${GREEN}已添加到crontab开机任务${NC}"
    else
        if [ -f /etc/rc.local ]; then
            sed -i '/exit 0/i \/usr/local/bin/iptables-forward.sh' /etc/rc.local
        else
            cat > /etc/rc.local << EOF
#!/bin/bash
/usr/local/bin/iptables-forward.sh
exit 0
EOF
            chmod +x /etc/rc.local
        fi
        echo -e "${GREEN}已添加到rc.local${NC}"
    fi
    echo -e "${GREEN}开机自启动脚本创建成功！${NC}"
    echo -e "${CYAN}脚本位置：/usr/local/bin/iptables-forward.sh${NC}"
}

restore_rules() {
    if [ ! -d "$BACKUP_DIR" ]; then
        echo -e "${RED}没有找到备份目录${NC}"
        return
    fi
    echo -e "${YELLOW}可用的备份文件：${NC}"
    ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null | nl -w2 -s'. '
    if [ $? -ne 0 ]; then
        echo -e "${RED}没有找到备份文件${NC}"
        sleep 1
        return
    fi
    echo ""
    echo -e "${YELLOW}请选择要恢复的备份文件编号（输入0取消）：${NC}"
    read -p "> " choice
    if [[ $choice == "0" ]]; then
        return
    fi
    selected_file=$(ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null | sed -n "${choice}p")
    if [[ -n "$selected_file" && -f "$selected_file" ]]; then
        backup_rules
        temp_extract="/tmp/iptables_restore_$(date +%s)"
        mkdir -p "$temp_extract"
        tar -xzf "$selected_file" -C "$temp_extract"
        if [ -f "$temp_extract/iptables_rules.v4" ]; then
            iptables-restore < "$temp_extract/iptables_rules.v4"
        fi
        if [ -f "$temp_extract/iptables_rules.v6" ]; then
            ip6tables-restore < "$temp_extract/iptables_rules.v6"
        fi
        if [ -f "$temp_extract/iptables-forward-rules.conf" ]; then
            cp "$temp_extract/iptables-forward-rules.conf" "$FORWARD_RULES_FILE"
        fi
        if [ -f "$temp_extract/ip6tables-forward-rules.conf" ]; then
            cp "$temp_extract/ip6tables-forward-rules.conf" "$FORWARD_RULES_FILE_IPV6"
        fi
        rm -rf "$temp_extract"
        echo -e "${GREEN}规则已恢复自: $selected_file${NC}"
    else
        echo -e "${RED}无效的选择${NC}"
    fi
    sleep 1
}

optimize_rules() {
    echo -e "${YELLOW}开始优化规则...${NC}"
    iptables -t nat -L PREROUTING --line-numbers -n | grep DNAT | awk '{print $1}' | while read line_num; do
        iptables -t nat -D PREROUTING $line_num
    done
    iptables -t nat -L POSTROUTING --line-numbers -n | grep MASQUERADE | awk '{print $1}' | while read line_num; do
        iptables -t nat -D POSTROUTING $line_num
    done
    iptables -L FORWARD --line-numbers -n | grep ACCEPT | awk '{print $1}' | while read line_num; do
        iptables -D FORWARD $line_num
    done
    if [ -f "$FORWARD_RULES_FILE" ]; then
        while read -r src_port protocol target_ip target_port; do
            if [ "$protocol" = "both" ] || [ "$protocol" = "tcp" ]; then
                iptables -t nat -A PREROUTING -p tcp --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}"
                iptables -t nat -A POSTROUTING -p tcp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
                iptables -A FORWARD -p tcp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
                iptables -A FORWARD -p tcp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
            fi
            if [ "$protocol" = "both" ] || [ "$protocol" = "udp" ]; then
                iptables -t nat -A PREROUTING -p udp --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}"
                iptables -t nat -A POSTROUTING -p udp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
                iptables -A FORWARD -p udp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
                iptables -A FORWARD -p udp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
            fi
        done < "$FORWARD_RULES_FILE"
    fi
    echo -e "${GREEN}规则优化完成！${NC}"
}

optimize_ipv6_rules() {
    echo -e "${YELLOW}开始优化IPv6规则...${NC}"
    ip6tables -t nat -L PREROUTING --line-numbers -n | grep DNAT | awk '{print $1}' | while read line_num; do
        ip6tables -t nat -D PREROUTING $line_num
    done
    ip6tables -t nat -L POSTROUTING --line-numbers -n | grep MASQUERADE | awk '{print $1}' | while read line_num; do
        ip6tables -t nat -D POSTROUTING $line_num
    done
    ip6tables -L FORWARD --line-numbers -n | grep ACCEPT | awk '{print $1}' | while read line_num; do
        ip6tables -D FORWARD $line_num
    done
    if [ -f "$FORWARD_RULES_FILE_IPV6" ]; then
        while read -r src_port protocol target_ip target_port; do
            if [ "$protocol" = "both" ] || [ "$protocol" = "tcp" ]; then
                ip6tables -t nat -A PREROUTING -p tcp --dport "$src_port" -j DNAT --to-destination "[${target_ip}]:${target_port}"
                ip6tables -t nat -A POSTROUTING -p tcp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
                ip6tables -A FORWARD -p tcp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
                ip6tables -A FORWARD -p tcp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
            fi
            if [ "$protocol" = "both" ] || [ "$protocol" = "udp" ]; then
                ip6tables -t nat -A PREROUTING -p udp --dport "$src_port" -j DNAT --to-destination "[${target_ip}]:${target_port}"
                ip6tables -t nat -A POSTROUTING -p udp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
                ip6tables -A FORWARD -p udp -d "${target_ip}" --dport "${target_port}" -j ACCEPT
                ip6tables -A FORWARD -p udp -s "${target_ip}" --sport "${target_port}" -j ACCEPT
            fi
        done < "$FORWARD_RULES_FILE_IPV6"
    fi
    echo -e "${GREEN}IPv6规则优化完成！${NC}"
}

check_forward_status() {
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                           系统状态                              │${NC}"
    echo -e "${CYAN}├──────────────────┬──────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│    IP转发状态    │${NC} $(cat /proc/sys/net/ipv4/ip_forward)                                        ${CYAN}│${NC}"
    echo -e "${CYAN}│    IPv6转发状态  │${NC} $(cat /proc/sys/net/ipv6/conf/all/forwarding)                                ${CYAN}│${NC}"
    echo -e "${CYAN}│    当前连接数    │${NC} $(netstat -nat | grep ESTABLISHED | wc -l)                                       ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────┴──────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                        当前转发规则                             │${NC}"
    echo -e "${CYAN}├────────────┬──────────┬───────────────────────┬──────────────────┤${NC}"
    echo -e "${CYAN}│   源端口   │ 协议    │       目标IP          │    目标端口     │${NC}"
    echo -e "${CYAN}├────────────┼──────────┼───────────────────────┼──────────────────┤${NC}"
    if [ -f "$FORWARD_RULES_FILE" ]; then
        while read -r src_port protocol target_ip target_port; do
            printf "${CYAN}│${NC} %-10s ${CYAN}│${NC} %-8s ${CYAN}│${NC} %-19s ${CYAN}│${NC} %-14s ${CYAN}│${NC}\n" "$src_port" "$protocol" "$target_ip" "$target_port"
        done < "$FORWARD_RULES_FILE"
    else
        echo -e "${CYAN}│${NC} 暂无转发规则                                                  ${CYAN}│${NC}"
    fi
    echo -e "${CYAN}└────────────┴──────────┴───────────────────────┴──────────────────┘${NC}"
    echo ""
}

manage_forward_rules() {
    while true; do
        clear
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}                           转发规则管理                                   ${NC}"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${YELLOW}请选择操作：${NC}"
        echo "1. 添加新的IPv4转发规则"
        echo "2. 删除IPv4转发规则"
        echo "3. 添加新的IPv6转发规则"
        echo "4. 删除IPv6转发规则"
        echo "0. 返回主菜单"
        echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}请选择操作 [0-4]:${NC}"
        read -p "> " sub_choice
        case $sub_choice in
            1)
                add_forward_rule
                read -p "按回车继续..."
                ;;
            2)
                delete_forward_rule
                read -p "按回车继续..."
                ;;
            3)
                add_ipv6_forward_rule
                read -p "按回车继续..."
                ;;
            4)
                delete_ipv6_forward_rule
                read -p "按回车继续..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}无效的选择${NC}"
                sleep 1
                ;;
        esac
    done
}

delete_ipv6_forward_rule() {
    if [ ! -f "$FORWARD_RULES_FILE_IPV6" ]; then
        echo -e "${RED}没有可删除的IPv6规则${NC}"
        sleep 1
        return
    fi
    echo -e "${YELLOW}请选择要删除的规则编号：${NC}"
    awk '{printf "%d. %s -> %s:%s (%s)\n", NR, $1, $3, $4, $2}' "$FORWARD_RULES_FILE_IPV6"
    read -p "> " rule_num
    if [[ ! $rule_num =~ ^[0-9]+$ ]]; then
        echo -e "${RED}无效的输入${NC}"
        sleep 1
        return
    fi
    rule=$(sed -n "${rule_num}p" "$FORWARD_RULES_FILE_IPV6")
    if [ -n "$rule" ]; then
        read -r src_port protocol target_ip target_port <<< "$rule"
        echo -e "${YELLOW}正在清除所有与 ${target_ip}:${target_port} 相关的规则...${NC}"
        if [ "$protocol" = "both" ] || [ "$protocol" = "tcp" ]; then
            ip6tables -t nat -D PREROUTING -p tcp --dport "$src_port" -j DNAT --to-destination "[${target_ip}]:${target_port}" 2>/dev/null
            ip6tables -t nat -D POSTROUTING -p tcp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE 2>/dev/null
            ip6tables -D FORWARD -p tcp -d "${target_ip}" --dport "${target_port}" -j ACCEPT 2>/dev/null
            ip6tables -D FORWARD -p tcp -s "${target_ip}" --sport "${target_port}" -j ACCEPT 2>/dev/null
        fi
        if [ "$protocol" = "both" ] || [ "$protocol" = "udp" ]; then
            ip6tables -t nat -D PREROUTING -p udp --dport "$src_port" -j DNAT --to-destination "[${target_ip}]:${target_port}" 2>/dev/null
            ip6tables -t nat -D POSTROUTING -p udp -d "${target_ip}" --dport "${target_port}" -j MASQUERADE 2>/dev/null
            ip6tables -D FORWARD -p udp -d "${target_ip}" --dport "${target_port}" -j ACCEPT 2>/dev/null
            ip6tables -D FORWARD -p udp -s "${target_ip}" --sport "${target_port}" -j ACCEPT 2>/dev/null
        fi
        sed -i "${rule_num}d" "$FORWARD_RULES_FILE_IPV6"
        echo -e "${GREEN}已清除与 ${target_ip}:${target_port} 相关的规则${NC}"
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save
            netfilter-persistent reload
            echo -e "${GREEN}规则已保存并重新加载${NC}"
        else
            echo -e "${YELLOW}请注意：系统未安装 netfilter-persistent，规则可能需要手动保存${NC}"
            echo -e "${YELLOW}建议安装：apt-get install iptables-persistent${NC}"
        fi
    else
        echo -e "${RED}无效的规则编号${NC}"
    fi
    sleep 1
}

show_menu() {
    while true; do
        print_banner
        echo -e "${YELLOW}请选择操作：${NC}"
        echo "1. 启用IP转发并优化和自启"
        echo "2. 转发规则管理"
        echo "3. 保存当前规则"
        echo "4. 查询转发规则"
        echo "5. 恢复之前的规则"
        echo "0. 退出"
        echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}请选择操作 [0-5]:${NC}"
        read -p "> " choice
        case $choice in
            1)
                enable_ip_forward
                read -p "按回车继续..."
                ;;
            2)
                manage_forward_rules
                ;;
            3)
                save_rules
                read -p "按回车继续..."
                ;;
            4)
                check_forward_status
                read -p "按回车继续..."
                ;;
            5)
                restore_rules
                read -p "按回车继续..."
                ;;
            0)
                exit 0
                ;;
            *)
                echo -e "${RED}无效的选择${NC}"
                sleep 1
                ;;
        esac
    done
}

check_root
show_menu