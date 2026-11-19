#!/bin/sh
#
# Copyright (c) 2022-2022, Muktadiur Rahman <muktadiur@gmail.com>
# All rights reserved.
#
# Shared by blockor and blockord. Source it after /usr/local/etc/blockor.conf.
#
# Picks the firewall that blocks IPs (nftables, ufw, firewalld or iptables)
# and where sshd's log is read from (auth_file or the systemd journal).

# Defaults for configs written before these settings existed.
: "${firewall:=auto}"
: "${log_source:=auto}"

# The count file lives in a directory only root can write. Older configs
# put it in /tmp, where any local user can create it first: root's writes
# then fail (fs.protected_regular) and nothing is ever counted, or the user
# controls the counts. blockor_file_old keeps the replaced path for a log line.
blockor_file_old=
case ${blockor_file:-} in
''|/tmp/blockor_blockedlist)
	blockor_file_old=${blockor_file:-}
	blockor_file=/var/lib/blockor/blockedlist
	;;
esac

blockor_table="blockor_table"   # nftables table, one per family (ip, ip6)
blockor_set="blockor_set"       # nftables set
blockor_chain="BLOCKOR"         # iptables and ip6tables chain
blockor_tag="blockor"           # ufw rule comment; firewalld ipsets blockor, blockor6

have() {
	command -v "$1" >/dev/null 2>&1
}

# nft's name for the address family of $1: ip or ip6.
ip_family() {
	case $1 in
	*:*) echo ip6 ;;
	*) echo ip ;;
	esac
}

# awk function norm(a): one spelling per address, so that different ways of
# writing the same address compare equal. IPv4 drops leading zeros
# (010.0.0.1 -> 10.0.0.1). IPv6 becomes 8 lowercase groups of 4 digits
# (2001:DB8::1 -> 2001:0db8:0000:0000:0000:0000:0000:0001), with a dotted
# IPv4 tail turned into two groups. Anything else comes back lowercased.
norm_awk='
function norm(a,    i, n, g, h, t, nh, nt, v, out) {
	a = tolower(a)
	if (index(a, ":") == 0) {
		if (split(a, g, ".") != 4) return a
		for (i = 1; i <= 4; i++)
			if (g[i] !~ /^[0-9]+$/ || g[i] + 0 > 255) return a
		return (g[1] + 0) "." (g[2] + 0) "." (g[3] + 0) "." (g[4] + 0)
	}
	if (index(a, ".")) {
		if (!match(a, /:[0-9.]+$/)) return a
		if (split(substr(a, RSTART + 1), g, ".") != 4) return a
		for (i = 1; i <= 4; i++)
			if (g[i] !~ /^[0-9]+$/ || g[i] + 0 > 255) return a
		a = substr(a, 1, RSTART) sprintf("%x:%x", g[1] * 256 + g[2], g[3] * 256 + g[4])
	}
	i = index(a, "::")
	if (i) {
		nh = i > 1 ? split(substr(a, 1, i - 1), h, ":") : 0
		nt = i + 2 <= length(a) ? split(substr(a, i + 2), t, ":") : 0
		if (index(substr(a, i + 2), "::") || nh + nt > 7) return a
	} else {
		nh = split(a, h, ":")
		nt = 0
		if (nh != 8) return a
	}
	out = ""
	for (n = 1; n <= 8; n++) {
		if (n <= nh) v = h[n]
		else if (n > 8 - nt) v = t[n - 8 + nt]
		else v = "0"
		if (v !~ /^[0-9a-f]+$/ || length(v) > 4) return a
		out = out (n > 1 ? ":" : "") substr("000" v, length(v))
	}
	return out
}

# canon(a): norm(a) in the short form sshd logs (RFC 5952): no leading
# zeros, the longest run of two or more zero groups (the first, on a tie)
# written as "::". 2001:DB8:0:0:0:0:0:1 -> 2001:db8::1.
function canon(a,    g, i, run, best, bestlen, out) {
	a = norm(a)
	if (index(a, ":") == 0 || split(a, g, ":") != 8) return a
	bestlen = 0
	run = 0
	for (i = 1; i <= 8; i++) {
		sub(/^0+/, "", g[i])
		if (g[i] == "") g[i] = "0"
		if (g[i] == "0") {
			if (++run > bestlen) { bestlen = run; best = i - run + 1 }
		} else run = 0
	}
	if (bestlen < 2) {
		out = g[1]
		for (i = 2; i <= 8; i++) out = out ":" g[i]
		return out
	}
	out = ""
	for (i = 1; i < best; i++) out = out (i > 1 ? ":" : "") g[i]
	out = out "::"
	for (i = best + bestlen; i <= 8; i++) out = out g[i] (i < 8 ? ":" : "")
	return out
}'

# Print each argument in canon() form, one per line.
canon_ips() {
	[ $# -gt 0 ] || return 0
	printf '%s\n' "$@" | awk "$norm_awk"'{ print canon($1) }'
}

# Print $1 in norm() form.
norm_ip() {
	awk -v a="$1" "$norm_awk"'BEGIN { print norm(a) }'
}

# True when one of the IPs on stdin, one per line, is the same address as $1.
ip_listed() {
	awk -v want="$1" "$norm_awk"'
		BEGIN { want = norm(want) }
		norm($1) == want { found = 1; exit }
		END { exit !found }'
}

is_whitelisted() {
	[ -n "$blockor_whitelist" ] || return 1
	# shellcheck disable=SC2086 # one whitelist entry per line
	printf '%s\n' $blockor_whitelist | ip_listed "$1"
}

#
# Firewall backends. Each has _usable, _init, _add, _remove, _has, _flush
# and _list (one blocked IP per line). _init is safe to run again: it only
# creates what is missing. IPv4 must work; IPv6 is best effort.
#

# nftables: a blockor_table per family with a set, the original behaviour.
nftables_usable() {
	have nft && nft list tables >/dev/null 2>&1
}

# Make sure the table for one family has its input chain hooked into the
# firewall, with the rule that drops the set's IPs, and add whatever is
# missing. That the table exists is not enough: an emptied table, or one
# missing its chain or rule, lists IPs and drops nothing.
nftables_init_family() {
	family=$1
	addr_type=$2
	# The drop rule names @blockor_set, and nft keeps a set while a rule
	# uses it, so this one check covers the set too.
	case $(nft list chain "$family" "$blockor_table" input 2>/dev/null) in
	*"hook input"*"$family saddr @$blockor_set drop"*) return 0 ;;
	esac
	# "add" leaves objects that exist alone, so this fills only the gaps,
	# in one transaction.
	nft -f /dev/stdin << EOF || return 1
add table $family $blockor_table
add set $family $blockor_table $blockor_set { type $addr_type; }
add chain $family $blockor_table input { type filter hook input priority 0; policy accept; }
EOF
	nft list chain "$family" "$blockor_table" input | grep -qF "$family saddr @$blockor_set drop" ||
		nft add rule "$family" "$blockor_table" input "$family" saddr @"$blockor_set" drop
}

nftables_init() {
	nftables_init_family ip ipv4_addr || return 1
	nftables_init_family ip6 ipv6_addr ||
		echo "blockor(ip6 table not created. blocking IPv4 only)"
	return 0
}

nftables_add() {
	nft add element "$(ip_family "$1")" "$blockor_table" "$blockor_set" "{ $1 }"
}

# An IP that is not in the set is already removed, not an error: blockor
# remove must still clear the counts of an IP that a reboot or "nft flush
# ruleset" unblocked, or its next failed login blocks it again.
nftables_remove() {
	nftables_has "$1" || return 0
	nft delete element "$(ip_family "$1")" "$blockor_table" "$blockor_set" "{ $1 }"
}

nftables_has() {
	nft get element "$(ip_family "$1")" "$blockor_table" "$blockor_set" "{ $1 }" >/dev/null 2>&1
}

nftables_flush() {
	nft flush set ip "$blockor_table" "$blockor_set"
	nft flush set ip6 "$blockor_table" "$blockor_set" 2>/dev/null
	return 0
}

nftables_list() {
	for family in ip ip6; do
		# nft wraps long element lists over several lines.
		nft list set "$family" "$blockor_table" "$blockor_set" 2>/dev/null | awk '
			/elements = / { p = 1 }
			p {
				last = /}/
				gsub(/.*= |[{},]/, "")
				for (i = 1; i <= NF; i++) print $i
				if (last) exit
			}'
	done
}

# UFW stores the persistent deny in its user chain. The matching runtime
# rule must run before ufw-before-input accepts established connections.
ufw_chain=BLOCKOR-UFW

ufw_usable() {
	have ufw && have iptables && LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active'
}

ufw_list() {
	ufw_status=$(LC_ALL=C ufw status) || return 1
	# Plain "ufw status" prints incoming rules as "DENY"; only the verbose
	# and numbered forms print "DENY IN". Accept both.
	printf '%s\n' "$ufw_status" | awk -v tag="$blockor_tag" '
		$1 == "Anywhere" {
			i = $2 == "(v6)" ? 3 : 2
			if ($i != "DENY") next
			j = $(i+1) == "IN" ? i+2 : i+1
			if (NF == j+2 && $j ~ /^[0-9a-fA-F:.]+$/ &&
			    $(j+1) == "#" && $(j+2) == tag)
				print $j
		}'
}

ufw_init_family() {
	case $1 in
	ip) before=ufw-before-input ;;
	ip6) before=ufw6-before-input ;;
	esac
	init_input_jump "$1" "$before" "$ufw_chain" || return 1
	runtime=$(ipt "$1" -S "$ufw_chain") || return 1
	# Compare the saved and runtime lists with normalized IPv6 addresses.
	missing=$(printf '%s\n' "$runtime" "$ufw_saved" | awk -v family="$1" "$norm_awk"'
		NF == 6 && $1 == "-A" && $3 == "-s" && $5 == "-j" && $6 == "DROP" {
			sub("/(32|128)$", "", $4); present[norm($4)] = 1
		}
		NF == 1 && $1 !~ /^-/ && (index($1, ":") > 0) == (family == "ip6") &&
		    !present[norm($1)] { print $1 }') || return 1
	for address in $missing; do
		ipt "$1" -A "$ufw_chain" -s "$address" -j DROP || return 1
	done
}

ufw_init() {
	ufw_usable || return 1
	ufw_saved=$(ufw_list) || return 1
	ufw_init_family ip || return 1
	if have ip6tables && ipt ip6 -S ufw6-before-input >/dev/null 2>&1; then
		ufw_init_family ip6 || return 1
	fi
}

ufw_has() {
	ipt "$(ip_family "$1")" -C "$ufw_chain" -s "$1" -j DROP 2>/dev/null
}

ufw_add() {
	# Reject a family where we cannot enforce the early drop.
	case $1 in
	*:*) ipt ip6 -C ufw6-before-input -j "$ufw_chain" || return 1 ;;
	esac
	LC_ALL=C ufw prepend deny from "$1" comment "$blockor_tag" >/dev/null || return 1
	# UFW may successfully skip a duplicate administrator rule.
	saved=$(ufw_list) || return 1
	if ! printf '%s\n' "$saved" | ip_listed "$1"; then
		echo "blockor(could not create an owned UFW rule for $1)" >&2
		return 1
	fi
	ufw_saved=$saved ufw_init_family "$(ip_family "$1")"
}

ufw_remove() {
	saved=$(ufw_list) || return 1
	# Delete by rule specification so another rule's index cannot shift
	# into place. UFW does not use comments when matching a deletion.
	if printf '%s\n' "$saved" | ip_listed "$1"; then
		LC_ALL=C ufw delete deny from "$1" >/dev/null || return 1
	fi
	while ufw_has "$1"; do
		ipt "$(ip_family "$1")" -D "$ufw_chain" -s "$1" -j DROP || return 1
	done
}

ufw_flush() {
	saved=$(ufw_list) || return 1
	for address in $saved; do
		ufw_remove "$address" || return 1
	done
	for family in ip ip6; do
		if ipt "$family" -S "$ufw_chain" >/dev/null 2>&1; then
			ipt "$family" -F "$ufw_chain" || return 1
		fi
	done
}

# A separate mangle INPUT chain drops packets before firewalld accepts
# established connections. The direct API can flush unrelated iptables
# rules on its first use, so manage only our chain through iptables.
firewalld_chain=BLOCKOR-FWD

firewalld_usable() {
	have firewall-cmd && have iptables && firewall-cmd --state >/dev/null 2>&1 &&
		ipt ip -t mangle -S INPUT >/dev/null 2>&1
}

firewalld_rule() {
	ipt "$(ip_family "$2")" -t mangle "$1" "$firewalld_chain" -s "$2" -j DROP
}

firewalld_has() {
	firewalld_rule -C "$1" >/dev/null 2>&1
}

firewalld_add() {
	firewalld_rule -A "$1"
}

firewalld_remove() {
	while firewalld_has "$1"; do
		firewalld_rule -D "$1" || return 1
	done
	# Also clear any ban left by an older Blockor.
	case $1 in
	*:*) old_set=${blockor_tag}6 ;;
	*) old_set=$blockor_tag ;;
	esac
	if firewall-cmd --zone=drop --query-source="ipset:$old_set" >/dev/null 2>&1 &&
		firewall-cmd --ipset="$old_set" --query-entry="$1" >/dev/null 2>&1; then
		firewall-cmd --ipset="$old_set" --remove-entry="$1" >/dev/null || return 1
	fi
}

firewalld_legacy_list() {
	for old_set in "$blockor_tag" "${blockor_tag}6"; do
		if firewall-cmd --zone=drop --query-source="ipset:$old_set" >/dev/null 2>&1; then
			firewall-cmd --ipset="$old_set" --get-entries || return 1
		fi
	done
}

firewalld_init() {
	firewalld_usable || return 1
	init_input_jump ip INPUT "$firewalld_chain" mangle || return 1
	if have ip6tables && ipt ip6 -t mangle -S INPUT >/dev/null 2>&1; then
		init_input_jump ip6 INPUT "$firewalld_chain" mangle || return 1
	fi
	legacy=$(firewalld_legacy_list) || return 1
	for address in $legacy; do
		firewalld_has "$address" || firewalld_add "$address" || return 1
	done
}

firewalld_list() {
	rules=$(ipt_list_drops mangle "$firewalld_chain")
	legacy=$(firewalld_legacy_list) || return 1
	printf '%s\n' "$rules" "$legacy" | awk "$norm_awk"'{
		for (i = 1; i <= NF; i++) {
			address = canon($i)
			if (!seen[address]++) print address
		}
	}'
}

firewalld_flush() {
	rules=$(firewalld_list) || return 1
	for address in $rules; do
		firewalld_remove "$address" || return 1
	done
}

# iptables: a BLOCKOR chain in iptables, and in ip6tables for IPv6.
# ipt ip|ip6 args...
ipt() {
	if [ "$1" = ip6 ]; then
		shift
		ip6tables -w "$@"
	else
		shift
		iptables -w "$@"
	fi
}

iptables_usable() {
	have iptables && ipt ip -n -L INPUT >/dev/null 2>&1
}

# Link our chain before any early ACCEPT in the owning input chain.
# init_input_jump family parent child [table]
init_input_jump() {
	table=${4:-filter}
	ipt "$1" -t "$table" -S "$3" >/dev/null 2>&1 || {
		ipt "$1" -t "$table" -N "$3" || ipt "$1" -t "$table" -S "$3" >/dev/null || return 1
	}
	parent_rules=$(ipt "$1" -t "$table" -S "$2") || return 1
	first_rule=$(printf '%s\n' "$parent_rules" | awk '/^-A / {print; exit}')
	if [ "$first_rule" != "-A $2 -j $3" ]; then
		while ipt "$1" -t "$table" -D "$2" -j "$3" 2>/dev/null; do :; done
		ipt "$1" -t "$table" -I "$2" 1 -j "$3"
	fi
}

iptables_init() {
	init_input_jump ip INPUT "$blockor_chain" || return 1
	{ have ip6tables && init_input_jump ip6 INPUT "$blockor_chain"; } ||
		echo "blockor(ip6tables chain not created. blocking IPv4 only)"
	return 0
}

iptables_add() {
	ipt "$(ip_family "$1")" -A "$blockor_chain" -s "$1" -j DROP
}

# Like nftables_remove, succeeds when the IP has no rule.
iptables_remove() {
	while iptables_has "$1"; do
		ipt "$(ip_family "$1")" -D "$blockor_chain" -s "$1" -j DROP || return 1
	done
}

iptables_has() {
	ipt "$(ip_family "$1")" -C "$blockor_chain" -s "$1" -j DROP 2>/dev/null
}

iptables_flush() {
	ipt ip -F "$blockor_chain"
	ipt ip6 -F "$blockor_chain" 2>/dev/null
	return 0
}

ipt_list_drops() {
	for family in ip ip6; do
		ipt "$family" -t "$1" -S "$2" 2>/dev/null |
			awk 'NF == 6 && $1 == "-A" && $3 == "-s" && $5 == "-j" && $6 == "DROP" {
				sub("/(32|128)$", "", $4); print $4
			}'
	done
}

iptables_list() {
	ipt_list_drops filter "$blockor_chain"
}

#
# Firewall selection. firewall="auto" takes the first usable backend in
# fw_backends order; any other value forces that one.
#
fw_backends="nftables ufw firewalld iptables"

# Sets FW to the backend to use, or fw_error and returns 1.
fw_setup() {
	FW=
	fw_error=
	case $firewall in
	auto)
		for fw in $fw_backends; do
			if "${fw}_usable"; then
				FW=$fw
				return 0
			fi
		done
		fw_error="no firewall found (tried $fw_backends). install nftables"
		;;
	nftables|ufw|firewalld|iptables)
		if "${firewall}_usable"; then
			FW=$firewall
			return 0
		fi
		fw_error="firewall=$firewall is set but $firewall is not installed or not running"
		;;
	*)
		fw_error="unknown firewall \"$firewall\". use auto, nftables, ufw, firewalld or iptables"
		;;
	esac
	return 1
}

fw_init() {
	"${FW}_init"
}

fw_add() {
	"${FW}_add" "$1"
}

fw_remove() {
	"${FW}_remove" "$1"
}

fw_has() {
	"${FW}_has" "$1"
}

fw_flush() {
	"${FW}_flush"
}

fw_list() {
	"${FW}_list"
}

#
# Log source. Prefer the local systemd journal for its trusted sender metadata.
#

# Sets log_from to file or journal. Sets log_error on a bad setting.
log_setup() {
	log_from=$log_source
	log_error=
	if [ "$log_from" = auto ]; then
		if [ -d /run/systemd/system ] && have journalctl; then
			log_from=journal
		else
			log_from='file'
		fi
	fi
	case $log_from in
	file|journal) return 0 ;;
	esac
	log_error="unknown log_source \"$log_source\". use auto, file or journal"
	return 1
}
