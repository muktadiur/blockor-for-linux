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

nftables_remove() {
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

# ufw: only when active, otherwise its rules do nothing. Rules carry the
# comment "blockor" so they can be told apart from the admin's own.
ufw_usable() {
	have ufw && ufw status 2>/dev/null | grep -q '^Status: active'
}

# ufw's rules stay in place when ufw is disabled but drop nothing then.
ufw_init() {
	ufw_usable
}

ufw_add() {
	# The deny has to sit above the rule that allows ssh, so prepend it
	# (ufw 0.35 or later). No fallback to appending: an appended deny sits
	# below the ssh allow and blocks nothing, so fail and let it be logged.
	ufw prepend deny from "$1" comment "$blockor_tag" >/dev/null
}

ufw_remove() {
	ufw delete deny from "$1" >/dev/null
}

ufw_has() {
	ufw_list | ip_listed "$1"
}

ufw_flush() {
	for ip in $(ufw_list); do
		ufw_remove "$ip"
	done
}

ufw_list() {
	ufw status | grep -E "# ${blockor_tag}[[:space:]]*\$" |
		grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:]*:[0-9a-fA-F.]*'
}

# firewalld: ipsets blockor (IPv4) and blockor6 (IPv6) bound to the drop
# zone. Creating them is a permanent change, so the first init runs one
# firewall-cmd --reload. Entries are runtime only, like the nftables sets.
firewalld_usable() {
	have firewall-cmd && firewall-cmd --state >/dev/null 2>&1
}

firewalld_ipset() {
	case $1 in
	*:*) echo "${blockor_tag}6" ;;
	*) echo "$blockor_tag" ;;
	esac
}

# firewalld_has_ipset name [--permanent]
firewalld_has_ipset() {
	name=$1
	shift
	firewall-cmd "$@" --get-ipsets | tr ' ' '\n' | grep -qxF -- "$name"
}

# firewalld_bound name [--permanent]: the ipset is a source of the drop
# zone. An ipset that is not bound holds entries but blocks nothing.
firewalld_bound() {
	name=$1
	shift
	firewall-cmd "$@" --zone=drop --query-source="ipset:$name" >/dev/null 2>&1
}

# Checks each ipset and its drop zone binding, in the saved config and in
# the running one, and repairs what is missing. Reloads only when the saved
# config changed or the running one lacks an ipset, since a reload empties
# the ipsets.
firewalld_init() {
	reload=
	for spec in "$blockor_tag inet" "${blockor_tag}6 inet6"; do
		# shellcheck disable=SC2086 # split "name family"
		set -- $spec
		firewalld_bound "$1" --permanent && continue
		if ! firewalld_has_ipset "$1" --permanent; then
			firewall-cmd --permanent --new-ipset="$1" --type=hash:ip --option=family="$2" >/dev/null ||
				return 1
		fi
		firewall-cmd --permanent --zone=drop --add-source="ipset:$1" >/dev/null || return 1
		reload=1
	done
	unbound=
	for name in "$blockor_tag" "${blockor_tag}6"; do
		firewalld_bound "$name" && continue
		firewalld_has_ipset "$name" || reload=1
		unbound="$unbound $name"
	done
	if [ -n "$reload" ]; then
		firewall-cmd --reload >/dev/null || return 1
		unbound="$blockor_tag ${blockor_tag}6"
	fi
	# A binding removed only in the running config stays gone until the
	# next reload; put it back without one.
	for name in $unbound; do
		firewalld_bound "$name" ||
			firewall-cmd --zone=drop --add-source="ipset:$name" >/dev/null || return 1
	done
}

firewalld_add() {
	firewall-cmd --ipset="$(firewalld_ipset "$1")" --add-entry="$1" >/dev/null
}

firewalld_remove() {
	firewall-cmd --ipset="$(firewalld_ipset "$1")" --remove-entry="$1" >/dev/null
}

firewalld_has() {
	firewall-cmd --ipset="$(firewalld_ipset "$1")" --query-entry="$1" >/dev/null 2>&1
}

firewalld_flush() {
	for ip in $(firewalld_list); do
		firewalld_remove "$ip"
	done
}

firewalld_list() {
	firewall-cmd --ipset="$blockor_tag" --get-entries 2>/dev/null
	firewall-cmd --ipset="${blockor_tag}6" --get-entries 2>/dev/null
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

iptables_init_family() {
	ipt "$1" -n -L "$blockor_chain" >/dev/null 2>&1 ||
		ipt "$1" -N "$blockor_chain" || return 1
	# Jump to the chain from the top of INPUT, so an ACCEPT rule that
	# another tool adds cannot let a blocked IP through first.
	if [ "$(ipt "$1" -S INPUT | sed -n 2p)" != "-A INPUT -j $blockor_chain" ]; then
		while ipt "$1" -D INPUT -j "$blockor_chain" 2>/dev/null; do :; done
		ipt "$1" -I INPUT 1 -j "$blockor_chain"
	fi
}

iptables_init() {
	iptables_init_family ip || return 1
	{ have ip6tables && iptables_init_family ip6; } ||
		echo "blockor(ip6tables chain not created. blocking IPv4 only)"
	return 0
}

iptables_add() {
	ipt "$(ip_family "$1")" -A "$blockor_chain" -s "$1" -j DROP
}

iptables_remove() {
	ipt "$(ip_family "$1")" -D "$blockor_chain" -s "$1" -j DROP
}

iptables_has() {
	ipt "$(ip_family "$1")" -C "$blockor_chain" -s "$1" -j DROP 2>/dev/null
}

iptables_flush() {
	ipt ip -F "$blockor_chain"
	ipt ip6 -F "$blockor_chain" 2>/dev/null
	return 0
}

iptables_list() {
	for family in ip ip6; do
		ipt "$family" -S "$blockor_chain" 2>/dev/null |
			awk '$1 == "-A" && $3 == "-s" { sub("/(32|128)$", "", $4); print $4 }'
	done
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
# Log source. log_source="auto" reads auth_file while a syslog daemon writes
# it, and the systemd journal otherwise (Debian 12 and later have no
# auth.log unless rsyslog is installed).
#

# True when systemd runs with no syslog daemon, so auth_file, if it exists,
# is left over and no longer grows. sshd's lines are in the journal then.
syslog_stopped() {
	[ -d /run/systemd/system ] && have journalctl &&
		! systemctl is-active --quiet syslog.service rsyslog.service syslog-ng.service
}

# Sets log_from to file or journal, and log_note to why auto skipped
# auth_file when it exists. Sets log_error and returns 1 on a bad setting.
log_setup() {
	log_from=$log_source
	log_note=
	log_error=
	if [ "$log_from" = auto ]; then
		if [ ! -e "$auth_file" ]; then
			log_from=journal
		elif syslog_stopped; then
			log_from=journal
			log_note="$auth_file exists but no syslog daemon is writing it"
		else
			log_from=file
		fi
	fi
	case $log_from in
	file|journal) return 0 ;;
	esac
	log_error="unknown log_source \"$log_source\". use auto, file or journal"
	return 1
}
