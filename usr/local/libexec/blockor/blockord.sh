#!/bin/sh
#
# Copyright (c) 2022-2022, Muktadiur Rahman <muktadiur@gmail.com>
# All rights reserved.

PATH=${PATH}:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin

. /usr/local/etc/blockor.conf
. /usr/local/libexec/blockor/blockor_lib.sh

log() {
	echo "$(date -u): $*" >> "$blockor_log_file"
}

# firewall="auto" takes the first of nftables, ufw, firewalld, iptables
# that works on this host.
if ! fw_setup; then
	log "$fw_error. Then restart blockord."
	echo "blockord($fw_error)" >&2
	exit 1
fi

if ! fw_init >/dev/null; then
	log "could not set up blockor rules in $FW."
	exit 1
fi

# Where sshd writes its log: auth.log while a syslog daemon writes it, the
# journal otherwise (Debian 12 and later log only to the journal).
if ! log_setup; then
	log "$log_error."
	exit 1
fi

# Failed-attempt counts. The directory is root-only (mode 700) when
# blockord creates it.
# shellcheck disable=SC2174 # 700 is meant for the last directory only
if ! mkdir -p -m 700 "${blockor_file%/*}"; then
	log "could not create ${blockor_file%/*} for the count file."
	exit 1
fi
if [ -n "$blockor_file_old" ]; then
	log "counting in $blockor_file, not $blockor_file_old (any local user can create files in /tmp). Update blockor_file in blockor.conf."
fi

if [ -z "$blockor_whitelist" ]; then
	log 'warning: blockor_whitelist is empty. Add your own IP so you cannot lock yourself out.'
fi
[ -n "$log_note" ] && log "$log_note. reading the journal instead."
log "started. reading sshd log from $log_from. blocking with $FW."

follow_log() {
	if [ "$log_from" = file ]; then
		# -F, not -f: keep following auth.log after logrotate replaces it.
		tail -n 0 -F "$auth_file" 2>/dev/null
	else
		# No journalctl -t sshd: systemd 256 and later drop most of the
		# first burst of entries whose -t value the journal file has not
		# seen yet, such as the first sshd-session lines after each journal
		# rotation. sshd's lines are picked out by line_re below instead.
		# short-iso prints "<time> <host> <identifier>[<pid>]: " in every
		# locale.
		journalctl -f -n 0 -o short-iso
	fi
}

block_ip() {
	# Check and repair blockor's rules first: a firewall reload, "nft flush
	# ruleset" or a deleted INPUT jump or drop zone binding leaves IPs
	# listed but not dropped, and an IP already listed is only blocked if
	# the rules around it are there.
	if ! fw_init >/dev/null; then
		log "$1 not blocked. blockor rules in $FW are missing and could not be restored."
		return
	fi

	# Already blocked: this is a line that was in flight when the block landed.
	fw_has "$1" && return 0

	if fw_add "$1"; then
		log "$1 added in blocked IP list."
	else
		log "$1 could not be added in blocked IP list."
	fi
}

# The client controls text inside some of sshd's messages: the username,
# the protocol banner, the key exchange offer ("Unable to negotiate with
# ... Their offer: <text>"), the disconnect reason ("Received disconnect
# from ...: <text>"). A line counts only if:
#
# 1. It is sshd's own line and its message STARTS with a search_pattern
#    phrase. The prefix before the message is matched exactly, for ISO
#    8601 timestamps (journalctl -o short-iso, rsyslog on Debian 12) and
#    traditional ones ("Nov 19 00:15:24"), so a phrase inside the client's
#    text never counts.
# 2. The address is the "<IP> port <N>" that ENDS the line, before sshd's
#    own " ssh2" or " [preauth]". In the default patterns' messages the
#    client's text (username, banner) only comes before it, so
#    "Invalid user x from 1.2.3.4 port 22 from <client> port 5555" counts
#    <client>.
line_re="^([0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+|[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) [^ ]+ (sshd|sshd-session)(\\[[0-9]+\\])?: ($search_pattern)"
ip_pattern='([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]*:[0-9a-fA-F.]*)'
addr_sed="s/.* $ip_pattern port [0-9]+( ssh2)?( \\[preauth\\])?\$/\\1/p"

# The whitelist rewritten once into the spelling sshd logs, so that
# 2001:DB8:0:0:0:0:0:1 in blockor.conf matches 2001:db8::1 in the log with
# a plain string compare per line, and no process per line.
# shellcheck disable=SC2086 # one argument per whitelist entry
whitelist=" $(canon_ips $blockor_whitelist | tr '\n' ' ')"

follow_log \
	| grep --line-buffered -E "$line_re" \
	| sed -n -E -u "$addr_sed" \
	| while IFS= read -r ip; do
		case $whitelist in
		*" $ip "*) continue ;;
		esac

		echo "$ip" >> "$blockor_file"
		count=$(grep -cxF -- "$ip" "$blockor_file")
		[ "$count" -ge "$max_tolerance" ] && block_ip "$ip"
	done
