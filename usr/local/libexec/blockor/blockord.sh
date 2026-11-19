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

# Prefer the journal, which can authenticate the process that logged a message.
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

# The journal is matched on _EXE, the program that logged. From OpenSSH
# 9.8, sshd-session (and from 10.0 sshd-auth) logs every failed login, not
# sshd, and distros install them in different places: Debian
# /usr/lib/openssh, Fedora /usr/libexec/openssh, Arch /usr/lib/ssh,
# openSUSE /usr/libexec/ssh. Ask sshd where its own are first ("sshd -T"
# prints sshdsessionpath and sshdauthpath from 9.8), then try those.
sshd_candidates() {
	if have sshd; then
		command -v sshd
		sshd -T 2>/dev/null |
			awk '$1 == "sshdsessionpath" || $1 == "sshdauthpath" { print $2 }'
	fi
	for dir in /usr/lib/openssh /usr/libexec/openssh /usr/lib/ssh \
		/usr/libexec/ssh /usr/libexec /usr/local/libexec; do
		echo "$dir/sshd-session"
		echo "$dir/sshd-auth"
	done
	echo /usr/sbin/sshd /usr/bin/sshd /usr/local/sbin/sshd
}

sshd_exes=
if [ "$log_from" = journal ]; then
	for exe in $(sshd_candidates); do
		if [ -f "$exe" ] && [ -x "$exe" ]; then
			case " $sshd_exes " in
			*" $exe "*) ;;
			*) sshd_exes="${sshd_exes:+$sshd_exes }$exe" ;;
			esac
		fi
	done
	if [ -z "$sshd_exes" ]; then
		log 'could not find an OpenSSH executable to match in the journal. install OpenSSH or set log_source="file", then restart blockord.'
		# 78 (EX_CONFIG) is in RestartPreventExitStatus in blockord.service:
		# restarting every 5 seconds would not find it either, and would
		# add this line to the log each time.
		exit 78
	fi
	log "started. reading sshd log from the journal ($sshd_exes). blocking with $FW."
else
	log "started. reading sshd log from $auth_file. blocking with $FW."
fi

follow_log() {
	if [ "$log_from" = file ]; then
		# -F, not -f: keep following auth.log after logrotate replaces it.
		tail -n 0 -F "$auth_file" 2>/dev/null
	else
		# journalctl turns each executable path into an _EXE= match on its
		# canonical path. Matches on one field are ORed, on different
		# fields ANDed: _UID=0 and any of the executables.
		# shellcheck disable=SC2086 # one argument per executable
		journalctl --system -f -n 0 -o short-iso _UID=0 $sshd_exes
	fi
}

block_ip() {
	# Check and repair blockor's rules first: a firewall reload, "nft flush
	# ruleset" or a deleted INPUT jump leaves IPs
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
# 1. Its message starts with a phrase from the built-in allowlist and
#    matches search_pattern. Match and strip the timestamp, host and SSH
#    tag first, so a phrase inside the client's text never counts.
# 2. The address is the "<IP> port <N>" that ENDS the line, before sshd's
#    own " ssh2" or " [preauth]". In the default patterns' messages the
#    client's text (username, banner) only comes before it, so
#    "Invalid user x from 1.2.3.4 port 22 from <client> port 5555" counts
#    <client>.
log_prefix='^([0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+|[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) [^ ]+ sshd(-session|-auth)?(\[[0-9]+\])?: '
safe_messages='Failed password for |Invalid user |Bad protocol version identification |Disconnected from authenticating user root '
search_pattern=${search_pattern:-$safe_messages}
ip_pattern='([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]*:[0-9a-fA-F.]*)'
addr_sed="s/.* $ip_pattern port [0-9]+( ssh2)?( \\[preauth\\])?\$/\\1/p"

# The whitelist rewritten once into the spelling sshd logs, so that
# 2001:DB8:0:0:0:0:0:1 in blockor.conf matches 2001:db8::1 in the log with
# a plain string compare per line, and no process per line.
# shellcheck disable=SC2086 # one argument per whitelist entry
whitelist=" $(canon_ips $blockor_whitelist | tr '\n' ' ')"

follow_log \
	| sed -n -E -u "s/$log_prefix//p" \
	| grep --line-buffered -E "^($safe_messages)" \
	| grep --line-buffered -E "^($search_pattern)" \
	| sed -n -E -u "$addr_sed" \
	| while IFS= read -r ip; do
		case $whitelist in
		*" $ip "*) continue ;;
		esac

		echo "$ip" >> "$blockor_file"
		count=$(grep -cxF -- "$ip" "$blockor_file")
		[ "$count" -ge "$max_tolerance" ] && block_ip "$ip"
	done
