# Blockor
Protect Linux servers from brute-force attacks. It blocks attackers with whichever firewall the server has: nftables, ufw, firewalld or iptables.

![Blockor](images/blockor.png)

## Prerequisites
- Linux operating system: Debian, Ubuntu, OpenSUSE, RHEL with systemd.
- One of these firewalls. Blockor uses the first one that works, in this order (see `firewall` below):
  - [nftables](https://wiki.debian.org/nftables): the `nft` command
  - ufw, when it is active (`ufw status` says `Status: active`)
  - firewalld, when it is running and iptables is available
  - iptables (and ip6tables for IPv6)
- sshd logging to the systemd journal or to a trusted log file. See `log_source` below.

## Installation
```
git clone https://github.com/muktadiur/blockor-for-linux

# root|sudo|doas required.
cd blockor-for-linux
make install
```

`make install` keeps an existing `/usr/local/etc/blockor.conf`.

Before starting blockord, add your own IP to `blockor_whitelist` in `/usr/local/etc/blockor.conf` so a few mistyped passwords cannot lock you out.

#### Start blockord at boot
```
blockor enable

or 
systemctl enable blockord
```

#### To remove blockor
```
make uninstall
```

#### Add blockor tables on /etc/nftables.conf
Only when blockor uses nftables. blockord creates these tables when they are missing. Adding them to `/etc/nftables.conf` keeps them in place when nftables.service reloads its ruleset.
```
table ip blockor_table {
	set blockor_set {
		type ipv4_addr
	}

	chain input {
		type filter hook input priority filter; policy accept;
		ip saddr @blockor_set drop
	}
}

table ip6 blockor_table {
	set blockor_set {
		type ipv6_addr
	}

	chain input {
		type filter hook input priority filter; policy accept;
		ip6 saddr @blockor_set drop
	}
}
```

## Basic Commands
```
Blockor protects Linux servers from brute-force attacks.
Usage:
  blockor command [args]
Available Commands:
  init          To initialize the blockor firewall rules.
  start         Start the blockord daemon.
  stop          Stop the blockord daemon.
  restart       Restart the blockord daemon.
  enable        Start the blockord daemon at boot.
  disable       Not start the blockord daemon at boot.
  add           Add IP to blocked list.
  remove        Remove IP from blocked list.
  flush         Remove all entries from blocked list.
  list          Show blocked list with the failed count.
  status        Running or Stopped, with the firewall and log in use.
Use "blockor -v|--version" for version info.
```


## Example

#### To initialize the blockor firewall rules.
```
linux# blockor init
blockor(ok)
firewall(nftables)
```

#### To start blockord
```
linux# blockor start
blockord(running.enabled)
```

#### To stop blockord
```
linux# blockor stop
blockord(stopped.enabled)
```

#### To restart blockord
```
linux# blockor restart
blockord(stopped.enabled)
blockord(running.enabled)
```

#### To remove an IP from blocked list
```
linux# blockor remove 192.168.56.2
blockor(removed)

# or if multiple
linux# blockor remove 192.168.56.45 192.168.56.151 192.168.56.152
blockor(removed)
```

#### To block(add) an IP manually
```
linux# blockor add 192.168.56.2
blockor(ok)

# or if multiple
linux# blockor add 192.168.56.45 192.168.56.151 192.168.56.152
blockor(ok)

# whitelisted IP will be skipped.
linux# blockor add 192.168.56.20
blockor(whitelisted. skipped. 192.168.56.20)
```

#### Check status (running|stopped)
```
linux# blockor status
blockord(running.enabled)
firewall(nftables)
log(journal)

enabled - will start at boot
disabled - will not start at boot
firewall - the firewall blockor blocks with
log - where blockord reads sshd's log: journal or the auth_file path
```

#### Show blocked list
```
linux# blockor list
Blocked IP(s):
  192.168.56.2
count  IP
  11 192.168.56.2
   2 192.168.56.30
   1 192.168.56.21
```

#### Remove all entries from blocked list
```
linux# blockor flush
blockor(flushed)
```

## /usr/local/etc/blockor.conf
Change the value of blockor_whitelist, max_tolerance, search_pattern, firewall, and log_source.
Better not to change others' values.
```
blockord="/usr/local/libexec/blockor/blockord.sh"
blockor="/usr/local/bin/blockor"
blockor_file="/var/lib/blockor/blockedlist"
firewall="auto"
log_source="auto"
auth_file="/var/log/auth.log"
blockor_log_file="/var/log/blockord.log"
blockor_whitelist="192.168.56.20 192.168.56.102"
search_pattern="Failed password|Invalid user|Bad protocol version identification|Disconnected from authenticating user root"
max_tolerance=10
```

#### blockor_file
```
Where failed attempts are counted. Older configs used /tmp/blockor_blockedlist;
blockord now uses /var/lib/blockor/blockedlist instead, because any local user
can create a file in /tmp before blockord does and stop the counting.
```
#### max_tolerance=10
```
IP will be blocked after 10 matching log lines. Change to any number.
One failed login can produce two matching lines (Invalid user + Failed password).
```
#### search_pattern
```
Select from the supported message formats in the default search_pattern.
For example, search_pattern="Failed password|Invalid user" counts only
those two formats.

A line counts only when it matches both the built-in list and search_pattern,
and it ends with the client's
"<IP> port <N>" (then only " ssh2" or " [preauth]"). That IP is counted.

The built-in list excludes key exchange offers and disconnect reasons,
including on upgrades that preserve an older search_pattern.

Timestamps must be ISO 8601 (the journal, rsyslog on Debian 12) or
traditional syslog ("Nov 19 00:15:24").
```
#### firewall
```
auto       the first that works, in this order (default):
           nftables, ufw (if active), firewalld (if running), iptables
nftables   blockor_table in the ip and ip6 families, with a set of IPs
ufw        Tagged deny rules persist across reboot and show in ufw status.
           Blockor also installs early drops to cover established connections.
           Run blockor init after a UFW reload to restore early drops immediately.
firewalld  A runtime chain in the iptables mangle table drops input before
           firewalld can accept established connections.
           Existing bans in Blockor's drop-zone ipsets are carried forward.
iptables   a BLOCKOR chain in iptables and ip6tables, jumped to from
           the top of INPUT
```
Run `blockor restart` after changing it.
#### log_source
```
auto     use the journal on systemd hosts with journalctl, or auth_file otherwise
file     always read auth_file
journal  always use the journal
```
Journal mode verifies the sender's UID and executable using trusted journal fields. If you use `file`, configure your logger to accept only verified OpenSSH messages for that file. A general syslog file can include entries with tags supplied by local users.
#### blockor_whitelist
```
IP in blockor_whitelist will be excluded from blocking. Add IP with space-separated.
Any spelling of an address matches: 2001:DB8:0:0:0:0:0:1 also covers 2001:db8::1.
blockor_whitelist="192.168.56.20 192.168.56.102"

```


## Source code structure
```
├── LICENSE
├── Makefile
├── README.md
├── etc
│   └── systemd
│       └── system
│           └── blockord.service
├── images
│   └── blockor.png
└── usr
    ├── local
    │   ├── bin
    │   │   └── blockor
    │   ├── etc
    │   │   └── blockor.conf
    │   └── libexec
    │       └── blockor
    │           ├── blockor_lib.sh
    │           └── blockord.sh
    └── share
        └── man
            └── man8
                └── blockor.8.gz
```
