# Blockor
Protect Linux servers from brute-force attacks. It works on top of the nftables firewall.

![Blockor](images/blockor.png)

## Prerequisites
- Linux operating system: Debian, Ubuntu, OpenSUSE, RHEL with systemd and [ nftables ](https://wiki.debian.org/nftables) enabled.

## Installation
```
git clone https://github.com/muktadiur/blockor-for-linux

# root|sudo|doas required.
cd blockor
make install
```

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

#### Add blockor table on /etc/nftables.conf
```
Sample:

table ip blockor_table {
	set blockor_set {
		type ipv4_addr
	}

	chain input {
    type filter hook input priority 0;
		policy drop;
		ct state established,related accept
		iifname "lo" accept
		tcp dport ssh accept
		ip saddr @blockor_set drop
	}
}

policy drop: drop all incoming connections.

ct state established,related accept: This allows incoming traffic that is part of an existing connection, such as responses to outgoing traffic.

iifname "lo" accept: This allows traffic within the local system.

tcp dport ssh accept: This allows incoming SSH connections.

ip saddr @blacklist_set drop: This blocks traffic from IP addresses in the blacklist_set is dropped.

```

## Basic Commands
```
Blockor protects Linux servers from brute-force attacks.
Usage:
  blockor command [args]
Available Commands:
  init          To initialize blockor nftables.
  start         Start the blockord daemon.
  stop          Stop the blockord daemon.
  restart       Restart the blockord daemon.
  enable        Start the blockord daemon at boot.
  disable       Not start the blockord daemon at boot.
  add           Add IP to blocked list.
  remove        Remove IP from blocked list.
  flush         Remove all entries from blocked list.
  list          Show blocked list with the failed count.
  status        Running or Stopped (enabled|disabled) 
Use "blockor -v|--version" for version info.
```


## Example

#### To initialize blockor nftables.
```
linux# blockor init
blockor(ok)
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

enabled - will start at boot
disabled - will not start at boot
```

#### Show blocked list
```
linux# blockor list
Blocked IP(s):
  { 192.168.56.2 }
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
Change the value of blockor_whitelist, max_tolerance, and search_pattern.
Better not to change others' values.
```
blockord="/usr/local/libexec/blockor/blockord.sh"
blockor="/usr/local/bin/blockor"
blockor_file="/tmp/blockor_blockedlist"
auth_file="/var/log/auth.log"
blockor_log_file="/var/log/blockord.log"
blockor_whitelist="192.168.56.20 192.168.56.102"
search_pattern="Disconnected from authenticating user root|Failed password"
max_tolerance=10
```

#### max_tolerance=10
```
IP will be blocked when more than 10 failed activities. Change to any number.
```
#### search_pattern
```
Add any text pattern with delimiter |
example: search_pattern="Bad protocol version identification|..other patterns"
```
#### blockor_whitelist
```
IP in blockor_whitelist will be excluded from blocking. Add IP with space-separated.
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
    │           └── blockord.sh
    └── share
        └── man
            └── man8
                └── blockor.8.gz
```