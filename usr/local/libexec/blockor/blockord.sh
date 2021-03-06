#!/bin/sh
#
# Copyright (c) 2022-2022, Muktadiur Rahman <muktadiur@gmail.com>
# All rights reserved.

. /usr/local/etc/blockor.conf

if [ $(nft list tables | grep blockor_table | wc -l) -eq 0 ]; then
	nft add table ip blockor_table
    nft add set ip blockor_table blockor_set { type ipv4_addr\; }
    nft add chain ip blockor_table input { type filter hook input priority 0 \; }
    nft add rule ip blockor_table input ip saddr @blockor_set drop
fi

OS=$(uname -s | tr '[A-Z]' '[a-z]')

tail -n 0 -f $auth_file | while read line
do 
	echo $line | grep -E "$search_pattern" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' >> $blockor_file

	for white_ip in $(echo $blockor_whitelist); do
		sed -i '/'"${white_ip}"'$/d' $blockor_file
	done

	cat $blockor_file | sort | uniq -c | sort -nr | while read row
	do
		count=$(echo $row | awk '{print $1}')
		ip=$(echo $row | awk '{print $2}')
		if [ $count -ge $max_tolerance ]; then
			nft add element ip blockor_table blockor_set { $ip }
			echo $(date -u): $ip 'added in blocked IP list.' >> $blockor_log_file
		fi
	done
done
