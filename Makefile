.PHONY: install
install:
	@echo "Installing blockor"
	@cp -Rv etc /
	@mkdir -p /usr/local/bin /usr/local/etc /usr/local/libexec /usr/share/man/man8
	@cp -v usr/local/bin/blockor /usr/local/bin/
	@cp -Rv usr/local/libexec/blockor /usr/local/libexec/
	@cp -v usr/share/man/man8/blockor.8.gz /usr/share/man/man8/
	@if [ -f /usr/local/etc/blockor.conf ]; then \
		echo "Keeping existing /usr/local/etc/blockor.conf"; \
	else \
		cp -v usr/local/etc/blockor.conf /usr/local/etc/; \
	fi
	@-systemctl daemon-reload
	@echo "Successfully installed"

.PHONY: uninstall
uninstall:
	@echo "Removing blockor"
	@rm -vf /etc/systemd/system/blockord.service
	@rm -vf /usr/local/bin/blockor
	@rm -vf /usr/local/etc/blockor.conf
	@rm -rvf /usr/local/libexec/blockor
	@rm -rvf /var/lib/blockor
	@rm -vf /usr/share/man/man8/blockor.8.gz
	@echo "Successfully removed"
