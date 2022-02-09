.PHONY: install
install:
	@echo "Installing blockor"
	@cp -Rv etc /
	@cp -Rv usr /
	@echo "Successfully installed"

.PHONY: uninstall
uninstall:
	@echo "Removing blockor"
	@rm -vf /etc/systemd/system/blockord.service
	@rm -vf /usr/local/bin/blockor
	@rm -vf /usr/local/etc/blockor.conf
	@rm -rvf /usr/local/libexec/blockor
	@rm -vf /usr/share/man/man8/blockor.8.gz
	@echo "Successfully removed"
