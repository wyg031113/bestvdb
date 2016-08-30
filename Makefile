all:
	make -C param_gen
	make -C client
	make -C server
clean:
	make -C param_gen clean
	make -C client clean
	make -C server clean
install:
	make -C param_gen install
	make -C client install
	make -C server install

uninstall:
	make -C param_gen uninstall
	make -C client uninstall
	make -C server uninstall
