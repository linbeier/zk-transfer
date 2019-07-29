.PHONY: all
librustzk: 
	cargo build --release
	sudo cp target/release/librustzk.so /usr/lib
	sudo cp zk.h /usr/include/

install:
	sudo cp target/release/librustzk.so /usr/lib
	sudo cp zk.h /usr/include/

params:
	cargo run --release
	mkdir -p $(DATADIR)/gethdata/zk-keys/
	cp -f *.vk $(DATADIR)/gethdata/zk-keys/
