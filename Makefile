build-release:
	cargo build --release
build-dev:
	cargo build
install:
	cp target/release/chars /usr/bin/chars