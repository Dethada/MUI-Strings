build-release:
	cargo build --release
build-dev:
	cargo build
install:
	cp target/release/ms /usr/bin/