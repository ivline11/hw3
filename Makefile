all: cryp

cryp:
	cargo build --release
	cp target/release/cryp .

clean:
	cargo clean
	rm -f cryp 