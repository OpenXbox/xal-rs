all:
	cargo test --all
	cargo check
	cargo clippy --tests