# campus-device-bypass —— wxdet-gate 构建入口（Rust）
CARGO ?= cargo
BIN   := wxdet-gate

.PHONY: all check fmt clippy test build arm64 clean

all: check build

check: fmt clippy test

# cargo fmt 只检查不改写：有未格式化文件即失败
fmt:
	cd gate && $(CARGO) fmt --check

clippy:
	cd gate && $(CARGO) clippy --all-targets -- -D warnings

test:
	cd gate && $(CARGO) test -- --test-threads=1

build:
	cd gate && $(CARGO) build --bins

# 常见路由器平台（arm64），静态 musl（OpenWrt 现行二进制亦静态）
arm64:
	cd gate && $(CARGO) build --release --target aarch64-unknown-linux-musl --bins

clean:
	rm -rf gate/target
