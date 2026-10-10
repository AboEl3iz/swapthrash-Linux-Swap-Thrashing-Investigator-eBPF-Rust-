# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
TARGET = swapthrash
RELEASE_BIN = target/release/$(TARGET)

.PHONY: all build release check clean test run install

all: release

build:
	cargo build

release:
	cargo build --release

check:
	cargo check

clean:
	cargo clean

run: release
	sudo $(RELEASE_BIN) -i 1 -p

test: release
	./scripts/test_thrash.sh

stress:
	./scripts/run_stress_test.sh 15

install: release
	install -m 755 $(RELEASE_BIN) /usr/local/bin/$(TARGET)
