# Builds the example guest components into the fixture directory that
# tests/component_scripts.rs loads. Each guest builds from its own directory,
# so its `.cargo/config.toml` sets the wasm32-wasip2 target and the
# stack-size link arg. This Makefile lives at
# examples/provenance-log/scripts.
ROOT := $(abspath ../../..)
SCRIPTS := $(ROOT)/examples/provenance-log/scripts
GUESTS := unlock lock first
COMPONENTS_DIR := $(ROOT)/target/components

guests:
	@mkdir -p $(COMPONENTS_DIR)
	@for g in $(GUESTS); do \
		echo "building guest $$g"; \
		( cd $(SCRIPTS)/$$g && cargo build --release ) || exit 1; \
		cp $(SCRIPTS)/target/wasm32-wasip2/release/$$g.wasm $(COMPONENTS_DIR)/$$g.wasm || exit 1; \
	done

fixtures: guests

clean:
	rm -rf $(SCRIPTS)/target $(COMPONENTS_DIR)

.PHONY: guests fixtures clean