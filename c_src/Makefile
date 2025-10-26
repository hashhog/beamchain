CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)
PRIVDIR := $(BASEDIR)/priv

# Erlang NIF
ERTS_INCLUDE := $(shell erl -noshell -eval \
	'io:format("~s/erts-~s/include", [code:root_dir(), erlang:system_info(version)]), halt().')

# libsecp256k1
SECP256K1_VSN := v0.5.1
SECP256K1_DIR := $(CURDIR)/secp256k1
SECP256K1_BUILD := $(SECP256K1_DIR)/build
SECP256K1_LIB := $(SECP256K1_BUILD)/src/libsecp256k1.a

CC ?= gcc
CFLAGS := -O2 -Wall -fPIC -I$(ERTS_INCLUDE) -I$(SECP256K1_DIR)/include
LDFLAGS := -shared

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LDFLAGS += -flat_namespace -undefined suppress
endif

NIF_SO := $(PRIVDIR)/beamchain_crypto_nif.so

all: $(NIF_SO)

$(NIF_SO): beamchain_crypto_nif.c $(SECP256K1_LIB) | $(PRIVDIR)
	$(CC) $(CFLAGS) $< $(SECP256K1_LIB) $(LDFLAGS) -o $@

$(SECP256K1_LIB): $(SECP256K1_DIR)/CMakeLists.txt
	mkdir -p $(SECP256K1_BUILD)
	cd $(SECP256K1_BUILD) && cmake .. \
		-DCMAKE_C_FLAGS="-fPIC" \
		-DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON \
		-DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
		-DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
		-DSECP256K1_BUILD_TESTS=OFF \
		-DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
		-DSECP256K1_BUILD_BENCHMARK=OFF \
		-DSECP256K1_BUILD_EXAMPLES=OFF \
		-DBUILD_SHARED_LIBS=OFF
	$(MAKE) -C $(SECP256K1_BUILD) -j$(shell nproc)

$(SECP256K1_DIR)/CMakeLists.txt:
	git clone --depth 1 --branch $(SECP256K1_VSN) \
		https://github.com/bitcoin-core/secp256k1.git $(SECP256K1_DIR)

$(PRIVDIR):
	mkdir -p $(PRIVDIR)

clean:
	rm -f $(NIF_SO)
	rm -rf $(SECP256K1_BUILD)

distclean: clean
	rm -rf $(SECP256K1_DIR)

.PHONY: all clean distclean
