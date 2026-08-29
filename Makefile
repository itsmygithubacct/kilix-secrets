CC ?= cc
AR ?= ar
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local
DESTDIR ?=
BUILD ?= build
TEST_TMPDIR ?= $(if $(TMPDIR),$(TMPDIR),/tmp)

SODIUM_CPPFLAGS ?= $(shell $(PKG_CONFIG) --cflags libsodium 2>/dev/null)
SODIUM_LDLIBS ?= $(shell $(PKG_CONFIG) --libs libsodium 2>/dev/null || printf '%s' '-lsodium')

CPPFLAGS += -Iinclude -Isrc $(SODIUM_CPPFLAGS)
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -fPIC -Wall -Wextra -Wpedantic -Wconversion -Wshadow \
	-Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Werror
LDFLAGS ?=
LDLIBS += $(SODIUM_LDLIBS)

LIB_SOURCES := \
	src/util.c \
	src/memory.c \
	src/format.c \
	src/crypto.c \
	src/store.c \
	src/policy.c \
	src/audit.c \
	src/protocol.c \
	src/client.c
LIB_OBJECTS := $(LIB_SOURCES:src/%.c=$(BUILD)/%.o)
LIB_DEPS := $(LIB_OBJECTS:.o=.d)

.DEFAULT_GOAL := all

.PHONY: all clean test sanitize fuzz install uninstall check-deps

all: $(BUILD)/libkilix-secrets.a $(BUILD)/libkilix-secrets.so.0 \
	$(BUILD)/kilix-secretsd $(BUILD)/kilix-secrets $(BUILD)/kilix-secrets.pc

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/libkilix-secrets.a: $(LIB_OBJECTS)
	$(AR) rcs $@ $^

$(BUILD)/libkilix-secrets.so.0: $(LIB_OBJECTS)
	$(CC) -shared -Wl,-soname,libkilix-secrets.so.0 $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILD)/kilix-secretsd: src/daemon.c $(BUILD)/libkilix-secrets.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(BUILD)/libkilix-secrets.a $(LDLIBS)

$(BUILD)/kilix-secrets: tools/kilix-secrets.c $(BUILD)/libkilix-secrets.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(BUILD)/libkilix-secrets.a $(LDLIBS)

$(BUILD)/generate-vectors: tools/generate_vectors.c $(BUILD)/libkilix-secrets.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< \
		$(BUILD)/libkilix-secrets.a $(LDLIBS)

$(BUILD)/kilix-secrets.pc: kilix-secrets.pc.in | $(BUILD)
	sed 's|@PREFIX@|$(PREFIX)|g' $< > $@

$(BUILD)/test-unit: tests/test_unit.c $(LIB_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DKSEC_TESTING $(LDFLAGS) -o $@ $< \
		$(LIB_SOURCES) $(LDLIBS)

$(BUILD)/test-crash: tests/test_crash.c $(LIB_SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DKSEC_TESTING $(LDFLAGS) -o $@ $< \
		$(LIB_SOURCES) $(LDLIBS)

$(BUILD)/test-vectors: tests/test_vectors.c $(BUILD)/libkilix-secrets.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< \
		$(BUILD)/libkilix-secrets.a $(LDLIBS)

$(BUILD)/parser-harness: tests/parser_harness.c $(BUILD)/libkilix-secrets.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< \
		$(BUILD)/libkilix-secrets.a $(LDLIBS)

test: all $(BUILD)/test-unit $(BUILD)/test-crash $(BUILD)/test-vectors \
	$(BUILD)/generate-vectors $(BUILD)/parser-harness
	test -d "$(TEST_TMPDIR)" && test ! -L "$(TEST_TMPDIR)"
	TMPDIR="$(TEST_TMPDIR)" $(BUILD)/test-unit
	TMPDIR="$(TEST_TMPDIR)" $(BUILD)/test-crash
	$(BUILD)/generate-vectors | cmp - tests/vectors/full-v1.txt
	$(BUILD)/test-vectors
	TMPDIR="$(TEST_TMPDIR)" PYTHONDONTWRITEBYTECODE=1 \
		python3 tests/test_integration.py --build-dir $(BUILD)
	PYTHONDONTWRITEBYTECODE=1 python3 tests/check_manifests.py
	PYTHONDONTWRITEBYTECODE=1 python3 tests/run_negative_corpus.py \
		--build-dir $(BUILD) --cases 4096

sanitize:
	$(MAKE) clean BUILD=build-sanitize
	$(MAKE) test BUILD=build-sanitize \
		CFLAGS='-O1 -g -std=c11 -fPIC -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Werror -fsanitize=address,undefined -fno-omit-frame-pointer' \
		LDFLAGS='-fsanitize=address,undefined'

fuzz: all $(BUILD)/parser-harness
	PYTHONDONTWRITEBYTECODE=1 python3 tests/run_negative_corpus.py \
		--build-dir $(BUILD) --cases 65536

install: all
	install -d $(DESTDIR)$(PREFIX)/include $(DESTDIR)$(PREFIX)/lib \
		$(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/pkgconfig \
		$(DESTDIR)$(PREFIX)/lib/systemd/user
	install -m 0644 include/kilix_secrets.h $(DESTDIR)$(PREFIX)/include/
	install -m 0644 $(BUILD)/libkilix-secrets.a $(DESTDIR)$(PREFIX)/lib/
	install -m 0755 $(BUILD)/libkilix-secrets.so.0 $(DESTDIR)$(PREFIX)/lib/
	ln -sfn libkilix-secrets.so.0 $(DESTDIR)$(PREFIX)/lib/libkilix-secrets.so
	install -m 0755 $(BUILD)/kilix-secretsd $(BUILD)/kilix-secrets $(DESTDIR)$(PREFIX)/bin/
	install -m 0644 $(BUILD)/kilix-secrets.pc $(DESTDIR)$(PREFIX)/lib/pkgconfig/
	install -m 0644 service/kilix-secrets.socket service/kilix-secrets.service \
		$(DESTDIR)$(PREFIX)/lib/systemd/user/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/include/kilix_secrets.h \
		$(DESTDIR)$(PREFIX)/lib/libkilix-secrets.a \
		$(DESTDIR)$(PREFIX)/lib/libkilix-secrets.so \
		$(DESTDIR)$(PREFIX)/lib/libkilix-secrets.so.0 \
		$(DESTDIR)$(PREFIX)/lib/pkgconfig/kilix-secrets.pc \
		$(DESTDIR)$(PREFIX)/bin/kilix-secretsd \
		$(DESTDIR)$(PREFIX)/bin/kilix-secrets \
		$(DESTDIR)$(PREFIX)/lib/systemd/user/kilix-secrets.socket \
		$(DESTDIR)$(PREFIX)/lib/systemd/user/kilix-secrets.service

clean:
	@case "$(abspath $(BUILD))" in \
		"$(CURDIR)"/build*) rm -rf -- "$(abspath $(BUILD))" ;; \
		*) printf 'refusing unsafe BUILD path: %s\n' "$(abspath $(BUILD))" >&2; exit 2 ;; \
	esac

-include $(LIB_DEPS)
