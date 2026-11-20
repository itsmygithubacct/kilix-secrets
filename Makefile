CC ?= cc
AR ?= ar
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local
# Library directory, separate from the prefix so a package can use the
# multiarch path. The default keeps a /usr/local install laid out as before.
LIBDIR ?= $(PREFIX)/lib
BINDIR ?= $(PREFIX)/bin
INCLUDEDIR ?= $(PREFIX)/include
UNITDIR ?= $(PREFIX)/lib/systemd/user
DOCDIR ?= $(PREFIX)/share/doc/kilix-secrets
DESTDIR ?=
BUILD ?= build
TEST_TMPDIR ?= $(if $(TMPDIR),$(TMPDIR),/tmp)
# A distribution build can pass WERROR= so a new compiler warning does not
# fail the package. The default is still to treat warnings as errors.
WERROR ?= -Werror

SODIUM_CPPFLAGS ?= $(shell $(PKG_CONFIG) --cflags libsodium 2>/dev/null)
SODIUM_LDLIBS ?= $(shell $(PKG_CONFIG) --libs libsodium 2>/dev/null || printf '%s' '-lsodium')
SYSTEMD_CPPFLAGS ?= $(shell $(PKG_CONFIG) --cflags libsystemd 2>/dev/null)
SYSTEMD_LDLIBS ?= $(shell $(PKG_CONFIG) --libs libsystemd 2>/dev/null || printf '%s' '-lsystemd')

CPPFLAGS += -Iinclude -Isrc $(SODIUM_CPPFLAGS)
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -fPIC -Wall -Wextra -Wpedantic -Wconversion -Wshadow \
	-Wstrict-prototypes -Wmissing-prototypes -Wformat=2 $(WERROR)
LDFLAGS ?=
LDLIBS += $(SODIUM_LDLIBS)

LIB_SOURCES := \
	src/util.c \
	src/memory.c \
	src/format.c \
	src/crypto.c \
	src/kdf.c \
	src/store.c \
	src/policy.c \
	src/audit.c \
	src/backup.c \
	src/protocol.c \
	src/client.c
LIB_OBJECTS := $(LIB_SOURCES:src/%.c=$(BUILD)/%.o)
LIB_DEPS := $(LIB_OBJECTS:.o=.d)

.DEFAULT_GOAL := all

.PHONY: all clean test sanitize fuzz install uninstall check-deps package-test deb deb-test calibrate

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

$(BUILD)/kilix-secretsd: src/daemon.c src/session.c src/session.h $(BUILD)/libkilix-secrets.a
	$(CC) $(CPPFLAGS) $(SYSTEMD_CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ \
		src/daemon.c src/session.c $(BUILD)/libkilix-secrets.a \
		$(LDLIBS) $(SYSTEMD_LDLIBS)

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

$(BUILD)/test-session: tests/test_session.c src/session.c src/session.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(SYSTEMD_CPPFLAGS) $(CFLAGS) -DKSEC_TESTING \
		$(LDFLAGS) -o $@ tests/test_session.c src/session.c $(SYSTEMD_LDLIBS)

$(BUILD)/test-serve-guard: tests/test_serve_guard.c src/daemon.c src/session.c \
		$(BUILD)/libkilix-secrets.a | $(BUILD)
	$(CC) $(CPPFLAGS) $(SYSTEMD_CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ \
		tests/test_serve_guard.c src/session.c $(BUILD)/libkilix-secrets.a \
		$(LDLIBS) $(SYSTEMD_LDLIBS)

$(BUILD)/identity-helper: tests/identity_helper.c $(BUILD)/libkilix-secrets.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< \
		$(BUILD)/libkilix-secrets.a $(LDLIBS)

$(BUILD)/parser-harness: tests/parser_harness.c $(BUILD)/libkilix-secrets.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< \
		$(BUILD)/libkilix-secrets.a $(LDLIBS)

test: all $(BUILD)/test-unit $(BUILD)/test-crash $(BUILD)/test-vectors \
	$(BUILD)/test-serve-guard $(BUILD)/test-session $(BUILD)/identity-helper $(BUILD)/generate-vectors \
	$(BUILD)/parser-harness
	test -d "$(TEST_TMPDIR)" && test ! -L "$(TEST_TMPDIR)"
	TMPDIR="$(TEST_TMPDIR)" $(BUILD)/test-unit
	TMPDIR="$(TEST_TMPDIR)" $(BUILD)/test-crash
	TMPDIR="$(TEST_TMPDIR)" $(BUILD)/test-serve-guard
	$(BUILD)/generate-vectors | cmp - tests/vectors/full-v1.txt
	$(BUILD)/test-vectors
	TMPDIR="$(TEST_TMPDIR)" PYTHONDONTWRITEBYTECODE=1 \
		python3 tests/run_session_harness.py --binary $(BUILD)/test-session
	TMPDIR="$(TEST_TMPDIR)" PYTHONDONTWRITEBYTECODE=1 \
		python3 tests/test_integration.py --build-dir $(BUILD)
	TMPDIR="$(TEST_TMPDIR)" PYTHONDONTWRITEBYTECODE=1 \
		python3 tests/test_identity.py --build-dir $(BUILD)
	TMPDIR="$(TEST_TMPDIR)" PYTHONDONTWRITEBYTECODE=1 \
		python3 tests/test_limits.py --build-dir $(BUILD)
	TMPDIR="$(TEST_TMPDIR)" PYTHONDONTWRITEBYTECODE=1 \
		python3 tests/test_activation.py --build-dir $(BUILD)
	PYTHONDONTWRITEBYTECODE=1 python3 tests/check_manifests.py
	PYTHONDONTWRITEBYTECODE=1 python3 tests/run_negative_corpus.py \
		--build-dir $(BUILD) --cases 4096
	TMPDIR="$(TEST_TMPDIR)" PYTHONDONTWRITEBYTECODE=1 \
		python3 tests/test_package.py --build-dir $(BUILD)
	TMPDIR="$(TEST_TMPDIR)" PYTHONDONTWRITEBYTECODE=1 \
		python3 tests/test_libdir_install.py --build-dir $(BUILD)

sanitize:
	$(MAKE) clean BUILD=build-sanitize
	$(MAKE) test BUILD=build-sanitize \
		CFLAGS='-O1 -g -std=c11 -fPIC -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Werror -fsanitize=address,undefined -fno-omit-frame-pointer' \
		LDFLAGS='-fsanitize=address,undefined'

# Not part of `all` or `install`: a measurement harness, not a shipped artifact.
calibrate: | $(BUILD)
	$(CC) -O2 -std=c11 -static $(CPPFLAGS) -o $(BUILD)/h0-calibrate \
		tools/h0-calibrate.c $(SODIUM_LDLIBS) -lpthread

fuzz: all $(BUILD)/parser-harness
	PYTHONDONTWRITEBYTECODE=1 python3 tests/run_negative_corpus.py \
		--build-dir $(BUILD) --cases 65536

install: all
	# Regenerate at install time. `all` may have written this file for a
	# different PREFIX, and the rule does not depend on that value.
	sed 's|@PREFIX@|$(PREFIX)|g' kilix-secrets.pc.in > $(BUILD)/kilix-secrets.pc
	install -d $(DESTDIR)$(INCLUDEDIR) $(DESTDIR)$(LIBDIR) \
		$(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR)/pkgconfig \
		$(DESTDIR)$(UNITDIR) \
		$(DESTDIR)$(DOCDIR)
	install -m 0644 include/kilix_secrets.h $(DESTDIR)$(INCLUDEDIR)/
	install -m 0644 $(BUILD)/libkilix-secrets.a $(DESTDIR)$(LIBDIR)/
	install -m 0755 $(BUILD)/libkilix-secrets.so.0 $(DESTDIR)$(LIBDIR)/
	ln -sfn libkilix-secrets.so.0 $(DESTDIR)$(LIBDIR)/libkilix-secrets.so
	install -m 0755 $(BUILD)/kilix-secretsd $(BUILD)/kilix-secrets $(DESTDIR)$(BINDIR)/
	install -m 0644 $(BUILD)/kilix-secrets.pc $(DESTDIR)$(LIBDIR)/pkgconfig/
	install -m 0644 service/kilix-secrets.socket service/kilix-secrets.service \
		$(DESTDIR)$(UNITDIR)/
	install -m 0644 LICENSE THIRD_PARTY_NOTICES.md docs/DEPENDENCIES.md \
		docs/F113-CUSTODY-INTERFACE.md \
		$(DESTDIR)$(DOCDIR)/

uninstall:
	rm -f $(DESTDIR)$(INCLUDEDIR)/kilix_secrets.h \
		$(DESTDIR)$(LIBDIR)/libkilix-secrets.a \
		$(DESTDIR)$(LIBDIR)/libkilix-secrets.so \
		$(DESTDIR)$(LIBDIR)/libkilix-secrets.so.0 \
		$(DESTDIR)$(LIBDIR)/pkgconfig/kilix-secrets.pc \
		$(DESTDIR)$(BINDIR)/kilix-secretsd \
		$(DESTDIR)$(BINDIR)/kilix-secrets \
		$(DESTDIR)$(UNITDIR)/kilix-secrets.socket \
		$(DESTDIR)$(UNITDIR)/kilix-secrets.service \
		$(DESTDIR)$(DOCDIR)/LICENSE \
		$(DESTDIR)$(DOCDIR)/THIRD_PARTY_NOTICES.md \
		$(DESTDIR)$(DOCDIR)/DEPENDENCIES.md \
		$(DESTDIR)$(DOCDIR)/F113-CUSTODY-INTERFACE.md
	-rmdir $(DESTDIR)$(DOCDIR)
	-rmdir $(DESTDIR)$(PREFIX)/share/doc
	-rmdir $(DESTDIR)$(PREFIX)/share
	-rmdir $(DESTDIR)$(LIBDIR)/pkgconfig
	-rmdir $(DESTDIR)$(UNITDIR)
	-rmdir $(DESTDIR)$(PREFIX)/lib/systemd
	-rmdir $(DESTDIR)$(LIBDIR)
	-rmdir $(DESTDIR)$(INCLUDEDIR) $(DESTDIR)$(BINDIR)
	-rmdir $(DESTDIR)$(PREFIX)/lib
	-rmdir $(DESTDIR)$(PREFIX)

package-test: all
	TMPDIR="$(TEST_TMPDIR)" PYTHONDONTWRITEBYTECODE=1 \
		python3 tests/test_package.py --build-dir $(BUILD)
	TMPDIR="$(TEST_TMPDIR)" PYTHONDONTWRITEBYTECODE=1 \
		python3 tests/test_libdir_install.py --build-dir $(BUILD)

deb:
	TMPDIR="$(TEST_TMPDIR)" packaging/build-deb.sh

deb-test:
	TMPDIR="$(TEST_TMPDIR)" packaging/test-deb.sh

clean:
	@case "$(abspath $(BUILD))" in \
		"$(CURDIR)"/build*) rm -rf -- "$(abspath $(BUILD))" ;; \
		*) printf 'refusing unsafe BUILD path: %s\n' "$(abspath $(BUILD))" >&2; exit 2 ;; \
	esac

-include $(LIB_DEPS)
