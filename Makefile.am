ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libwolfspdm.la

libwolfspdm_la_SOURCES = \
    src/spdm_context.c \
    src/spdm_crypto.c \
    src/spdm_kdf.c \
    src/spdm_msg.c \
    src/spdm_secured.c \
    src/spdm_session.c \
    src/spdm_transcript.c

# Nuvoton TPM support (TCG binding + vendor commands)
if BUILD_NUVOTON
libwolfspdm_la_SOURCES += src/spdm_nuvoton.c
endif

libwolfspdm_la_CPPFLAGS = -I$(srcdir)/wolfspdm -I$(srcdir)/src
libwolfspdm_la_LIBADD = -lwolfssl

# Generate options.h from config.h (propagate WOLFSPDM_ defines to consumers)
BUILT_SOURCES = wolfspdm/options.h
wolfspdm/options.h: config.h
	@mkdir -p wolfspdm
	@echo '/* wolfspdm/options.h — auto-generated from config.h, do not edit */' > $@
	@echo '#ifndef WOLFSPDM_OPTIONS_H' >> $@
	@echo '#define WOLFSPDM_OPTIONS_H' >> $@
	@grep '^\#define WOLFSPDM_' config.h >> $@ || true
	@echo '#endif /* WOLFSPDM_OPTIONS_H */' >> $@

# Public headers
nobase_include_HEADERS = \
    wolfspdm/spdm.h \
    wolfspdm/spdm_types.h \
    wolfspdm/spdm_error.h \
    wolfspdm/options.h

# Nuvoton header (always installed, conditionally useful)
if BUILD_NUVOTON
nobase_include_HEADERS += wolfspdm/spdm_nuvoton.h
endif

# Test programs
check_PROGRAMS = test/unit_test test/test_spdm

test_unit_test_SOURCES = test/unit_test.c
test_unit_test_CPPFLAGS = -I$(srcdir)/wolfspdm -I$(srcdir)/src
test_unit_test_LDADD = libwolfspdm.la -lwolfssl

test_test_spdm_SOURCES = test/test_spdm.c
test_test_spdm_CPPFLAGS = -I$(srcdir)/wolfspdm
test_test_spdm_LDADD = libwolfspdm.la -lwolfssl

TESTS = test/unit_test

# pkgconfig
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = wolfspdm.pc

EXTRA_DIST = \
    autogen.sh \
    README.md \
    LICENSE \
    wolfspdm.pc.in

CLEANFILES = wolfspdm.pc wolfspdm/options.h
