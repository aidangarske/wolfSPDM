AC_PREREQ([2.69])
AC_INIT([wolfspdm],[1.0.0],[support@wolfssl.com])
AC_CONFIG_SRCDIR([src/spdm_context.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11 foreign subdir-objects -Wall -Werror])

AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
AC_PROG_INSTALL
LT_INIT

# Checks for header files
AC_CHECK_HEADERS([stdint.h string.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# wolfSSL/wolfCrypt detection
AC_ARG_WITH([wolfssl],
    [AS_HELP_STRING([--with-wolfssl=PATH], [Path to wolfSSL installation])],
    [WOLFSSL_DIR=$withval],
    [WOLFSSL_DIR=""])

if test -n "$WOLFSSL_DIR"; then
    # Prepend local wolfSSL includes to ensure they take priority over system
    CPPFLAGS="-I$WOLFSSL_DIR -I$WOLFSSL_DIR/include $CPPFLAGS"
    LDFLAGS="-L$WOLFSSL_DIR/src/.libs -L$WOLFSSL_DIR/lib $LDFLAGS"
fi

AC_CHECK_LIB([wolfssl], [wc_InitRng], [],
    [AC_MSG_ERROR([wolfSSL library not found. Use --with-wolfssl=PATH])])

AC_CHECK_HEADER([wolfssl/wolfcrypt/ecc.h], [],
    [AC_MSG_ERROR([wolfSSL headers not found. Use --with-wolfssl=PATH])])

# Debug mode
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug], [Enable debug output])],
    [enable_debug=$enableval],
    [enable_debug=no])

if test "x$enable_debug" = "xyes"; then
    AC_DEFINE([WOLFSPDM_DEBUG], [1], [Enable debug output])
    CFLAGS="$CFLAGS -g -O0"
else
    CFLAGS="$CFLAGS -O2"
fi

# Nuvoton TPM support (TCG binding + vendor commands)
AC_ARG_ENABLE([nuvoton],
    [AS_HELP_STRING([--enable-nuvoton], [Enable Nuvoton TPM support (TCG binding headers, vendor commands)])],
    [enable_nuvoton=$enableval],
    [enable_nuvoton=no])

if test "x$enable_nuvoton" = "xyes"; then
    AC_DEFINE([WOLFSPDM_NUVOTON], [1], [Enable Nuvoton TPM support])
fi
AM_CONDITIONAL([BUILD_NUVOTON], [test "x$enable_nuvoton" = "xyes"])

# Output files
AC_CONFIG_FILES([Makefile wolfspdm.pc])
AC_OUTPUT

echo ""
echo "wolfSPDM configuration summary:"
echo "  Version:     $PACKAGE_VERSION"
echo "  Debug:       $enable_debug"
echo "  Nuvoton:     $enable_nuvoton"
echo "  wolfSSL:     ${WOLFSSL_DIR:-system}"
echo ""
