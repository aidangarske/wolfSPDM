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

# wolfSSL minimum version: v5.8.0-stable. This is the oldest release the CI
# matrix in .github/workflows/wolfssl-versions.yml exercises end-to-end; older
# releases are not validated and may be missing API/curve fixes wolfSPDM relies
# on (ECDHE P-384, HKDF-SHA384, AES-256-GCM record protection).
AC_MSG_CHECKING([wolfSSL version >= v5.8.0])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <wolfssl/version.h>
    #if !defined(LIBWOLFSSL_VERSION_HEX) || LIBWOLFSSL_VERSION_HEX < 0x05008000
    #error "wolfSSL < v5.8.0"
    #endif
    int main(void) { return 0; }
]])],
[AC_MSG_RESULT([yes])],
[AC_MSG_RESULT([no])
 AC_MSG_ERROR([wolfSPDM requires wolfSSL >= v5.8.0-stable. Please upgrade wolfSSL.])])

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

# Dynamic memory allocation (enables wolfSPDM_New/XMALLOC)
AC_ARG_ENABLE([dynamic-mem],
    [AS_HELP_STRING([--enable-dynamic-mem], [Enable dynamic memory allocation (wolfSPDM_New)])],
    [enable_dynamic_mem=$enableval],
    [enable_dynamic_mem=no])

if test "x$enable_dynamic_mem" = "xyes"; then
    AC_DEFINE([WOLFSPDM_DYNAMIC_MEMORY], [1], [Enable dynamic memory allocation])
fi

# ML-DSA (FIPS 204) post-quantum signatures (DSP0274 1.4). Default: auto-follow
# the linked wolfSSL - on when it reports WOLFSSL_HAVE_MLDSA, off otherwise.
AC_ARG_ENABLE([mldsa],
    [AS_HELP_STRING([--disable-mldsa], [Disable ML-DSA support even if wolfSSL has it])],
    [enable_mldsa=$enableval],
    [enable_mldsa=auto])

AC_MSG_CHECKING([whether wolfSSL provides ML-DSA])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/settings.h>
    #ifndef WOLFSSL_HAVE_MLDSA
    #error "no mldsa"
    #endif
    int main(void) { return 0; }
]])],
[have_wolfssl_mldsa=yes],
[have_wolfssl_mldsa=no])
AC_MSG_RESULT([$have_wolfssl_mldsa])

# wolfSPDM uses the context-based wc_MlDsaKey_* verification API (FIPS 204
# ML-DSA.Verify with a context). That API lands post-v5.9.1-stable; older
# wolfSSL releases ship only the legacy ML-DSA interface and report the same
# LIBWOLFSSL_VERSION_HEX as wolfSSL master, so we capability-test for the API
# instead of gating on a version number.
have_mldsa_api=no
if test "x$enable_mldsa" != "xno" && test "x$have_wolfssl_mldsa" = "xyes"; then
    AC_MSG_CHECKING([for the wc_MlDsaKey context API])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
        #include <wolfssl/options.h>
        #include <wolfssl/wolfcrypt/settings.h>
        #include <wolfssl/wolfcrypt/wc_mldsa.h>
    ]], [[
        MlDsaKey k; int res = 0; word32 idx = 0;
        (void)wc_MlDsaKey_VerifyCtx(&k, 0, 0, 0, 0, 0, 0, &res);
        (void)wc_MlDsaKey_PublicKeyDecode(&k, 0, 0, &idx);
    ]])],
    [have_mldsa_api=yes],
    [have_mldsa_api=no])
    AC_MSG_RESULT([$have_mldsa_api])
fi

if test "x$enable_mldsa" = "xno"; then
    AC_DEFINE([WOLFSPDM_NO_MLDSA], [1], [Disable ML-DSA support])
    mldsa_status=disabled
elif test "x$have_mldsa_api" = "xyes"; then
    mldsa_status=enabled
elif test "x$enable_mldsa" = "xyes"; then
    AC_MSG_ERROR([--enable-mldsa requires a wolfSSL with the wc_MlDsaKey context API (wolfSSL master or a release that ships it, built with --enable-mldsa). Use --disable-mldsa or update wolfSSL.])
else
    AC_DEFINE([WOLFSPDM_NO_MLDSA], [1], [Disable ML-DSA support])
    mldsa_status=disabled
fi

# Output files
AC_CONFIG_FILES([Makefile wolfspdm.pc])
AC_OUTPUT

echo ""
echo "wolfSPDM configuration summary:"
echo "  Version:     $PACKAGE_VERSION"
echo "  Debug:       $enable_debug"
echo "  Dynamic mem: $enable_dynamic_mem"
echo "  ML-DSA:      $mldsa_status"
echo "  wolfSSL:     ${WOLFSSL_DIR:-system}"
echo ""
