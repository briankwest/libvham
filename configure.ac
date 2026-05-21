dnl libvham — autoconf script.
dnl
dnl Auto-detects optional codec / crypto libraries and gates the
dnl corresponding source files + -DVHAM_WITH_* defines accordingly.
dnl
dnl Re-generate `configure` after editing with:  autoreconf -i

AC_PREREQ([2.69])
AC_INIT([libvham], [1.0], [https://github.com/anthropics/vham])
AC_CONFIG_SRCDIR([src/codec.c])
AC_CONFIG_AUX_DIR([build-aux])

dnl --- toolchain ---------------------------------------------------------
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_CHECK_TOOL([AR], [ar], [ar])

dnl pkg-config availability is highly preferred (most distros ship .pc
dnl files for the optional libs); we fall back to AC_CHECK_LIB.
PKG_PROG_PKG_CONFIG

dnl Pre-flight: pick up the homebrew prefix on macOS so deps installed
dnl under /opt/homebrew (Apple Silicon) or /usr/local (Intel) are seen.
AC_CHECK_PROG([BREW], [brew], [brew])
if test "x$BREW" != x; then
    HOMEBREW_PREFIX=`$BREW --prefix 2>/dev/null`
    if test "x$HOMEBREW_PREFIX" != x; then
        AC_MSG_NOTICE([using homebrew prefix $HOMEBREW_PREFIX])
        CPPFLAGS="$CPPFLAGS -I$HOMEBREW_PREFIX/include"
        LDFLAGS="$LDFLAGS -L$HOMEBREW_PREFIX/lib"
    fi
fi

dnl ----------------------------------------------------------------------
dnl Per-dep detection. Each emits VHAM_WITH_X=yes/no, X_CFLAGS, X_LIBS,
dnl and substitutes a -D into VHAM_FEATURE_DEFS used by Makefile.in.
dnl ----------------------------------------------------------------------

dnl Optional dep boilerplate. Takes:
dnl   $1  cli arg (opus, amr, ilbc, dtls)
dnl   $2  pretty name
dnl   $3  detection command (sets HAVE_$1=yes on success and fills CFLAGS/LIBS)
dnl   $4  source file to add to SRCS when enabled (e.g. src/codec_opus.c)
m4_define([VHAM_OPTIONAL_DEP], [
  AC_ARG_WITH([$1],
    [AS_HELP_STRING([--with-$1], [enable $2 support (default: auto)])
     AS_HELP_STRING([--without-$1], [disable $2 support])],
    [WITH_$1=$withval],
    [WITH_$1=auto])

  if test "x$WITH_$1" != "xno"; then
    $3
    if test "x$HAVE_$1" = "xyes"; then
      VHAM_FEATURE_DEFS="$VHAM_FEATURE_DEFS -DVHAM_WITH_[]m4_toupper($1)"
      VHAM_FEATURE_SRCS="$VHAM_FEATURE_SRCS $4"
    elif test "x$WITH_$1" = "xyes"; then
      AC_MSG_ERROR([$2 was requested but the required library wasn't found])
    fi
  fi
  AC_MSG_CHECKING([whether $2 support is enabled])
  AC_MSG_RESULT([$HAVE_$1])
])

dnl -- Opus -------------------------------------------------------------
HAVE_opus=no
VHAM_OPTIONAL_DEP([opus], [Opus codec (PT 106)], [
  PKG_CHECK_MODULES([OPUS], [opus],
    [HAVE_opus=yes],
    [AC_CHECK_LIB([opus], [opus_encoder_create],
       [AC_CHECK_HEADER([opus.h],
          [HAVE_opus=yes
           OPUS_LIBS="-lopus"],
          [HAVE_opus=no])],
       [HAVE_opus=no])])
], [src/codec_opus.c])

dnl -- AMR-NB + AMR-WB (treated as one toggle) -------------------------
HAVE_amr=no
VHAM_OPTIONAL_DEP([amr], [AMR-NB and AMR-WB codecs (PT 96/97)], [
  AC_CHECK_HEADER([opencore-amrnb/interf_enc.h],
    [AC_CHECK_LIB([opencore-amrnb], [Encoder_Interface_init],
       [AC_CHECK_HEADER([opencore-amrwb/dec_if.h],
          [AC_CHECK_LIB([opencore-amrwb], [D_IF_init],
             [AC_CHECK_HEADER([vo-amrwbenc/enc_if.h],
                [AC_CHECK_LIB([vo-amrwbenc], [E_IF_init],
                   [HAVE_amr=yes
                    AMR_LIBS="-lopencore-amrnb -lopencore-amrwb -lvo-amrwbenc"],
                   [HAVE_amr=no])],
                [HAVE_amr=no])],
             [HAVE_amr=no])],
          [HAVE_amr=no])],
       [HAVE_amr=no])],
    [HAVE_amr=no])
], [src/codec_amr.c])

dnl -- iLBC -------------------------------------------------------------
HAVE_ilbc=no
VHAM_OPTIONAL_DEP([ilbc], [iLBC codec (PT 102)], [
  AC_CHECK_HEADER([ilbc.h],
    [AC_CHECK_LIB([ilbc], [WebRtcIlbcfix_EncoderCreate],
       [HAVE_ilbc=yes
        ILBC_LIBS="-lilbc"],
       [HAVE_ilbc=no])],
    [HAVE_ilbc=no])
], [src/codec_ilbc.c])

dnl -- DTLS-SRTP (mbedtls 3 + libsrtp2) -------------------------------
dnl
dnl mbedtls 4.x removed mbedtls_ssl_conf_rng / ctr_drbg.h / entropy.h —
dnl all of which our DTLS code uses. We must use the v3 API. On macOS
dnl that's `brew install mbedtls@3`; check for the v3-specific symbol
dnl to be sure we got the right one.
HAVE_dtls=no
VHAM_OPTIONAL_DEP([dtls], [DTLS-SRTP (mbedtls 3 + libsrtp2)], [
  saved_CPPFLAGS=$CPPFLAGS
  saved_LDFLAGS=$LDFLAGS
  if test "x$BREW" != x; then
    MBEDTLS3_PREFIX=`$BREW --prefix mbedtls@3 2>/dev/null`
    if test -n "$MBEDTLS3_PREFIX" && test -d "$MBEDTLS3_PREFIX/include"; then
      AC_MSG_NOTICE([found mbedtls@3 at $MBEDTLS3_PREFIX])
      CPPFLAGS="-I$MBEDTLS3_PREFIX/include $CPPFLAGS"
      LDFLAGS="-L$MBEDTLS3_PREFIX/lib $LDFLAGS"
      DTLS_CFLAGS="-I$MBEDTLS3_PREFIX/include"
      DTLS_LIBS_PREFIX="-L$MBEDTLS3_PREFIX/lib"
    fi
  fi
  AC_CHECK_HEADER([mbedtls/ctr_drbg.h],
    [AC_CHECK_LIB([mbedcrypto], [mbedtls_ctr_drbg_seed],
       [AC_CHECK_LIB([mbedtls], [mbedtls_ssl_conf_rng],
          [AC_CHECK_HEADER([srtp2/srtp.h],
             [AC_CHECK_LIB([srtp2], [srtp_init],
                [HAVE_dtls=yes
                 DTLS_LIBS="$DTLS_LIBS_PREFIX -lmbedtls -lmbedx509 -lmbedcrypto -lsrtp2"],
                [HAVE_dtls=no])],
             [HAVE_dtls=no])],
          [HAVE_dtls=no],
          [-lmbedx509 -lmbedcrypto])],
       [HAVE_dtls=no])],
    [HAVE_dtls=no])
  if test "x$HAVE_dtls" != "xyes"; then
    CPPFLAGS=$saved_CPPFLAGS
    LDFLAGS=$saved_LDFLAGS
  fi
], [])dnl DTLS source lives in src/srtp.c (always compiled — guarded by #ifdef)

dnl --- expose to Makefile -----------------------------------------------
AC_SUBST([VHAM_FEATURE_DEFS])
AC_SUBST([VHAM_FEATURE_SRCS])
AC_SUBST([OPUS_CFLAGS])
AC_SUBST([OPUS_LIBS])
AC_SUBST([AMR_LIBS])
AC_SUBST([ILBC_LIBS])
AC_SUBST([DTLS_CFLAGS])
AC_SUBST([DTLS_LIBS])

dnl Combined link line, with DTLS first so mbedtls@3 outranks any
dnl mbedtls 4 from a more general -L path.
VHAM_EXTRA_LIBS="$DTLS_LIBS $OPUS_LIBS $AMR_LIBS $ILBC_LIBS"
AC_SUBST([VHAM_EXTRA_LIBS])

dnl Likewise put DTLS includes first.
VHAM_EXTRA_CFLAGS="$DTLS_CFLAGS $OPUS_CFLAGS"
AC_SUBST([VHAM_EXTRA_CFLAGS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

dnl --- summary ---------------------------------------------------------
echo
echo "  libvham build configuration"
echo "  ------------------------------"
echo "  cc           = $CC"
echo "  CFLAGS       = $CFLAGS"
echo "  Opus         = $HAVE_opus"
echo "  AMR-NB/WB    = $HAVE_amr"
echo "  iLBC         = $HAVE_ilbc"
echo "  DTLS-SRTP    = $HAVE_dtls"
echo
echo "  Run \`make\` to build."
echo
