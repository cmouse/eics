AC_INIT(eics, 4.0, cmouse@cmouse.fi)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/main.cc)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(src/config.h)
AC_USE_SYSTEM_EXTENSIONS

LT_INIT
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL

AC_GNU_SOURCE

AC_CHECK_HEADERS([sys/vfs.h sys/statfs.h termios.h])
AC_CHECK_FUNCS([statfs])

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES(openssl, [libssl], [], AC_MSG_ERROR([OpenSSL is required to compile this software]))

BOOST_REQUIRE(1.46)

BOOST_ARRAY
BOOST_DATE_TIME
BOOST_FILESYSTEM
BOOST_THREADS
BOOST_TOKENIZER

AC_CHECK_FUNC(gnutls_load_file)

AC_CHECK_LIB(acl, acl_init)
AC_CHECK_LIB(attr, attr_list)

AC_OUTPUT(Makefile src/Makefile)
