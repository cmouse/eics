AC_INIT(eics, 4.0, cmouse@cmouse.fi)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/main.cc)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(src/config.h)
AC_USE_SYSTEM_EXTENSIONS

LT_INIT
AC_PROG_CXX
gl_EARLY
AC_PROG_LIBTOOL
AM_PATH_DOTCONF(1.0.0, [], AC_MSG_ERROR([dotconf is required to compile this software]))

AC_GNU_SOURCE
gl_INIT

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES(GNUTLS, [gnutls], [], AC_MSG_ERROR([GnuTLS is required to compile this software]))

BOOST_REQUIRE(1.46)

BOOST_ARRAY
BOOST_FILESYSTEM
BOOST_PROGRAM_OPTIONS
BOOST_THREADS

AC_CHECK_LIB(acl, acl_init)
AC_CHECK_LIB(attr, attr_list)

AC_OUTPUT(Makefile src/Makefile lib/Makefile)
