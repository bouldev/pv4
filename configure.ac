AC_INIT([pv4], [1.0], [admin@boul.dev])
AC_PREREQ([2.69])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX

AC_LANG_PUSH(C++)
AX_CHECK_COMPILE_FLAG(-std=c++20, [
  CFLAGS="$CFLAGS -std=c++20"
  CPPFLAGS="$CPPFLAGS -std=c++20"], [AC_MSG_ERROR([Need at least C++ 20 to compile.])])
AC_LANG_POP(C++)

#AC_ARG_WITH([httplib-include],
#  [AS_HELP_STRING([--with-httplib-include=<path>],
#    [The directory to the httplib.h installation.])],
#  [AS_IF([test -d "$with_httplib_include"],
#    [AC_MSG_NOTICE([Using httplib.h from "$with_httplib_include"])
#     CPPFLAGS="$CPPFLAGS -I$with_httplib_include"],
#    [AC_MSG_WARN([Ignoring directory "$with_httplib_include"])])],
#  [])
# Checks for header files.
AC_LANG_PUSH([C++])
AC_CHECK_HEADERS([link.h])
AC_LANG_POP([C++])

if test "x$ac_cv_header_httplib_h" == x"no"; then
  AC_MSG_ERROR([Cannot find httplib.])
fi

# Checks for typedefs, structures, and compiler characteristics.
# If your project needs specific compiler checks, add them here.

# Most systems does not support this, but we may use it on Linux
AC_CHECK_FUNCS([dladdr1])

PKG_WITH_MODULES([FMT], [fmt], [
  CFLAGS="$CFLAGS $FMT_CFLAGS"
  LIBS="$LIBS $FMT_LIBS"
], [AC_MSG_ERROR([Cannot find fmtlib.])], [build with fmtlib support], [auto])
PKG_WITH_MODULES([JSONCPP], [jsoncpp], [
  CFLAGS="$CFLAGS $JSONCPP_CFLAGS"
  LIBS="$LIBS $JSONCPP_LIBS"
], [AC_MSG_ERROR([Cannot find jsoncpp.])])
PKG_WITH_MODULES([SPDLOG], [spdlog], [
  CFLAGS="$CFLAGS $SPDLOG_CFLAGS"
  LIBS="$LIBS $SPDLOG_LIBS"
], [AC_MSG_ERROR([Cannot find spdlog.])])
PKG_WITH_MODULES([BSONCXX], [libbsoncxx], [
  CFLAGS="$CFLAGS $BSONCXX_CFLAGS"
  LIBS="$LIBS $BSONCXX_LIBS"
], [AC_MSG_ERROR([Cannot find bsoncxx.])])
PKG_WITH_MODULES([MONGOCXX], [libmongocxx], [
  CFLAGS="$CFLAGS $MONGOCXX_CFLAGS"
  LIBS="$LIBS $MONGOCXX_LIBS"
], [AC_MSG_ERROR([Cannot find mongocxx.])])
PKG_WITH_MODULES([OPENSSL], [openssl >= 3.0], [
  CFLAGS="$CFLAGS $OPENSSL_CFLAGS"
  LIBS="$LIBS $OPENSSL_LIBS"
], [AC_MSG_ERROR([Cannot find OpenSSL >= 3.0.])], [build with SSL support], [auto])
PKG_WITH_MODULES([HTTPLIB], [cpp-httplib], [
  CFLAGS="$CFLAGS $HTTPLIB_CFLAGS"
], [AC_MSG_ERROR([Cannot find cpp-httplib.])])

CPPFLAGS="$CPPFLAGS $CFLAGS"

# Generate the configure script.
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
