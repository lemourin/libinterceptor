AC_INIT([libinterceptor], [1.0])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_MACRO_DIRS([m4])
AC_USE_SYSTEM_EXTENSIONS
AC_LANG(C++)

LT_INIT([win32-dll shared disable-static])

CXXFLAGS="-O0 -g"
CFLAGS="-O0 -g"
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_11

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  src/libinterceptor.pc
  test/Makefile
])

AC_OUTPUT
