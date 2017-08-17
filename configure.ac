AC_INIT([grmpycaller], [0.1.0])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([no-dist-gzip dist-xz foreign])
AM_MAINTAINER_MODE()

dnl ********************************
dnl *** Check for basic programs ***
dnl ********************************
AC_PREREQ([2.59])
AC_PROG_CC
AC_PROG_CC_STDC
AM_PROG_CC_C_O

dnl **************************
dnl *** Initialize libtool ***
dnl **************************
LT_PREREQ([2.2.6])
LT_INIT([disable-static])

PKG_CHECK_MODULES([PYTHON35m], [python-3.5m])

AC_OUTPUT([
Makefile
libgrmpycaller/Makefile
libgrmpycaller/grmpycaller.pc
data/Makefile
])
