ACLOCAL_AMFLAGS = -I m4

AM_CXXFLAGS = \
	-std=c++11

AM_LDFLAGS = \
	-no-undefined \
	-ldl

lib_LTLIBRARIES = libinterceptor.la

libinterceptor_la_SOURCES = \
	interceptor.cpp

noinst_HEADERS =

nobase_include_HEADERS = \
	interceptor.h

libinterceptor_la_LIBADD =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libinterceptor.pc
