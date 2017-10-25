AM_CPPFLAGS = \
	-I$(top_srcdir)

lib_LTLIBRARIES = \
	libgrmpycaller.la

libgrmpycaller_includedir = $(includedir)/gooroom/libgrmpycaller

libgrmpycaller_include_HEADERS = grmpycaller.h

libgrmpycaller_la_SOURCES = grmpycaller.c

libgrmpycaller_la_CFLAGS = $(PYTHON35m_CFLAGS) -lssl -lcrypto

libgrmpycaller_la_LDFLAGS = \
	-no-undefined \
	-export-dynamic

libgrmpycaller_la_LIBADD = $(PYTHON35m_LIBS)

pycallerdir=$(libdir)/gooroom-security-utils/pycaller
pycaller_DATA=	\
	pycaller.py

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = grmpycaller.pc
