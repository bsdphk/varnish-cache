

AM_CPPFLAGS = \
        -I$(top_srcdir)/include \
        -I$(top_srcdir)/lib/libvsc \
        -I$(top_srcdir)/bin/varnishd \
        -I$(top_builddir)/include

AM_CFLAGS   = $(AM_LT_CFLAGS)
AM_LDFLAGS  = $(AM_LT_LDFLAGS)

lib_LTLIBRARIES = libvext_debug_persistent.la

libvext_debug_persistent_la_LDFLAGS = $(AM_LDFLAGS) -version-info 3:0:0
libvext_debug_persistent_la_CFLAGS = -DNOT_IN_A_VMOD=1 -DIS_A_VEXT=1

libvext_debug_persistent_la_SOURCES = \
	$(top_srcdir)/bin/varnishd/storage/mgt_storage_persistent.c \
	$(top_srcdir)/bin/varnishd/storage/storage_persistent.c \
	$(top_srcdir)/bin/varnishd/storage/storage_persistent_silo.c \
	$(top_srcdir)/bin/varnishd/storage/storage_persistent_subr.c
	

