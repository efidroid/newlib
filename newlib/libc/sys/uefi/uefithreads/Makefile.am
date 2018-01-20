## Process this file with automake to generate Makefile.in

AUTOMAKE_OPTIONS = cygnus

INCLUDES = -I$(srcdir)/../include -I$(srcdir)/machine/$(machine_dir) -I$(srcdir)/machine/generic  $(NEWLIB_CFLAGS) $(CROSS_CFLAGS) $(TARGET_CFLAGS) -I$(srcdir)/..

LIBTOOL_VERSION_INFO = 0:0:0

LIB_SOURCES= \
	pthreads.c

SUBDIRS = .

tooldir = $(tooldir)
toollibdir = $(top_toollibdir)

libpthread_la_LDFLAGS = -version-info $(LIBTOOL_VERSION_INFO) -release newlib -no-undefined -lgcc -Xcompiler -nostdlib -Xlinker --version-script=$(srcdir)/../shared.ld `cat extra-libtool-objlist`

if USE_LIBTOOL

toollib_LTLIBRARIES = libpthread.la
libpthread_la_SOURCES = $(LIB_SOURCES)
libpthread_la_LIBADD = $(LIBADD_OBJS)
libpthread_la_DEPENDENCIES = $(LIBADD_OBJS)
LIB_COMPILE = $(LTCOMPILE)

else

toollib_LIBRARIES = libpthread.a
libpthread_a_SOURCES = $(LIB_SOURCES)
libpthread_a_LIBADD = $(LIBADD_OBJS)
libpthread_a_CFLAGS = $(AM_CFLAGS)
libpthread_a_DEPENDENCIES = $(LIBADD_OBJS)
LIB_COMPILE = $(COMPILE)

endif # USE_LIBTOOL

include $(srcdir)/../../../../Makefile.shared

doc:

install-data-local: install-toollibLIBRARIES

AM_CFLAGS = -D_XOPEN_SOURCE=600 -D_GNU_SOURCE=1
ACLOCAL_AMFLAGS = -I ../../../.. -I ../../../../..
CONFIG_STATUS_DEPENDENCIES = $(newlib_basedir)/configure.host
