## Process this file with automake to generate Makefile.in

AUTOMAKE_OPTIONS = cygnus

INCLUDES = $(NEWLIB_CFLAGS) $(CROSS_CFLAGS) $(TARGET_CFLAGS) -I$(newlib_basedir)/libc/machine/uefi

SUBDIRS = \
	$(EXTRA_SUBDIRS) \
	.

SUBLIBS = \
	$(EXTRA_SUBLIBS)

AM_CCASFLAGS = $(INCLUDES)

noinst_LIBRARIES = lib.a

if MAY_SUPPLY_SYSCALLS
extra_objs = $(lpfx)syscalls.o
else
extra_objs =
endif

lib_a_SOURCES =
lib_a_LIBADD = $(extra_objs)
EXTRA_lib_a_SOURCES = syscalls.c
lib_a_DEPENDENCIES = $(extra_objs)
lib_a_CCASFLAGS = $(AM_CCASFLAGS)
lib_a_CFLAGS = $(AM_CFLAGS)

if MAY_SUPPLY_SYSCALLS
all-local: crt0.o

crt0.o: crt0.c
	$(CC) $(CFLAGS_FOR_TARGET) $($(MULTI_FLAGS_FOR_TARGET)) $(CFLAGS) $(INCLUDES) -fPIC -o $@ -c $<
endif

ACLOCAL_AMFLAGS = -I ../../.. -I ../../../..
CONFIG_STATUS_DEPENDENCIES = $(newlib_basedir)/configure.host
