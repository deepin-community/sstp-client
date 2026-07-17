noinst_LTLIBRARIES     = libsstp_log.la
libsstp_log_la_CFLAGS  = -I$(top_srcdir)/include
libsstp_log_la_SOURCES = \
    sstp-log.c          \
    sstp-log-syslog.c   \
    sstp-log-std.c      \
    sstp-log-file.c

noinst_HEADERS =        \
    sstp-log-private.h

utest_log_SOURCES   = sstp-log.c
utest_log_CFLAGS    = -I$(top_srcdir)/include -D__SSTP_UNIT_TEST_LOG=1

check_PROGRAMS      =   \
    utest_log

# This test isn't ready yet
# TESTS= $(check_PROGRAMS)
