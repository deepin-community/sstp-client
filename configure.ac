AC_PREREQ([2.69])
AC_INIT([sstp-client],
	 [1.0.17],
	 [https://gitlab.com/eivnaes/sstp-client])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_LANG(C)
AC_CONFIG_SRCDIR([src/sstp-client.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
LIBEVENT2_MINIMUM=2.0.10

LT_INIT

PKG_PROG_PKG_CONFIG()

# Check if user asked us to compile with 1.4 support
AC_ARG_WITH(libevent,
    AS_HELP_STRING([--with-libevent],[Specify the libevent version to compile with]),
    [with_libevent="$withval"], [with_libevent="2"])

AS_CASE([$with_libevent],
    ["1"],[AX_CHECK_LIBRARY([LIBEVENT], [event.h], [event], 
            [AC_CHECK_LIB([event], [event_init], [],
                [AC_MSG_ERROR([libevent is not usable])])],
            [AC_MSG_ERROR([Required library libevent not found])])],
    ["2"],[PKG_CHECK_MODULES([LIBEVENT], [libevent >= $LIBEVENT2_MINIMUM],
            [AC_DEFINE([HAVE_LIBEVENT2], [1], [Specify use of libevent >= $LIBEVENT2_MINIMUM])],
            [AC_MSG_ERROR([Required library libevent not found])])],
    ["*"],[AC_MSG_ERROR([Unknown version of libevent specified])])

CFLAGS="$LIBEVENT_CFLAGS $CFLAGS"
LDFLAGS="$LIBEVENT_LIBS $LDFLAGS"

# Check for OpenSSL
AX_CHECK_OPENSSL([], 
    [AC_MSG_ERROR([OpenSSL not found Hint: apt-get install libssl-dev])])
LIBS="$LIBS $OPENSSL_LIBS"
CFLAGS="$OPENSSL_INCLUDES $CFLAGS"
LDFLAGS="$OPENSSL_LDFLAGS $LDFLAGS"


# Check for openpty
AC_CHECK_LIB([util], [openpty])


# Specify privilege separation user
AC_ARG_ENABLE(user,
    AS_HELP_STRING([--enable-user=user],[Drop privileges after start to this user (default: sstpc)]))
AS_IF([ test "${enable_user}" = "yes" || test x"${enable_user}" = x"" ],
    [enable_user="sstpc"],
    [enable_user="root"])
AC_SUBST([enable_user])
AC_DEFINE_UNQUOTED(SSTP_USER, "${enable_user}", The sstpc privilege drop user)


# Specify privilege separation group
AC_ARG_ENABLE(group,
    AS_HELP_STRING([--enable-group=group],[Drop privileges after start to this group (default: sstpc)]))
AS_IF([ test "${enable_group}" = "yes" || test x"${enable_group}" = x"" ],
    [enable_group="sstpc"],
    [enable_group="root"])
AC_SUBST([enable_group])
AC_DEFINE_UNQUOTED(SSTP_GROUP, "${enable_group}", The sstpc privilege drop group)


# Specify runtime directory
AC_ARG_WITH([runtime-dir], 
	AS_HELP_STRING([--with-runtime-dir=DIR],[Specify the runtime directory for sstpc]))
AS_IF([ test -n "$with_runtime_dir"],
	[SSTP_RUNTIME_DIR="$with_runtime_dir"],
	[SSTP_RUNTIME_DIR="${localstatedir}/run/sstpc"])
AC_SUBST(SSTP_RUNTIME_DIR)


# Check to see if we enabled PPP plug-in support (default:yes)
AC_ARG_ENABLE(ppp-plugin, 
    AS_HELP_STRING([--disable-ppp-plugin=DIR],[disable PPP Plugin support]),
    [enable_ppp_plugin=${enableval}], [enable_ppp_plugin=yes])
AS_IF([test "x$enable_ppp_plugin" != "xno"],
    AC_CHECK_HEADER(pppd/pppd.h,,
            AC_MSG_ERROR([pppd.h missing Hint: apt-get install ppp-dev]))
    AC_DEFINE(HAVE_PPP_PLUGIN, 1, [Define if you have PPP support]))

# Check if the version of mppe.h define mppe_keys_xxx() functions, 2.4.9 does not; but 2.4.10 will.
AM_CONDITIONAL(WITH_PPP_PLUGIN, test "${enable_ppp_plugin}" = "yes")
AS_IF([test "x$enable_ppp_plugin" != "xno"],
    [CFLAGS_OLD="$CFLAGS"
     CFLAGS="$CFLAGS -Werror"
     AC_CACHE_CHECK([if pppd/mppe.h defines mppe_keys_xyz() functions], ac_cv_working_mppe_h,
     [AC_COMPILE_IFELSE(
         [AC_LANG_PROGRAM([[
            @%:@define MPPE 1
            @%:@include <pppd/pppd.h>
            @%:@include <pppd/chap_ms.h>
            @%:@include <pppd/mppe.h>]],
            [[if (mppe_keys_isset())
                return 0;]])],
        [ac_cv_working_mppe_h=yes],
        [ac_cv_working_mppe_h=no])])
     if test $ac_cv_working_mppe_h = yes; then
         AC_DEFINE(HAVE_MPPE_KEYS_FUNCTIONS, 1,
             [Define to 1 if you have <pppd/mppe.h> and it declares the mppe_keys_xyz() functions])
     fi
     CFLAGS="$CFLAGS_OLD"
    ])

# pkg-config support was added in 2.4.10, assuming 2.4.7 if not given
PPPD_VERSION=2.4.7
PPPD_MINIMUM=2.4.9
AM_CONDITIONAL(WITH_PPP_PLUGIN, test "${enable_ppp_plugin}" = "yes")
PKG_CHECK_EXISTS([pppd],
    [PKG_CHECK_MODULES([pppd], [pppd >= $PPPD_MINIMUM],
        [AS_VAR_SET([with_pppd_auth_notify_support],[yes])],
        [AC_MSG_RESULT(version < $PPPD_MINIMUM)])
     PPPD_PLUGIN_CFLAGS=$pppd_CFLAGS
     AC_SUBST(PPPD_PLUGIN_CFLAGS)
     PPPD_VERSION=`$PKG_CONFIG --modversion pppd`
    ])

# Auth notifier was fixed in pppd version 2.4.9
AM_CONDITIONAL(WITH_PPP_PLUGIN, test "${enable_ppp_plugin}" = "yes")
AC_ARG_WITH([pppd-auth-notify-support],
    AS_HELP_STRING([--with-pppd-auth-notify-support], [is the auth-notifier supported in this pppd version]))
AS_IF([test "x$with_pppd_auth_notify_support" == "xyes" ],
    [AC_DEFINE(USE_PPPD_AUTH_HOOK,1,[Define if pppd has support for client side authentication complete notification])
     PPPD_AUTH_NOTIFIER="yes"], 
    [PPPD_AUTH_NOTIFIER="no"])

# Check to see if the plugin directory was set
AM_CONDITIONAL(WITH_PPP_PLUGIN, test "${enable_ppp_plugin}" = "yes")
AC_ARG_WITH([pppd-plugin-dir], 
    AS_HELP_STRING([--with-pppd-plugin-dir=DIR], [path to the pppd plugins directory]))
if test -n "$with_pppd_plugin_dir" ; then
    PPPD_PLUGIN_DIR="$with_pppd_plugin_dir"
else
    PPPD_PLUGIN_DIR="${libdir}/pppd/$PPPD_VERSION"
fi
AC_SUBST(PPPD_PLUGIN_DIR)

# system CA certificates path
AC_ARG_WITH(system-ca-path,
            AS_HELP_STRING([--with-system-ca-path=/path/to/ssl/certs], [path to system CA certificates]))
if test "x${with_system_ca_path}" = x; then 
    SYSTEM_CA_PATH="${sysconfdir}/ssl/certs"
else
    SYSTEM_CA_PATH="$with_system_ca_path"
fi
AC_DEFINE_UNQUOTED(SYSTEM_CA_PATH, "$SYSTEM_CA_PATH", [Define to path to system CA certificates])
AC_SUBST(SYSTEM_CA_PATH)

# Check if we have netlink support
AC_CHECK_HEADER([linux/rtnetlink.h],
    AC_DEFINE(HAVE_NETLINK, 1, [Use netlink to add/remove route]),
    AC_MSG_WARN([Compiling without netlink support]),
    [#include <sys/socket.h>
     #include <linux/netlink.h>])

# Checks for header files.
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([  \
    arpa/inet.h     \
    fcntl.h         \
    netdb.h         \
    paths.h         \
    stdint.h        \
    stdlib.h        \
    string.h        \
    syslog.h        \
    stdbool.h       \
    pty.h           \
    sys/types.h     \
    sys/socket.h    \
    unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_CHOWN
AC_FUNC_MALLOC
AC_CHECK_FUNCS([    \
    dup2            \
    gethostname     \
    localtime_r     \
    memmove         \
    memset          \
    mkdir           \
    socket          \
    strcasecmp      \
    strncasecmp     \
    strchr          \
    strdup          \
    strrchr         \
    strstr          \
    strtoul         \
    strtoull])

AC_CONFIG_FILES([Makefile
                 sstp-client-1.0.pc
                 src/Makefile
                 include/Makefile
                 src/libsstp-log/Makefile
                 src/libsstp-api/Makefile
                 src/libsstp-compat/Makefile
                 src/pppd-plugin/Makefile])
AC_OUTPUT

echo -n "
$PACKAGE_NAME version $PACKAGE_VERSION
    Prefix..........: $prefix
    Runtime Dir.....: $SSTP_RUNTIME_DIR
    System CA Path..: $SYSTEM_CA_PATH
    User:...........: $enable_user
    Group:..........: $enable_group
    Using OpenSSL...: $OPENSSL_INCLUDES $OPENSSL_LDFLAGS $OPENSSL_LIBS
    C Compiler......: $CC $CFLAGS
    Using Event.....: $LIBEVENT_CFLAGS $LIBEVENT_LIBS
    Linker..........: $LD $LDFLAGS $LIBS
"
if [ test "x${enable_ppp_plugin}" = "xyes" ] ; then
    echo -n "
with pppd plugin support
    Plugin Directory: $PPPD_PLUGIN_DIR
    Auth-Notifier...: $PPPD_AUTH_NOTIFIER
    Plugin Cflags...: $PPPD_PLUGIN_CFLAGS
"
fi

