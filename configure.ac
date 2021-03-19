AC_PREREQ([2.60])
AC_INIT([packet-norp], [0.0.0], [mvs@nyantec.com])

AC_CONFIG_SRCDIR([packet-norp.c])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_TARGET
AX_ENABLE_BUILDDIR([$target])
AM_INIT_AUTOMAKE([foreign subdir-objects tar-pax dist-xz no-dist-gzip])

AX_SPLIT_VERSION([AC_PACKAGE_VERSION])

AC_PROG_CC([clang gcc cl cc])
AC_PROG_CC_STDC
AC_PROG_LN_S
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AX_AM_JOBSERVER

AC_SYS_LARGEFILE

AC_HEADER_ASSERT
AC_HEADER_STDC

AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

AC_C_RESTRICT

AX_CFLAGS_NO_WRITABLE_STRINGS
AX_CFLAGS_WARN_ALL

AX_ADD_FORTIFY_SOURCE

AX_APPEND_COMPILE_FLAGS([ \
	-Wcast-align \
	-Werror=implicit-function-declaration \
	-Werror=init-self \
	-Werror=nonnull \
	-Werror=sequence-point \
	-Werror=uninitialized \
	-Wformat \
	-Wformat-security \
	-Wredundant-decls \
	-Wshadow \
	-Wstrict-overflow=4 \
	-Wtype-limits \
	-fstack-protector-strong \
	-flto \
])

AX_APPEND_LINK_FLAGS([ \
	-Wl,-z,combreloc \
	-Wl,-z,relro \
	-Wl,-z,now \
])

PKG_CHECK_MODULES([wireshark], [wireshark >= 3.4])
AC_SUBST([epandir], [$($PKG_CONFIG --variable=plugindir wireshark)/epan])
AC_DEFINE([HAVE_PLUGINS], [1], [Work around missing inclusion of <wireshark/config.h>])

wireshark_version="$($PKG_CONFIG --modversion wireshark)"
wireshark_version_major="$(echo "$wireshark_version" | $SED 's/\([[^.]][[^.]]*\).*/\1/')"
wireshark_version_minor="$(echo "$wireshark_version" | $SED 's/[[^.]][[^.]]*.\([[^.]][[^.]]*\).*/\1/')"

AC_DEFINE_UNQUOTED([WIRESHARK_VERSION_RELEASE],
	["$wireshark_version_major.$wireshark_version_minor"], [Wireshark release version])
AC_DEFINE_UNQUOTED([WIRESHARK_VERSION_MAJOR], [$wireshark_version_major], [Wireshark major version])
AC_DEFINE_UNQUOTED([WIRESHARK_VERSION_MINOR], [$wireshark_version_minor], [Wireshark minor version])

AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT
