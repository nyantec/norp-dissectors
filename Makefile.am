AM_LDFLAGS = -module -avoid-version -shared

AM_CFLAGS = $(wireshark_CFLAGS)
LDADD = $(wireshark_LIBS)

epan_LTLIBRARIES = norp.la
norp_la_SOURCES = \
	plugin.c \
	packet-norp.h \
	packet-norp.c \
	packet-nyantec-oui.h \
	packet-nyantec-oui.c \
	packet-ieee802a-nyantec.c \
	packet-llc-nyantec.c
