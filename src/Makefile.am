AM_CFLAGS = $(PACKAGE_CFLAGS)

IRSSI_DIST=/usr/include/irssi
IRSSI_INCLUDE = -I$(IRSSI_DIST) \
				-I$(IRSSI_DIST)/src \
				-I$(IRSSI_DIST)/src/fe-common/core \
				-I$(IRSSI_DIST)/src/core \
				-I$(IRSSI_DIST)/src/fe-text \
				-I$(IRSSI_DIST)/src/irc \
				-I$(IRSSI_DIST)/src/irc/core \
				-I$(IRSSI_DIST)/src/irc/dcc \
				-I$(IRSSI_DIST)/src/irc/notifylist

INCLUDES = -I$(top_srcdir)/src $(IRSSI_INCLUDE)

lib_LTLIBRARIES = libotr.la

libotr_la_SOURCES = key.c key.h otr.c otr-ops.c io_set.c io_util.c \
					otr.h module.c irssi_otr.h otr-formats.c otr-formats.h