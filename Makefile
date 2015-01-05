###############################################################################
#
# Makefile: Makefile to build the goProbe traffic monitor
#
# Written by Lennart Elsen and Fabian Kohn, August 2014
# Copyright (c) 2014 Open Systems AG, Switzerland
# All Rights Reserved.
#
# Package for network traffic statistics capture (goProbe), storage (goDB)
# and retrieval (goquery)
#
################################################################################
# This code has been developed by Open Systems AG
#
# goProbe is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# goProbe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with goProbe; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

SHELL := /bin/bash

PKG=goProbe

# downloader used for grabbing the external code. Change this if it does not
# correspond to the usual way you download files on your system
DOWNLOAD	= curl --progress-bar -L --url

INST		= install

# GoLang main version
GO_PRODUCT	    = goProbe
GO_QUERY        = goQuery

GOLANG		    = go1.4.linux-amd64
GOLANG_SITE	    = https://storage.googleapis.com/golang
GO_SRCDIR	    = $(PWD)/addon/gocode/src
GO_CPU_PROFILE  = 0 

# for providing the go compiler with the right env vars
export GOROOT := $(PWD)/go
export PATH := $(GOROOT)/bin:$(PATH)
export GOPATH := $(PWD)/addon/gocode

# gopacket and gopcap
GOPACKET	    = v1.1.9
GOPACKET_REV	= v1.1.9 
GOPACKET_SITE	= https://gopacket.googlecode.com/archive
GOPACKETDIR	    = code.google.com/p

# pcap libraries
PCAP_VERSION = 1.5.3
PCAP		 = libpcap-$(PCAP_VERSION)
PCAP_SITE	 = http://www.tcpdump.org/release
PCAP_DIR	 = $(PWD)/$(PCAP)

# libprotoident libraries
LIBTRACE	    = libtrace-3.0.20
LIBTRACE_SITE	= http://research.wand.net.nz/software/libtrace
LIBTRACE_DIR	= $(PWD)/$(LIBTRACE)

LIBPROTOIDENT	= libprotoident-2.0.7
LPIDENT_SITE	= http://research.wand.net.nz/software/libprotoident
LPIDENT_DIR	    = $(PWD)/$(LIBPROTOIDENT)
export LD_LIBRARY_PATH := $(PWD)/$(PCAP):$(PWD)/$(LIBPROTOIDENT)/lib/.libs:$(PWD)/$(LIBTRACE)/lib/.libs:$(PWD)/addon/dpi

configure:

	## GO SETUP ##
ifeq ($(GO_CPU_PROFILE),0)
	echo "*** removing cpu profiling options in $(GO_PRODUCT) and $(GO_QUERY) ***"
	sed '/\/\/ PROFILING DEBUG START/,/\/\/ PROFILING DEBUG END/d' -i $(GO_SRCDIR)/OSAG/capture/GPCore.go
	sed '/\/\/ PROFILING DEBUG START/,/\/\/ PROFILING DEBUG END/d' -i $(GO_SRCDIR)/OSAG/query/GPQuery.go
endif

	echo "*** downloading $(GOLANG) ***"
	$(DOWNLOAD) $(GOLANG_SITE)/$(GOLANG).tar.gz -O 

	echo "*** unpacking $(GOLANG) ***"
	tar -zxf $(GOLANG).tar.gz

	echo "*** downloading gopacket_$(GOPACKET) ***"
	$(DOWNLOAD) $(GOPACKET_SITE)/$(GOPACKET).tar.gz -O

	echo "*** unpacking/patching dependency gopacket_$(GOPACKET) ***"
	tar -zxf $(GOPACKET).tar.gz
	mv gopacket-$(GOPACKET) gopacket

	patch -Np0 < addon/gopacket-$(GOPACKET).patch

	# change the library path inside pcap.go
	sed -i -e 's#LIBPCAPPATH#$(PCAP_DIR)#g' gopacket/pcap/pcap.go

	mkdir -p $(GO_SRCDIR)/$(GOPACKETDIR)
	mv gopacket $(GO_SRCDIR)/$(GOPACKETDIR)

	echo "*** downloading $(PCAP) ***"
	$(DOWNLOAD) $(PCAP_SITE)/$(PCAP).tar.gz -O 
	echo "*** unpacking/patching/configuring dependency $(PCAP) ***"
	tar -zxf $(PCAP).tar.gz
	patch -Np0 < addon/libpcap-$(PCAP_VERSION).patch
	cd $(PCAP); sh configure --prefix=/usr/local/$(PKG) --quiet >> /dev/null

	echo "*** downloading $(LIBTRACE) ***"
	$(DOWNLOAD) $(LIBTRACE_SITE)/$(LIBTRACE).tar.bz2 -O
	tar -xf $(LIBTRACE).tar.bz2

	echo "*** downloading/patching $(LIBPROTOIDENT) ***"
	$(DOWNLOAD) $(LPIDENT_SITE)/$(LIBPROTOIDENT).tar.gz -O

	tar -xf $(LIBPROTOIDENT).tar.gz
	patch -Np0 < addon/libprotoident.patch

compile:

	## GO CODE COMPILATION ##
	# first, compile libpcap and libprotoident because the go code depends on it
	echo "*** compiling $(PCAP) ***"
	cd $(PCAP); make -s > /dev/null; rm libpcap.a; ln -sf libpcap.so.$(PCAP_VERSION) libpcap.so; ln -sf libpcap.so.$(PCAP_VERSION) lipbcap.so.1

	echo "*** compiling lz4 ***"
	cd addon/lz4; make -s > /dev/null 

	echo "*** configuring/compiling $(LIBTRACE) ***"
	cd $(LIBTRACE); sh configure --prefix=/usr/local/$(PKG) CFLAGS='-I$(PCAP_DIR)' CPPFLAGS='-I$(PCAP_DIR)' LDFLAGS='-L$(PCAP_DIR)' --quiet >> /dev/null 
	cd $(LIBTRACE); make -s >> /dev/null

	echo "*** configuring/compiling dependency $(LIBPROTOIDENT) ***"
	cd $(LIBPROTOIDENT); sh configure --with-tools=no --prefix=/usr/local/$(PKG) CXXFLAGS='-I$(LIBTRACE_DIR)/lib' LDFLAGS='-L$(LIBTRACE_DIR)/lib/.libs' --quiet >> /dev/null
	cd $(LIBPROTOIDENT); make -j2 -s >> /dev/null

	echo "*** compiling ProtoId C-Wrapper ***"
	cd addon/dpi; make -s >> /dev/null

	# make the protocol-category mappings available to goquery using the
	# compiled helper binary and a bash script for IP protocols
	addon/dpi/serialize_prot_list > $(GO_SRCDIR)/OSAG/goDB/GPDPIProtocols.go
	addon/dpi/serialize_ipprot_list.sh >> $(GO_SRCDIR)/OSAG/goDB/GPDPIProtocols.go

	echo "*** compiling $(GO_PRODUCT) ***"
	cd $(GO_SRCDIR)/OSAG/capture; CGO_CFLAGS='-I$(PCAP_DIR)' CGO_LDFLAGS='-L$(PCAP_DIR)' go build -a -o $(GO_PRODUCT)   # build th    e goProbe binary

	echo "*** compiling $(GO_QUERY) ***"
	cd $(GO_SRCDIR)/OSAG/query; go build -a -o $(GO_QUERY) 

install:

	rm -rf absolute

	# additional directories
	echo "*** creating binary tree ***"
	$(INST) -d -o $(USER) -g $(USER) -m 755   absolute/usr/local/$(PKG)/etc
	$(INST) -d -o $(USER) -g $(USER) -m 755   absolute/usr/local/$(PKG)/shared
	$(INST) -d -o $(USER) -g $(USER) -m 755   absolute/usr/local/$(PKG)/data/db

	echo "*** installing $(GO_PRODUCT) and $(GO_QUERY) ***"
	cd $(PCAP); make -s install DESTDIR=$(PWD)/absolute >> /dev/null
	$(INST) -o $(USER) -g $(USER) -m 755 $(GO_SRCDIR)/OSAG/capture/$(GO_PRODUCT) absolute/usr/local/$(PKG)/bin
	$(INST) -o $(USER) -g $(USER) -m 755 $(GO_SRCDIR)/OSAG/query/$(GO_QUERY)     absolute/usr/local/$(PKG)/bin
	$(INST) -o $(USER) -g $(USER) -m 755 addon/goquery                           absolute/usr/local/$(PKG)/shared

#	echo "*** installing cronjob in /etc/cron.d ***" 
#	$(INST) -o root -g root -m 644 addon/goprobe.cron                            /etc/cron.d/goprobe.cron

	echo "*** installing $(LIBTRACE) ***"
	cd $(LIBTRACE); make -s install DESTDIR=$(PWD)/absolute >> /dev/null

	echo "*** installing $(LIBPROTOIDENT) ***"
	cd $(LIBPROTOIDENT); make -s install DESTDIR=$(PWD)/absolute >> /dev/null

	# move the libProtoId.so library and the protocol list to the correct location
	$(INST) -o $(USER) -g $(USER) -m 755 addon/dpi/libProtoId.so absolute/usr/local/$(PKG)/lib

	echo "*** cleaning unneeded files ***"

	# binary cleaning
	# libpcap binaries
	rm -f absolute/usr/local/$(PKG)/bin/pcap-config

	# libtrace binaries
	rm -f absolute/usr/local/$(PKG)/bin/trace*
	rm -f absolute/usr/local/$(PKG)/bin/wandiocat

	# library cleaning
	rm -f absolute/usr/local/$(PKG)/lib/*.la
	rm -f absolute/usr/local/$(PKG)/lib/*.lai
	rm -f absolute/usr/local/$(PKG)/lib/*.a
	rm -rf absolute/usr/local/$(PKG)/include
	rm -rf absolute/usr/local/$(PKG)/share
	rm -rf absolute/usr/local/$(PKG)/lib/libpacketdump*

	# strip binaries
	strip --strip-unneeded absolute/usr/local/$(PKG)/bin/*

	echo "*** installing binaries in standard path ***"
	$(INST) -o root -g root -m 744 addon/goprobe.init /etc/init.d/goprobe.init
	ln -sf /usr/local/$(PKG)/bin/goProbe /usr/local/sbin
	ln -sf /usr/local/$(PKG)/shared/goquery /usr/local/sbin

	rsync -a absolute/ /

package:

	tar cjf $(PKG).tar.bz2 absolute/*

clean:
	echo "*** removing binary tree ***"
	rm -rf absolute

	echo "*** removing $(GOLANG), gopacket and $(PCAP) ***"
	rm -rf go $(GOLANG).tar.gz
	rm -rf $(GO_SRCDIR)/$(GOPACKETDIR) gopacket-$(GOPACKET_REV) gopacket-$(GOPACKET) gopacket $(GO_SRCDIR)/code.google.com $(GOPACKET).tar.gz $(GO_SRCDIR)/OSAG/capture/$(GO_PRODUCT) $(GO_SRCDIR)/OSAG/query/$(GO_QUERY)
	rm -rf $(PCAP) $(PCAP).tar.gz

	echo "*** removing $(LIBTRACE) and $(LIBPROTOIDENT) ***"
	rm -rf $(LIBTRACE) $(LIBPROTOIDENT)
	rm -f $(LIBTRACE).tar.bz2 $(LIBPROTOIDENT).tar.gz
	rm -f l7protocols.json
	rm -f addon/dpi/serialize_prot_list

	rm -rf $(PKG).tar.bz2

	cd addon/lz4; make clean > /dev/null

all: clean configure compile install

.SILENT:
