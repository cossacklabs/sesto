#
# Copyright (c) 2015 Cossack Labs Limited
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
#

# Project Build flags
WARNINGS := -Wno-long-long -Wall -Wswitch-enum -pedantic -Werror
CXXFLAGS := -pthread -std=gnu++98 $(WARNINGS)

#
# Compute tool paths
#
GETOS := python $(PNACL_ROOT)/tools/getos.py
OSHELPERS = python $(PNACL_ROOT)/tools/oshelpers.py
OSNAME := $(shell $(GETOS))
RM := $(OSHELPERS) rm

PNACL_TC_PATH := $(abspath $(PNACL_ROOT)/toolchain/$(OSNAME)_pnacl)
PNACL_CXX := $(PNACL_TC_PATH)/bin/pnacl-clang++
PNACL_FINALIZE := $(PNACL_TC_PATH)/bin/pnacl-finalize
CXXFLAGS := -g -I$(PNACL_ROOT)/include -I$(PNACL_ROOT)/include/pnacl -Iwebthemis/themis/src -Iwebthemis/themis/src/wrappers/themis webthemis/getentropy_pnacl.cc
LDFLAGS := -L$(PNACL_ROOT)/lib/pnacl/Release -lppapi_cpp -lppapi -lnacl_io -ljsoncpp -Lwebthemis/build -lthemis -lsoter -lcrypto -lnacl_io --pnacl-exceptions=sjlj


all: sesto_pnacl_module.pexe

clean:
	$(RM) static/*.pexe *.bc

sesto_pnacl_module.bc: sesto_pnacl_module.cc
	$(PNACL_CXX)  -std=gnu++11 -o $@ -O2 sesto_pnacl_module.cc $(CXXFLAGS) $(LDFLAGS)

sesto_pnacl_module.pexe: sesto_pnacl_module.bc
	$(PNACL_FINALIZE) -o static/$@ $<