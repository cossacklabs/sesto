#
# Copyright (c) 2016 Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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