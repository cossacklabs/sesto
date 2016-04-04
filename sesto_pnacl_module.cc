/*
 * Copyright (c) 2015 Cossack Labs Limited
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
*/

#include <cstdio>
#include <string>
#include "ppapi/cpp/instance.h"
#include "ppapi/cpp/module.h"
#include "ppapi/cpp/var.h"
#include "ppapi/cpp/var_array.h"
#include "nacl_io/nacl_io.h"

#include <themispp/secure_cell.hpp>

#include "helpers/base64.hpp"

#define VECTOR(str) std::vector<uint8_t>(str.c_str(), str.c_str()+str.length())

namespace pnacl {
  namespace themis {

    class sesto_instance : public pp::Instance {
    private:
      enum mode{SEAL, TOKEN_PROTECT, CONTEXT_IMPRINT, UNDEFINED};
    public:
      explicit sesto_instance(PP_Instance instance) : 
	pp::Instance(instance)
      {
	nacl_io_init_ppapi(instance, pp::Module::Get()->get_browser_interface());
	post("info", std::string("used themis version ")+themis_version());
      }
      virtual ~sesto_instance() {}

      virtual bool Init(uint32_t argc, const char* argn[], const char* argv[]) {
	return true;
      }

    public:
      virtual void HandleMessage(const pp::Var& var_message) {
	if (!var_message.is_array()){
	  post("error", "incorrect message format");
	  return;
	}
	pp::VarArray params(var_message);  
      }

      void post(const std::string& command, const std::string& param1){
	pp::VarArray message;
	message.Set(0,command);
	message.Set(1,param1);
	PostMessage(message);
      }

      void post(const std::string& command, const std::string& param1, const std::string& param2){
	pp::VarArray message;
	message.Set(0,command);
	message.Set(1,param1);
	message.Set(2,param2);	
	PostMessage(message);
      }

      void post(const std::string& command, const std::string& param1, const std::string& param2, const std::string& param3){
	pp::VarArray message;
	message.Set(0,command);
	message.Set(1,param1);
	message.Set(2,param2);	
	message.Set(3,param3);	
	PostMessage(message);
      }
    };

    class sesto_module : public pp::Module {
    public:
      sesto_module() : pp::Module() {}
      virtual ~sesto_module() {}
      virtual pp::Instance* CreateInstance(PP_Instance instance) {
	return new sesto_instance(instance);
      }

    };
  } //end themis
} //end pnacl


namespace pp {
    Module* CreateModule() {
      return new pnacl::themis::sesto_module();
    }
} // namespace pp
