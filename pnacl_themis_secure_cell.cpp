/*
 * Copyright (c) 2015 Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

    class secure_cell_instance : public pp::Instance {
    private:
      enum mode{SEAL, TOKEN_PROTECT, CONTEXT_IMPRINT, UNDEFINED};
    public:
      explicit secure_cell_instance(PP_Instance instance) : 
	pp::Instance(instance),
	mode_(UNDEFINED)
      {
	nacl_io_init_ppapi(instance, pp::Module::Get()->get_browser_interface());
	//	post("info", std::string("used themis version ")+themis_version());
      }
      virtual ~secure_cell_instance() {}

      virtual bool Init(uint32_t argc, const char* argn[], const char* argv[]) {
	mode_=SEAL;
	for(uint32_t i=0;i<argc;++i){
	  if(strcmp(argn[i], "mode")==0){
	    if(strcmp(argv[i], "seal")==0){ mode_=SEAL; break;}
	    else if(strcmp(argv[i], "token protect")==0){ mode_=TOKEN_PROTECT; break;} 
	    else if(strcmp(argv[i], "context imprint")==0){ mode_=CONTEXT_IMPRINT; break;} 
	  }
	}
	return true;
      }

    public:
      virtual void HandleMessage(const pp::Var& var_message) {
	if (!var_message.is_array()){
	  post("error", "incorrect message format");
	  return;
	}

	pp::VarArray params(var_message);  
	if(params.Get(0).AsString() == "encrypt"){
	  switch(mode_){
	  case SEAL:
	    if(params.GetLength()==4)
	      seal_encrypt(params.Get(1).AsString(), params.Get(2).AsString(), params.Get(3).AsString());
	    else
	      seal_encrypt(params.Get(1).AsString(), params.Get(2).AsString(), "");	      
	    break;
	  case CONTEXT_IMPRINT:
	    context_imprint_encrypt(params.Get(1).AsString(), params.Get(2).AsString(), params.Get(3).AsString());	    
	    break;
	  case TOKEN_PROTECT:
	    if(params.GetLength()==4)
	      token_protect_encrypt(params.Get(1).AsString(), params.Get(2).AsString(), params.Get(3).AsString());
	    else
	      token_protect_encrypt(params.Get(1).AsString(), params.Get(2).AsString(), "");	      
	    break;
	  default:
	    post("error", "themis secure cell mode not supported");
	  }
	}
	else if(params.Get(0).AsString() == "decrypt"){
	  switch(mode_){
	  case SEAL:
	    if(params.GetLength()==4)
	      seal_decrypt(params.Get(1).AsString(), params.Get(2).AsString(), params.Get(3).AsString());
	    else
	      seal_decrypt(params.Get(1).AsString(), params.Get(2).AsString(), "");	      
	    break;
	  case CONTEXT_IMPRINT:
	      context_imprint_decrypt(params.Get(1).AsString(), params.Get(2).AsString(), params.Get(3).AsString());	    
	    break;
	  case TOKEN_PROTECT:
	    if(params.GetLength()==5)
	      token_protect_decrypt(params.Get(1).AsString(), params.Get(2).AsString(), params.Get(3).AsString(), params.Get(4).AsString());
	    else
	      token_protect_decrypt(params.Get(1).AsString(), params.Get(2).AsString(), params.Get(3).AsString(), "");	      
	    break;
	  default:
	    post("error", "themis secure cell mode not supported");	    
	  }
	} else {
	  post("error", "operation not supported");
	}
      }

      private:
	  mode mode_;

      void seal_encrypt(const std::string& password, const std::string& message, const std::string& context){
	themispp::secure_cell_seal_t cell(VECTOR(password));
	std::string enc=pnacl::helpers::base64_encode(cell.encrypt(VECTOR(message), VECTOR(context)));
	post("encrypted", enc);
      }
	  
      void seal_decrypt(const std::string& password, const std::string& message, const std::string& context){
	themispp::secure_cell_seal_t cell(VECTOR(password));
	std::vector<uint8_t> dec=cell.decrypt(pnacl::helpers::base64_decode(message), VECTOR(context));
	post("decrypted", std::string((char*)(&dec[0]), dec.size()));	
      }

      void context_imprint_encrypt(const std::string& password, const std::string& message, const std::string& context){
	themispp::secure_cell_context_imprint_t cell(VECTOR(password));
	std::string enc=pnacl::helpers::base64_encode(cell.encrypt(VECTOR(message), VECTOR(context)));
	post("encrypted", enc);
      }
	  
      void context_imprint_decrypt(const std::string& password, const std::string& message, const std::string& context){
	themispp::secure_cell_context_imprint_t cell(VECTOR(password));
	std::vector<uint8_t> dec=cell.decrypt(pnacl::helpers::base64_decode(message), VECTOR(context));
	post("decrypted", std::string((char*)(&dec[0]), dec.size()));	
      }

      void token_protect_encrypt(const std::string& password, const std::string& message, const std::string& context){
	themispp::secure_cell_token_protect_t cell(VECTOR(password));
	std::string enc=pnacl::helpers::base64_encode(cell.encrypt(VECTOR(message), VECTOR(context)));
	std::string token=pnacl::helpers::base64_encode(cell.get_token());
	post("encrypted", enc, token);
      }
	  
      void token_protect_decrypt(const std::string& password, const std::string& message, const std::string& token, const std::string& context){
	themispp::secure_cell_token_protect_t cell(VECTOR(password));
	cell.set_token(pnacl::helpers::base64_decode(token));
	std::vector<uint8_t> dec=cell.decrypt(pnacl::helpers::base64_decode(message), VECTOR(context));
	post("decrypted", std::string((char*)(&dec[0]), dec.size()));	
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
    };

    class secure_cell_module : public pp::Module {
    public:
      secure_cell_module() : pp::Module() {}
      virtual ~secure_cell_module() {}
      virtual pp::Instance* CreateInstance(PP_Instance instance) {
	return new secure_cell_instance(instance);
      }

    private:
      virtual void encrypt(const std::string& message){}

      virtual void decrypt(const std::string& message){}
    };
  } //end themis
} //end pnacl


namespace pp {
    Module* CreateModule() {
      return new pnacl::themis::secure_cell_module();
    }
} // namespace pp
