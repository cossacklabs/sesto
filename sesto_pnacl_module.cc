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
#include <sstream>
#include "ppapi/cpp/instance.h"
#include "ppapi/cpp/module.h"
#include "ppapi/cpp/var.h"
#include "ppapi/cpp/var_array.h"
#include "nacl_io/nacl_io.h"
#include "ppapi/cpp/var.h"
#include "ppapi/cpp/var_array.h"
#include "ppapi/utility/completion_callback_factory.h"
#include "ppapi/utility/threading/simple_thread.h"

#define SECURE_COMPARATOR_ENABLED


#include "secure_websocket_api.hpp"

#include <themispp/secure_cell.hpp>
#include <themispp/secure_keygen.hpp>
#include <themis/themis.h>

#include "helpers/base64.hpp"

#define UI_STRING_PARAM(array, i) array.Get(i).AsString()
#define UI_INT_PARAM(array, i) array.Get(i).AsInteger()

#define VECTOR(str) std::vector<uint8_t>(str.c_str(), str.c_str()+str.length())
#define STR_2_VEC(str) std::vector<uint8_t>((str).c_str(), (str).c_str()+(str).length())
#define B64_2_VEC(str) helpers::base64_decode(str)


namespace pnacl {
  namespace themis {

    class sesto_instance : public pp::Instance {
    private:
      enum mode{SEAL, TOKEN_PROTECT, CONTEXT_IMPRINT, UNDEFINED};
    public:
      explicit sesto_instance(PP_Instance instance) :
	pp::Instance(instance){
	nacl_io_init_ppapi(instance, pp::Module::Get()->get_browser_interface());
	comparator_ = secure_comparator_create();
      }
      virtual ~sesto_instance() {
	secure_comparator_destroy(comparator_);
      }

      virtual bool Init(uint32_t argc, const char* argn[], const char* argv[]) {
	std::string server_id="";
	std::string server_pub="";
	std::string url="";
	for(uint32_t i=0;i<argc;++i){
	  if(strcmp(argn[i], "url")==0){
	    url=argv[i];
	  }else if(strcmp(argn[i], "server_pub")==0){
	    server_pub=argv[i];
	  }else if(strcmp(argn[i], "server_id")==0){
	    server_id=argv[i];
	  }
	}
	if(url=="" || server_id=="" || server_pub=="")
	  return false;
	socket_=std::shared_ptr<pnacl::secure_websocket_api>(new pnacl::secure_websocket_api(STR_2_VEC(server_id), B64_2_VEC(server_pub), this, std::bind(&sesto_instance::on_receive, this, std::placeholders::_1), [this](const std::string& a){
	      postError("socket_error" ,a);
	    }));
	themispp::secure_key_pair_generator_t<themispp::EC> gen;
	socket_->open(url, gen.get_pub(), gen.get_priv(), [this](){
	    postInfo("connected");
	  });
	return true;
      }

    private:
      void on_login_msg(const pp::VarArray& params){
	username_=UI_STRING_PARAM(params, 1);
	password_=UI_STRING_PARAM(params, 2);
	secure_comparator_append_secret(comparator_, password_.c_str(), password_.length());
	uint8_t comparator_data[4000];
	size_t comparator_length=4000;
	secure_comparator_begin_compare(comparator_, comparator_data, &comparator_length);
	socket_->send(std::string("AUTH1 ")+username_+" "+helpers::base64_encode(comparator_data, comparator_length));	
      }
      
      std::shared_ptr<pnacl::secure_websocket_api> socket_;
      std::map<std::string, std::function<void(const pp::VarArray&)> > ui_handlers_={
	{"login", std::bind(&sesto_instance::on_login_msg, this, std::placeholders::_1)}
      };

    public:
      virtual void HandleMessage(const pp::Var& var_message) {
	if (!var_message.is_array()){
	  post("error", "incorrect message format");
	  return;
	}
	pp::VarArray params(var_message);
	try{
	  ui_handlers_.at(UI_STRING_PARAM(params, 0))(params);
	}catch(std::out_of_range& e){
	  postError("received undefined command from UI ", UI_STRING_PARAM(params, 0));
	}
      }
      
    public:
      void on_receive(const std::string& data){
	std::string command;
	std::istringstream st(data);
	st>>command;
	postInfo(command);
	try{
	  socket_handlers_.at(command)(data);
	}catch(std::out_of_range& e){
	  postError("received undefined command from server ", command);
	}
      }

      void on_get_data(const std::string& data){

      }

      void on_invalid_username(){
	socket_->send(std::string("NEWUSER ")+username_+" "+password_);
      }
    private:
      std::string username_;
      std::string password_;
      std::map<std::string, std::function<void(const std::string&)> > socket_handlers_={
	{"GET", std::bind(&sesto_instance::on_get_data, this, std::placeholders::_1)},
	{"INVALID_USERNAME", std::bind(&sesto_instance::on_invalid_username, this)}
      };
     

      void post(const std::string& command, const std::string& param1){
	pp::VarArray message;
	message.Set(0,command);
	message.Set(1,param1);
	PostMessage(message);
      }

      void postError(const std::string& msg){
	post("Error", msg);
      }

      void postInfo(const std::string& msg){
	post("Info", msg);
      }

      void post(const std::string& command, const std::string& param1, const std::string& param2){
	pp::VarArray message;
	message.Set(0,command);
	message.Set(1,param1);
	message.Set(2,param2);	
	PostMessage(message);
      }

      void postError(const std::string& msg, const std::string& msg1){
	post("Error", msg, msg1);
      }

      void post(const std::string& command, const std::string& param1, const std::string& param2, const std::string& param3){
	pp::VarArray message;
	message.Set(0,command);
	message.Set(1,param1);
	message.Set(2,param2);	
	message.Set(3,param3);	
	PostMessage(message);
      }

      secure_comparator_t* comparator_;
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
