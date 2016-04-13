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
#include "json/json.h"
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
#define UI_INT_PARAM(array, i) array.Get(i).AsInt()

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
	    //	    postInfo("connected");
	  });
	return true;
      }

    private:      
      std::shared_ptr<pnacl::secure_websocket_api> socket_;
      std::map<std::string, std::function<void(const pp::VarArray&)> > ui_handlers_={
	{"login", [this](const pp::VarArray& params){
	    username_=UI_STRING_PARAM(params, 1);
	    password_=UI_STRING_PARAM(params, 2);
	    comparator_ = secure_comparator_create();
	    secure_comparator_append_secret(comparator_, password_.c_str(), password_.length());
	    uint8_t comparator_data[4000];
	    size_t comparator_length=4000;
	    if(secure_comparator_begin_compare(comparator_, comparator_data, &comparator_length)!=THEMIS_SCOMPARE_SEND_OUTPUT_TO_PEER){
	      post("login_failed", "");
	      return;
	    }
	    socket_->send(std::string("AUTH1 ")+username_+" "+helpers::base64_encode(comparator_data, comparator_length));	
	  }},
	{"get", [this](const pp::VarArray& params){
	    int id=std::stoi( UI_STRING_PARAM(params, 1));
	    socket_->send(std::string("GET ")+UI_STRING_PARAM(params, 1)+" "+passmap_[id]+" "+username_);
	  }},
	{"update", [this](const pp::VarArray& params){
	    int id=std::stoi( UI_STRING_PARAM(params, 1));
	    std::string data=UI_STRING_PARAM(params, 2);
	    Json::Value root;
	    Json::Reader reader;
	    if(!reader.parse(data, root)){
	      postError("get invalide unswer from server");
	      return;
	    }
	    Json::Value context = root["context"];
	    if (!context.isArray()) {
	      postError("get invalide unswer from server");
	      return;
	    }
	    for (int32_t i=context.size()-1; i >=0; --i){
	      root["context"][i]["password"]=passmap_[root["context"][i]["id"].asInt()];
	    }
	    Json::FastWriter writer;
	    std::string jjstr=writer.write(root);
	    socket_->send(std::string("UPDATE ")+UI_STRING_PARAM(params, 1)+" "+passmap_[id]+" "+username_+" "+helpers::base64_encode(STR_2_VEC(jjstr)));
	  }},
	{"add_folder", [this](const pp::VarArray& params){
	    int id=std::stoi( UI_STRING_PARAM(params, 1));
	    socket_->send(std::string("NEW_FOLDER ")+UI_STRING_PARAM(params, 1)+" "+passmap_[id]+" "+username_);
	  }},
	{"add_file", [this](const pp::VarArray& params){
	    int id=std::stoi( UI_STRING_PARAM(params, 1));
	    socket_->send(std::string("NEW_FILE ")+UI_STRING_PARAM(params, 1)+" "+passmap_[id]+" "+username_);
	  }},
	{"enc", [this](const pp::VarArray& params){
	    try{
	      themispp::secure_cell_seal_t sc(STR_2_VEC(password_));
	      std::string data=UI_STRING_PARAM(params, 1);
	      post("enc_done", helpers::base64_encode(sc.encrypt(STR_2_VEC(data), STR_2_VEC(username_))));
	    }catch(themispp::exception_t& e){
	      postError(e.what());
	    }
	  }},
	{"dec", [this](const pp::VarArray& params){
	    try{
	      themispp::secure_cell_seal_t sc(STR_2_VEC(password_));
	      std::vector<uint8_t> datavec=sc.decrypt(helpers::base64_decode(UI_STRING_PARAM(params, 1)), STR_2_VEC(username_));
	      post("dec_done", std::string((char*)(&datavec[0]), datavec.size()));
	    }catch(themispp::exception_t& e){
	      postError(e.what());
	    }
	  }},
	{"del_file", [this](const pp::VarArray& params){
	    int id=std::stoi( UI_STRING_PARAM(params, 1));
	    socket_->send(std::string("DEL_FILE ")+UI_STRING_PARAM(params, 1)+" "+UI_STRING_PARAM(params, 2)+" "+passmap_[id]+" "+username_);
	  }},
	{"del_folder", [this](const pp::VarArray& params){
	    int id=std::stoi( UI_STRING_PARAM(params, 1));
	    socket_->send(std::string("DEL_FOLDER ")+UI_STRING_PARAM(params, 1)+" "+UI_STRING_PARAM(params, 2)+" "+passmap_[id]+" "+username_);
	  }}
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
	//	postInfo(command);
	try{
	  socket_handlers_.at(command)(data);
	}catch(std::out_of_range& e){
	  postError("received undefined command from server ", command);
	}
      }

    private:
      std::string username_;
      std::string password_;
      std::map<std::string, std::function<void(const std::string&)> > socket_handlers_={
	{"INVALID_LOGIN", [this](const std::string& data){
	    post("login_failed", "");
	  }},
	{"AUTH1",  [this](const std::string& data){
	    std::istringstream s(data);
	    std::string command, comparator_data;
	    s>>command>>comparator_data;
	    uint8_t comparator_data_buf[4000];
	    size_t comparator_length=4000;
	    std::vector<uint8_t> c_dat=helpers::base64_decode(comparator_data);
	    if(secure_comparator_proceed_compare(comparator_, &c_dat[0], c_dat.size(), comparator_data_buf, &comparator_length)!=THEMIS_SCOMPARE_SEND_OUTPUT_TO_PEER){
	      post("login_failed", "secure_comparator_proceed_compare 1 failed");
	      return;
	    }
	    socket_->send(std::string("AUTH2 ")+username_+" "+helpers::base64_encode(comparator_data_buf, comparator_length));		    
	  }},
	{"AUTH2",  [this](const std::string& data){
	    std::istringstream s(data);
	    std::string command, comparator_data;
	    int root_id;
	    s>>command>>comparator_data>>root_id;
	    uint8_t comparator_data_buf[4000];
	    size_t comparator_length=4000;
	    std::vector<uint8_t> c_dat=helpers::base64_decode(comparator_data);
	    if(secure_comparator_proceed_compare(comparator_, &c_dat[0], c_dat.size(), comparator_data_buf, &comparator_length)!=THEMIS_SUCCESS || secure_comparator_get_result(comparator_)!=THEMIS_SCOMPARE_MATCH){
	      post("login_failed", "secure_comparator_proceed_compare 2 failed");
	      return;
	    }
	    secure_comparator_destroy(comparator_);
	    comparator_=NULL;
	    passmap_.insert(std::pair<int, std::string>(root_id, password_));
	    post("root_id", root_id);
	  }},
	{"GET", [this](const std::string& data){
	    std::string command, id, d;
	    std::istringstream s(data);
	    s>>command>>id>>d;
	    Json::Value root;
	    Json::Reader reader;
	    std::vector<uint8_t> ss=helpers::base64_decode(d);
	    if(!reader.parse(std::string((char*)(&ss[0]), ss.size()), root)){
	      postError("get invalide unswer from server");
	      return;
	    }
	    Json::Value context = root["context"];
	    if (!context.isArray()) {
	      postError("get invalide unswer from server");
	      return;
	    }
	    res_="{\"name\":\""+root["name"].asString()+"\", \"desc\":\""+root["desc"].asString()+"\",\"id\":"+id+",\"type\":\""+root["type"].asString()+"\", \"context\":[";
	    if(root["type"].asString()=="folder"){
	      std::string post_value="{\"context_info\":[";
	      for (int32_t i=context.size()-1; i >=0; --i){
		post_value+="{\"id\":"+context[i]["id"].asString()+", \"password\":\""+context[i]["password"].asString()+"\"}";
		post_value+=(i==0)?"":",";
		passmap_.insert(std::pair<int, std::string>(context[i]["id"].asInt(), context[i]["password"].asString()));
	      }
	      post_value+="]}";
	      socket_->send(std::string("GET_CONTEXT_INFO ")+username_+" "+helpers::base64_encode(STR_2_VEC(post_value)));
	    }else if(root["type"].asString()=="file"){
	      post("get",std::string((char*)(&ss[0]), ss.size())); 
	    }
	  }},
	{"GET_CONTEXT", [this](const std::string& data){
	    std::string command, d;
	    std::istringstream s(data);
	    s>>command>>d;
	    Json::Value root;
	    Json::Reader reader;
	    std::vector<uint8_t> ss=helpers::base64_decode(d);
	    if(!reader.parse(std::string((char*)(&ss[0]), ss.size()), root)){
	      postError("get invalide unswer from server");
	      return;
	    }
	    if (!root["context"].isArray()) {
	      postError("get invalide unswer from server");
	      return;
	    }
	    for (int32_t i=root["context"].size()-1; i >=0; --i){
	      res_+="{\"id\":"+root["context"][i]["id"].asString()+", \"name\":\""+root["context"][i]["name"].asString()+"\", \"desc\":\""+root["context"][i]["desc"].asString()+"\"}";
	      res_+=(i==0)?"":",";
	    }
	    res_+="]}";
	    post("get", res_);
	  }},	
	{"NEW_FOLDER", [this](const std::string& data){
	    std::string command;
	    int new_id;
	    std::istringstream s(data);
	    s>>command>>new_id;
	    post("new_folder", new_id);
	  }},
	{"NEW_FILE", [this](const std::string& data){
	    std::string command;
	    int new_id;
	    std::istringstream s(data);
	    s>>command>>new_id;
	    post("new_file", new_id);
	  }}
      };
     

      void post(const std::string& command, const std::string& param1){
	pp::VarArray message;
	message.Set(0,command);
	message.Set(1,param1);
	PostMessage(message);
      }

      void post(const std::string& command, int param1){
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
      std::map<int, std::string> passmap_;
      std::string res_;
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
