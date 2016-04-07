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

#ifndef SESTO_PNACL_WEBSOCKET_API_HPP_
#define SESTO_PNACL_WEBSOCKET_API_HPP_


#include <string>
#include "ppapi/cpp/var.h"
#include "ppapi/cpp/var_array_buffer.h"
#include "ppapi/cpp/websocket.h"

namespace pnacl{
  
  class web_socket_receive_listener
  {
  public:
    virtual void on_receive(const std::string& data) = 0;
    virtual void on_connect() =0;
    virtual void on_error(int32_t code, const std::string& reason) = 0;
  };

  class websocket_api
  {
  public:
    websocket_api(pp::Instance* ppinstance, web_socket_receive_listener* recv_listener)
      : socket_(ppinstance),/*instance*/
	callback_factory_(this),
	receive_listener_(recv_listener){}

    websocket_api(pp::Instance* ppinstance, web_socket_receive_listener* recv_listener, const std::string& url)
      : socket_(ppinstance),
	receive_listener_(recv_listener){
      this->open(url);
    }

    virtual ~websocket_api() {
	socket_.Close(PP_WEBSOCKETSTATUSCODE_NORMAL_CLOSURE, "bye...", pp::BlockUntilComplete());
    }
    
    void open(const std::string& url){
      int32_t res=socket_.Connect(url, NULL, 0, callback_factory_.NewCallback(&websocket_api::open_handler));
      if(res!=PP_OK_COMPLETIONPENDING)
	receive_listener_->on_error(res, "socket_.Connect");
    }
    
    void send(const std::string& data) {
      socket_.SendMessage(data);
    }

    void receive(){
      int32_t res=socket_.ReceiveMessage(&received_data_, callback_factory_.NewCallback(&websocket_api::receive_handler));
      if(res!=PP_OK_COMPLETIONPENDING)
	receive_listener_->on_error(res, "socket_.ReceiveMessage");
    }

  private:

    void open_handler(int32_t result){
      if(result!=PP_OK){
	receive_listener_->on_error(result, "socket_.open_handler");
	return;
      }
      receive_listener_->on_connect();
      receive();
    }
    
    void receive_handler(int32_t result){
      if(result!=PP_OK || !received_data_.is_string()){
	receive_listener_->on_error(result, "socket_.receive_handler");
      }
      else{
	receive_listener_->on_receive(received_data_.AsString());
	receive();
      }
    }

    pp::Var received_data_;
    websocket_api(const websocket_api&);
    websocket_api& operator=(const websocket_api&);
    
    web_socket_receive_listener* const receive_listener_;
    pp::WebSocket socket_;
    pp::CompletionCallbackFactory<websocket_api> callback_factory_;
  };

} /*namespace pnacl*/
#endif /* SESTO_PNACL_WEBSOCKET_API_HPP_ */
