#!/usr/bin/python3.5
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

import argparse
import logging
import random
import string
import asyncio
import base64
import json

import jinja2
from aiohttp import web
import aiohttp_jinja2

from pythemis import ssession
from pythemis import skeygen
from pythemis import scomparator
from pythemis import scell

import sqlite3
dbconn = sqlite3.connect('sesto.db');
try:
    c = dbconn.cursor()
    # Create table
    c.execute('''CREATE TABLE users (user text, password text, root_id blob)''');
    c.execute('''CREATE TABLE data (id INTEGER PRIMARY KEY AUTOINCREMENT, data blob)''');
    dbconn.commit()
except sqlite3.OperationalError:
    a=1;
    
def get_user_password(username):
    c = dbconn.cursor();
    t = (username,)
    c.execute('SELECT password FROM users WHERE user=?', t);
    return c.fetchone();

def get_user_root_id(username):
    c = dbconn.cursor();
    t = (username,)
    c.execute('SELECT root_id FROM users WHERE user=?', t);
    return c.fetchone()[0];

def get_data_by_id(id):
    c = dbconn.cursor();
    t = (id,)
    c.execute('SELECT data FROM data WHERE id=?', t);
    return c.fetchone()
    
def update_data_by_id(id, data):
    c = dbconn.cursor();
    t = (sqlite3.Binary(data), id,)
    c.execute('UPDATE data SET data=? WHERE id=?', t);
    dbconn.commit()

def new_folder(context):
    c = dbconn.cursor();
    passwd=generate_pass();
    enc=scell.scell_seal(passwd.encode("UTF-8"));
    c.execute("INSERT INTO data (data) VALUES (?)", [sqlite3.Binary(enc.encrypt(base64.b64encode(b"{ \"type\":\"folder\",\"name\": \"Folder\", \"desc\":\"folder\",\"context\": []}"), context.encode('utf8'))), ] );
    dbconn.commit()
    return c.lastrowid, passwd;

def new_file(context):
    c = dbconn.cursor();
    passwd=generate_pass();
    enc=scell.scell_seal(passwd.encode("UTF-8"));
    c.execute("INSERT INTO data (data) VALUES (?)", [sqlite3.Binary(enc.encrypt(base64.b64encode(b"{ \"type\":\"file\",\"name\": \"File\", \"desc\":\"file\",\"context\": []}"), context.encode('utf8'))), ] );
    dbconn.commit()
    return c.lastrowid, passwd;

def del_by_id(id):
    c = dbconn.cursor();
    t = (id,)
    c.execute("DELETE FROM data WHERE id=?", t);
    dbconn.commit();



id_symbols = string.ascii_letters + string.digits
def generate_pass():
    return ''.join([random.choice(id_symbols) for _ in range(32)])

class Transport(ssession.mem_transport):  # necessary callback
    def get_pub_key_by_id(self, user_id):
        return user_id;


id_symbols = string.ascii_letters + string.digits
def generate_id():
    return ''.join([random.choice(id_symbols) for _ in range(32)])


def on_auth1_message(msg, ws_response, session, comparator):
    p=get_user_password(msg[1]);
    if p is None:
        ws_response.send_str(base64.b64encode(session.wrap(b"INVALID_LOGIN")).decode("UTF-8"));
    else:
        comparator = scomparator.scomparator(p[0].encode("UTF-8"));
        try:
            data = base64.b64encode(comparator.proceed_compare(base64.b64decode(msg[2]))).decode("UTF-8");
            ws_response.send_str(base64.b64encode(session.wrap(("AUTH1 "+data).encode("UTF-8"))).decode("UTF-8"));
            return comparator;
        except Exception:
            ws_response.send_str(base64.b64encode(session.wrap(b"INVALID_LOGIN")).decode("UTF-8"));
            
def on_auth2_message(msg, ws_response, session, comparator):
    try:
        data = base64.b64encode(comparator.proceed_compare(base64.b64decode(msg[2]))).decode("UTF-8");
        sc = scell.scell_seal(get_user_password(msg[1])[0].encode("UTF-8"))
        rr = int.from_bytes((sc.decrypt(get_user_root_id(msg[1]),msg[1].encode("UTF-8"))), byteorder='big');
        if comparator.result() != scomparator.SCOMPARATOR_CODES.NOT_MATCH:
            ws_response.send_str(base64.b64encode(session.wrap(("AUTH2 "+data+" "+str(rr)).encode("UTF-8"))).decode("UTF-8"));
            return True;
    except Exception:
        a=1
    ws_response.send_str(base64.b64encode(session.wrap(b"INVALID_LOGIN")).decode("UTF-8"));
    return False

def on_get_message(msg, ws_response, session, is_authorized):
    if not is_authorized:
        logger.info("not_authorized")
        return False
    d=get_data_by_id(msg[1])
    if d is None:
        logger.info("not found", msg[1])
        return False;
    try:
        sc = scell.scell_seal(msg[2].encode("UTF-8"))
        d=sc.decrypt(d[0], msg[3].encode("UTF-8"));
        ws_response.send_str(base64.b64encode(session.wrap("GET {} {}".format(msg[1], d.decode("UTF-8")).encode("UTF-8"))).decode("UTF-8"));
        return True
    except Exception:
        logger.info("decription_error")
    return False
    
def on_update_message(msg, ws_response, session, is_authorized):
    if not is_authorized:
        logger.info("not_authorized")
        return False
    try:
        sc = scell.scell_seal(msg[2].encode("UTF-8"))
        d=sc.encrypt(msg[4].encode("UTF-8"), msg[3].encode("UTF-8"));
        update_data_by_id(msg[1], d)
        return True
    except Exception:
        logger.info("decription_error")
    return False

def on_new_folder(msg, ws_response, session, is_authorized):
    if not is_authorized:
        logger.info("not_authorized")
        return False
    d=get_data_by_id(msg[1])    
    if d is None:
        logger.info("not found", msg[1])
        return False;
    try:
        sc = scell.scell_seal(msg[2].encode("UTF-8"))
        d=base64.b64decode(sc.decrypt(d[0], msg[3].encode("UTF-8")));
        jj=json.loads(d.decode("UTF-8"));
        new_id, new_pass=new_folder(msg[3]);
        jj["context"].append({"type":"folder", "name":"New Folder","desc":"folder", "id":new_id, "password":new_pass})
        update_data_by_id(msg[1], sc.encrypt(base64.b64encode(json.dumps(jj).encode("UTF-8")), msg[3].encode("UTF-8")))
        ws_response.send_str(base64.b64encode(session.wrap("NEW_FOLDER {}".format(new_id).encode("UTF-8"))).decode("UTF-8"));
        return True;
    except Exception:
        logger.info("decription_error")
    return False

def on_get_context_info(msg, ws_response, session, is_authorized):
    if not is_authorized:
        logger.info("not_authorized")
        return False
    jj=json.loads(base64.b64decode(msg[2]).decode("UTF-8"));
    res="{\"context\":["
    for ctx in jj["context_info"]:
        sc=scell.scell_seal(ctx["password"].encode("UTF-8"));
        d=json.loads(base64.b64decode(sc.decrypt(get_data_by_id(ctx["id"])[0],msg[1].encode("UTF-8"))).decode("UTF-8"));
        res+="{\"name\":\""+d["name"]+"\",\"desc\":\""+d["desc"]+"\",\"id\":"+str(ctx["id"])+"}"
        if ctx != jj["context_info"][-1]:
            res+=",";
    res+="]}";
    ws_response.send_str(base64.b64encode(session.wrap("GET_CONTEXT {}".format(base64.b64encode(res.encode("UTF-8")).decode("UTF-8")).encode("UTF-8"))).decode("UTF-8"));
    return True;

def on_new_file(msg, ws_response, session, is_authorized):
    if not is_authorized:
        logger.info("not_authorized")
        return False
    d=get_data_by_id(msg[1])    
    if d is None:
        logger.info("not found", msg[1])
        return False;
    try:
        sc = scell.scell_seal(msg[2].encode("UTF-8"))
        d=base64.b64decode(sc.decrypt(d[0], msg[3].encode("UTF-8")));
        jj=json.loads(d.decode("UTF-8"));
        new_id, new_pass=new_file(msg[3]);
        jj["context"].append({"type":"file", "name":"New File","desc":"new file", "id":new_id, "password":new_pass})
        update_data_by_id(msg[1], sc.encrypt(base64.b64encode(json.dumps(jj).encode("UTF-8")), msg[3].encode("UTF-8")))
        ws_response.send_str(base64.b64encode(session.wrap("NEW_FILE {}".format(new_id).encode("UTF-8"))).decode("UTF-8"));
        return True;
    except Exception:
        logger.info("decription_error")
    return False

def on_del(msg, ws_response, session, is_authorized):
    if not is_authorized:
        logger.info("not_authorized")
        return False
    d=get_data_by_id(msg[1])    
    if d is None:
        logger.info("not found", msg[1])
        return False;
    try:
        sc = scell.scell_seal(msg[3].encode("UTF-8"))
        d=base64.b64decode(sc.decrypt(d[0], msg[4].encode("UTF-8")));
        jj=json.loads(d.decode("UTF-8"));
        for a in jj["context"]:
            if a["id"] == int(msg[2]):
                jj["context"].remove(a);
        update_data_by_id(msg[1], sc.encrypt(base64.b64encode(json.dumps(jj).encode("UTF-8")), msg[4].encode("UTF-8")))
        del_by_id(int(msg[2]));
        return True;
    except Exception:
      logger.info("decription_error")
    return False

        
handlers_map = {"AUTH1": on_auth1_message,
                "AUTH2": on_auth2_message,
                "GET": on_get_message,
                "UPDATE": on_update_message,
                "NEW_FOLDER": on_new_folder,
                "GET_CONTEXT_INFO": on_get_context_info,
                "NEW_FILE": on_new_file,
                "DEL_FILE": on_del,
                "DEL_FOLDER": on_del}
            
@asyncio.coroutine
def wshandler(request):
    logger.info('new connection')
    ws_response = web.WebSocketResponse()
    yield from ws_response.prepare(request)
    pub_key = ""
    session = ssession.ssession(b'server', server_private_key, Transport())
    authorized = False
    while True:
        message = yield from ws_response.receive()
        if message.tp == web.MsgType.text:
            msg = session.unwrap(base64.b64decode(message.data))
            if msg.is_control:
               ws_response.send_str(base64.b64encode(msg).decode("UTF-8"));
            else:
#                logger.info('request:' + msg.decode("UTF-8"))
                msg = msg.decode("UTF-8").split();
                authorized = handlers_map[msg[0]](msg, ws_response, session, authorized)
        elif message.tp == web.MsgType.closed or message.tp == web.MsgType.close:
            if pub_key in online:
                del online[pub_key]
                logger.info('connection closed')
            break
        else:
            ws_response.send_str('{} malformed request'.format(COMMAND.ERROR))
            if 'msg' in locals():
                logger.info('error:{}'.format(msg))
                if pub_key in online:
                    del online[pub_key]
                    logger.info('closed')
    return ws_response


@asyncio.coroutine
@aiohttp_jinja2.template('index.html')
def index(request):
    scheme = 'wss' if request.scheme == 'https' else 'ws'
    url = '{scheme}://{host}{url}'.format(
        scheme=scheme, host=request.host,
        url=request.app.router['websocket'].url()
    )
    return {'url': url,
            'server_id': 'server',
            'server_public_key': base64.b64encode(server_public_key).decode("UTF-8"),
            'static_resolver': app.router['static'].url}


@asyncio.coroutine
def init(port, loop):
    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', index)
    app.router.add_route('GET', '/ws', wshandler, name='websocket')
    app.router.add_static('/s/', 'static/', name='static')


    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('templates/'))

    handler = app.make_handler()
    srv = yield from loop.create_server(handler, '0.0.0.0', port)
    logger.info("Server started at http://0.0.0.0:{}".format(port))
    return handler, app, srv


@asyncio.coroutine
def finish(app, srv, handler):
    global online
    for sockets in online.values():
        for socket in sockets:
            socket.close()

    yield from asyncio.sleep(0.1)
    srv.close()
    yield from handler.finish_connections()
    yield from srv.wait_closed()



if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Run server')

    parser.add_argument('-p', '--port', type=int, help='Port number',
                        default=5103)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Output verbosity')
    args = parser.parse_args()
    port = args.port

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    logger = logging.getLogger(__name__)

    key_pair=skeygen.themis_gen_key_pair('EC')
    server_private_key=key_pair.export_private_key()
    server_public_key=key_pair.export_public_key()
    
    rooms = {}
    pub_keys = {}
    online = {}
    history = {}
    rooms_history = {}

    loop = asyncio.get_event_loop()
    handler, app, srv = loop.run_until_complete(init(port, loop))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(finish(app, srv, handler))
