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

import jinja2
from aiohttp import web
import aiohttp_jinja2

from pythemis import ssession
from pythemis import skeygen


class Transport(ssession.mem_transport):  # necessary callback
    def get_pub_key_by_id(self, user_id):
        return base64.b64decode(user_id.decode("utf8"))


class COMMAND:
    NEW_ROOM = 'ROOM.CREATE'
    ROOM_CREATED = 'ROOM.CREATED'
    OPEN_ROOM = 'ROOM.OPEN'
    OPENED_ROOM = 'ROOM.OPENED'
    ERROR_ROOM = 'ROOM.NOT_EXIST'
    INVITE = 'ROOM.INVITE.VERIFICATION_REQUEST'
    INVITE_RESPONSE = 'ROOM.INVITE.VERIFICATION_RESPONSE'
    INVALID_INVITE = 'ROOM.INVITE.DECLINED'
    MESSAGE = 'ROOM.MESSAGE'
    MESSAGE_KEY_ROTATE = 'ROOM.MESSAGE.KEY.ROTATE'
    MESSAGE_ERROR = 'ROOM.MESSAGE.ERROR'
    PUBLIC_KEY = 'PUBKEY'
    ERROR = 'ERROR'


id_symbols = string.ascii_letters + string.digits
def generate_id():
    return ''.join([random.choice(id_symbols) for _ in range(32)])


@asyncio.coroutine
def wshandler(request):
    logger.info('new connection')
    ws_response = web.WebSocketResponse()
    yield from ws_response.prepare(request)
    pub_key = ""
    session = ssession.ssession(b'server', server_private_key, Transport())
    while True:
        message = yield from ws_response.receive()
        if message.tp == web.MsgType.text:
            msg = session.unwrap(base64.b64decode(message.data))
            if msg.is_control:
               ws_response.send_str(base64.b64encode(msg).decode("UTF-8"));
            else:
                msg = msg.decode("UTF-8")
                logger.info('request:' + msg)
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
