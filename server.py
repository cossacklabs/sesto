import argparse
import logging
import random
import string
import asyncio
import base64

import jinja2
from aiohttp import web
import aiohttp_jinja2

@asyncio.coroutine
def posthandler(request):
    name = request.match_info.get('name', 'AAA')
    data = yield from request.read()
    f = open("data/"+name+".dat", "wb");
    f.write(data);
    f.close();
    print("post", data)
    return web.Response()

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


@asyncio.coroutine
@aiohttp_jinja2.template('index.html')
def index(request):
    scheme = request.scheme
    url = '{scheme}://{host}'.format(
        scheme=scheme, host=request.host)
    return {'url': url,
            'static_resolver': app.router['static'].url}


@asyncio.coroutine
def init(port, loop):
    app = web.Application(loop=loop)
    app.router.add_route('GET', '/', index)
    app.router.add_route('POST', '/data/{name}.dat', posthandler)    
    app.router.add_static('/s/', 'static/', name='static')
    app.router.add_static('/data/', 'data/')


    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('templates/'))

    handler = app.make_handler()
    srv = yield from loop.create_server(handler, '0.0.0.0', port)
    logger.info("Server started at http://0.0.0.0:{}".format(port))
    return handler, app, srv


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Run server')

    parser.add_argument('-p', '--port', type=int, help='Port number',
                        default=8888)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Output verbosity')
    args = parser.parse_args()
    port = args.port

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    logger = logging.getLogger(__name__)

    loop = asyncio.get_event_loop()
    handler, app, srv = loop.run_until_complete(init(port, loop))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(finish(app, srv, handler))
