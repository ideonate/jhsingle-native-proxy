from tornado import web, ioloop
from tornado.log import app_log
from .proxyhandlers import _make_serverproxy_handler
import click

import logging
app_log.setLevel(logging.DEBUG)


def make_app(port, command):

    proxy_handler = _make_serverproxy_handler('mainprocess', command, {}, 10, False, port, None)

    return web.Application([
        (r"^/(.*)", proxy_handler, dict(state={})),
    ],
    debug=True)


@click.command()
@click.option('--serverport', default=8888, help='port for the proxy server to listen on')
@click.option('--port', default=8500, help='port that the webapp should end up running on')
@click.argument('command', nargs=-1, required=True)
def run(serverport, port, command):
    app = make_app(port, list(command))
    app.listen(serverport)
    print("Starting jhsingle-native-proxy server on port {}, proxying to port {}".format(serverport, port))
    print("Command: {}".format(command))
    ioloop.IOLoop.current().start()


if __name__ == '__main__':
    run()
