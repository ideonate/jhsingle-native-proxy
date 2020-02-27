from tornado import web, ioloop
from tornado.log import app_log
from .proxyhandlers import _make_serverproxy_handler
import click
import re
import logging
app_log.setLevel(logging.DEBUG)


def make_app(port, prefix, command):

    proxy_handler = _make_serverproxy_handler('mainprocess', command, {}, 10, False, port, {})

    return web.Application([
        (r"^"+re.escape(prefix)+r"(.*)", proxy_handler, dict(state={})),
    ],
    debug=True)


@click.command()
@click.option('--serverport', default=8888, help='port for the proxy server to listen on')
@click.option('--port', default=8500, help='port that the webapp should end up running on')
@click.option('--prefix', default='/', help='URL prefix to strip before forwarding')
@click.argument('command', nargs=-1, required=True)
def run(serverport, port, prefix, command):
    app = make_app(port, prefix, list(command))
    app.listen(serverport)
    print("Starting jhsingle-native-proxy server on port {}, proxying to port {}".format(serverport, port))
    print("URL Prefix: {}".format(prefix))
    print("Command: {}".format(command))
    ioloop.IOLoop.current().start()


if __name__ == '__main__':
    run()
