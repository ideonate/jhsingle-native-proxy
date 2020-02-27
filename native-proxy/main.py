from tornado import web, ioloop
from tornado.log import app_log
from .proxyhandlers import _make_serverproxy_handler
import click

import logging
app_log.setLevel(logging.DEBUG)

port = 8500

url_prefix = '/user/dan/test'

proc_url = f'http://localhost:{port}/'


cmd_to_run = ['streamlit', 'hello',
              '--server.port', '{port}',
              '--server.headless', 'True',
              '--server.runOnSave', 'True',
              '--server.enableCORS', 'False']

#cmd_to_run = 'streamlit hello --server.port {port} --server.headless True --server.enableCORS False'


def make_app():

    proxy_handler = _make_serverproxy_handler('streamlit', cmd_to_run, {}, 10, False, port, None)

    return web.Application([
        (r"^/(.*)", proxy_handler, dict(state={})),
    ],
    debug=True)


@click.command()
@click.option('--port', default=8888, help='port for the launchpad server')
@click.argument('folder')
def run(port, folder):
    global cmd_to_run
    app = make_app()
    app.listen(port)
    print("Starting jhsingle-native-proxy server of folder {} on port {}".format(cmd_to_run, port))
    ioloop.IOLoop.current().start()


if __name__ == '__main__':
    run()
