from tornado.httpserver import HTTPServer
from tornado import ioloop
from tornado.web import Application, RequestHandler
from tornado.log import app_log
from .proxyhandlers import _make_serverproxy_handler, AddSlashHandler
import click
import re
import os
import logging
from jupyterhub.services.auth import HubOAuthCallbackHandler
from jupyterhub import __version__ as __jh_version__
from .util import url_path_join


def patch_default_headers():
    if hasattr(RequestHandler, '_orig_set_default_headers'):
        return
    RequestHandler._orig_set_default_headers = RequestHandler.set_default_headers

    def set_jupyterhub_header(self):
        self._orig_set_default_headers()
        self.set_header('X-JupyterHub-Version', __jh_version__)

    RequestHandler.set_default_headers = set_jupyterhub_header


def make_app(destport, prefix, command, authtype, request_timeout, debug):

    patch_default_headers()

    proxy_handler = _make_serverproxy_handler('mainprocess', command, {}, 10, False, destport, {})

    return Application([
        (
            r"^"+re.escape(prefix)+r"$",
            AddSlashHandler
        ),
        (
            url_path_join(prefix, 'oauth_callback'),
            HubOAuthCallbackHandler,
        ),
        (
            r"^"+re.escape(prefix)+r"/(.*)",
            proxy_handler,
            dict(state={}, authtype=authtype)
        )
    ],
    debug=debug,
    cookie_secret=os.urandom(32),
    user=os.environ.get('JUPYTERHUB_USER') or '',
    group=os.environ.get('JUPYTERHUB_GROUP') or '',
    anyone=os.environ.get('JUPYTERHUB_ANYONE') or '',
    base_url=prefix, # This is a confusing name, sorry
    request_timeout=request_timeout
    )


@click.command()
@click.option('--port', default=8888, help='port for the proxy server to listen on')
@click.option('--destport', default=8500, help='port that the webapp should end up running on; specify 0 to be assigned a random free port')
@click.option('--ip', default=None, help='Address to listen on')
@click.option('--debug/--no-debug', default=False, help='To display debug level logs')
@click.option('--authtype', type=click.Choice(['oauth', 'none'], case_sensitive=True), default='oauth')
@click.option('--request-timeout', default=300, type=click.INT, help='timeout of proxy http calls to subprocess in seconds (default 300)')
@click.argument('command', nargs=-1, required=True)
def run(port, destport, ip, debug, authtype, request_timeout, command):

    if debug:
        print('Setting debug')
        app_log.setLevel(logging.DEBUG)

    prefix = os.environ.get('JUPYTERHUB_SERVICE_PREFIX', '/')

    if len(prefix) > 0 and prefix[-1] == '/':
        prefix = prefix[:-1]

    app = make_app(destport, prefix, list(command), authtype, request_timeout, debug)

    http_server = HTTPServer(app)

    http_server.listen(port, ip)

    print("Starting jhsingle-native-proxy server on address {} port {}, proxying to port {}".format(ip, port, destport))
    print("URL Prefix: {}".format(prefix))
    print("Auth Type: {}".format(authtype))
    print("Command: {}".format(command))
    ioloop.IOLoop.current().start()


if __name__ == '__main__':
    run()
