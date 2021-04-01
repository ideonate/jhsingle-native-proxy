from tornado import web, httpclient, ioloop, httputil
import os, json, re
import aiohttp, urllib
import socket
import subprocess
from simpervisor import SupervisedProcess
from datetime import datetime
from asyncio import Lock, ensure_future
from .util import url_path_join
from .websocket import WebSocketHandlerMixin, pingable_ws_connect
from tornado.log import app_log, gen_log
from jupyterhub.services.auth import HubOAuthenticated
from urllib.parse import urlunparse, urlparse, quote
from typing import (
    Any
)

class AddSlashHandler(web.RequestHandler):
    """Add trailing slash to URLs that need them."""
    #@web.authenticated
    def get(self, *args):
        src = urlparse(self.request.uri)
        dest = src._replace(path=src.path + '/')
        self.redirect(urlunparse(dest))


class ProxyHandler(HubOAuthenticated, WebSocketHandlerMixin):
    """
    A tornado request handler that proxies HTTP and websockets from
    a given host/port combination. This class is not meant to be
    used directly as a means of overriding CORS. This presents significant
    security risks, and could allow arbitrary remote code access. Instead, it is
    meant to be subclassed and used for proxying URLs from trusted sources.
    Subclasses should implement open, http_get, post, put, delete, head, patch,
    and options.
    """
    def __init__(self, *args, **kwargs):
        self.proxy_base = ''
        self.absolute_url = kwargs.pop('absolute_url', False)
        self.host_whitelist = kwargs.pop('host_whitelist', ['localhost', '127.0.0.1'])
        self.subprotocols = None
        self.forward_user_info = kwargs.pop('forward_user_info', False)
        self.query_user_info = kwargs.pop('query_user_info', False)
        super().__init__(*args, **kwargs)

    @property
    def log(self):
        """use tornado's logger"""
        return app_log

    # Support all the methods that tornado does by default except for GET which
    # is passed to WebSocketHandlerMixin and then to WebSocketHandler.

    async def open(self, port, proxied_path):
        raise NotImplementedError('Subclasses of ProxyHandler should implement open')

    async def http_get(self, host, port, proxy_path=''):
        '''Our non-websocket GET.'''
        raise NotImplementedError('Subclasses of ProxyHandler should implement http_get')

    def post(self, host, port, proxy_path=''):
        raise NotImplementedError('Subclasses of ProxyHandler should implement this post')

    def put(self, port, proxy_path=''):
        raise NotImplementedError('Subclasses of ProxyHandler should implement this put')

    def delete(self, host, port, proxy_path=''):
        raise NotImplementedError('Subclasses of ProxyHandler should implement delete')

    def head(self, host, port, proxy_path=''):
        raise NotImplementedError('Subclasses of ProxyHandler should implement head')

    def patch(self, host, port, proxy_path=''):
        raise NotImplementedError('Subclasses of ProxyHandler should implement patch')

    def options(self, host, port, proxy_path=''):
        raise NotImplementedError('Subclasses of ProxyHandler should implement options')

    def on_message(self, message):
        """
        Called when we receive a message from our client.
        We proxy it to the backend.
        """
        self._record_activity()
        if hasattr(self, 'ws'):
            self.ws.write_message(message, binary=isinstance(message, bytes))

    def on_ping(self, data):
        """
        Called when the client pings our websocket connection.
        We proxy it to the backend.
        """
        self.log.debug('jupyter_server_proxy: on_ping: {}'.format(data))
        self._record_activity()
        if hasattr(self, 'ws'):
            self.ws.protocol.write_ping(data)

    def on_pong(self, data):
        """
        Called when we receive a ping back.
        """
        self.log.debug('jupyter_server_proxy: on_pong: {}'.format(data))

    def on_close(self):
        """
        Called when the client closes our websocket connection.
        We close our connection to the backend too.
        """
        if hasattr(self, 'ws'):
            self.ws.close()

    def _record_activity(self):
        """Record proxied activity as API activity
        avoids proxied traffic being ignored by the notebook's
        internal idle-shutdown mechanism
        """
        self.settings['api_last_activity'] = datetime.utcnow()

    def _get_context_path(self, port):
        """
        Some applications need to know where they are being proxied from.
        This is either:
        - {base_url}/proxy/{port}
        - {base_url}/proxy/absolute/{port}
        - {base_url}/{proxy_base}
        """
        if self.proxy_base:
            return url_path_join(self.base_url, self.proxy_base)
        if self.absolute_url:
            return url_path_join(self.base_url, 'proxy', 'absolute', str(port))
        else:
            return url_path_join(self.base_url, 'proxy', str(port))

    def get_client_uri(self, protocol, host, port, proxied_path, get_args=None):
        context_path = self._get_context_path(port)
        if self.absolute_url:
            client_path = url_path_join(context_path, proxied_path)
        else:
            client_path = proxied_path

        client_path = quote(client_path, safe=":/?#[]@!$&'()*+,;=-._~")

        client_uri = '{protocol}://{host}:{port}{path}'.format(
            protocol=protocol,
            host=host,
            port=port,
            path=client_path
        )
        if get_args:
            client_uri += '?' + get_args

        return client_uri

    def _build_proxy_request(self, host, port, proxied_path, body, **extra_opts):

        headers, query_args = self._filter_headers_and_query(self.proxy_request_headers(), self.proxy_query_arguments())

        client_uri = self.get_client_uri('http', host, port, proxied_path, urllib.parse.urlencode(query_args, doseq=True))
        # Some applications check X-Forwarded-Context and X-ProxyContextPath
        # headers to see if and where they are being proxied from.
        if not self.absolute_url:
            context_path = self._get_context_path(port)
            headers['X-Forwarded-Context'] = context_path
            headers['X-ProxyContextPath'] = context_path

        req = httpclient.HTTPRequest(
            client_uri, method=self.request.method, body=body,
            headers=headers, **self.proxy_request_options(), **extra_opts)
        return req

    def _filter_headers_and_query(self, headers, query_args):
        """
        Depending on config, add headers or query params containing JH user data
        Return a headers dict and query dict
        """

        # Forward JupyterHub user info if it exists
        X_CDSDASHBOARDS_JH_USER = 'X-CDSDASHBOARDS-JH-USER'

        if X_CDSDASHBOARDS_JH_USER in headers:
            # This must be a spoof, remove it
            del headers[X_CDSDASHBOARDS_JH_USER]

        # Include JH user in the query string
        Q_CDSDASHBOARDS_JH_USER = 'CDSDASHBOARDS_JH_USER'

        if Q_CDSDASHBOARDS_JH_USER in query_args:
            # This must be a spoof, remove it
            del query_args[Q_CDSDASHBOARDS_JH_USER]

        if (self.forward_user_info or self.query_user_info) and hasattr(self, '_hub_auth_user_cache'):
            # Take internal _hub_auth_user_cache property of jupyterhub.services.auth.HubAuthenticated
            # Only include headline info in case, e.g. secret auth info is stored on the user object

            self.log.info(self._hub_auth_user_cache)

            user_info_str = json.dumps(dict(
                    [(k, self._hub_auth_user_cache.get(k, None)) for k in ('kind', 'name', 'admin', 'groups')]
                ))

            if self.forward_user_info:
                headers[X_CDSDASHBOARDS_JH_USER] = user_info_str

            if self.query_user_info:
                query_args[Q_CDSDASHBOARDS_JH_USER] = user_info_str

        return headers, query_args

    def _check_host_whitelist(self, host):
        if callable(self.host_whitelist):
            return self.host_whitelist(self, host)
        else:
            return host in self.host_whitelist

    #@web.authenticated - handled in subclass
    async def proxy(self, host, port, proxied_path):
        '''
        This serverextension handles:
            {base_url}/proxy/{port([0-9]+)}/{proxied_path}
            {base_url}/proxy/absolute/{port([0-9]+)}/{proxied_path}
            {base_url}/{proxy_base}/{proxied_path}
        '''

        if not self._check_host_whitelist(host):
            self.set_status(403)
            self.write("Host '{host}' is not whitelisted. "
                       "See https://jupyter-server-proxy.readthedocs.io/en/latest/arbitrary-ports-hosts.html for info.".format(host=host))
            return

        if 'Proxy-Connection' in self.request.headers:
            del self.request.headers['Proxy-Connection']

        self._record_activity()

        if self.request.headers.get("Upgrade", "").lower() == 'websocket':
            # We wanna websocket!
            # jupyterhub/jupyter-server-proxy@36b3214
            self.log.info("we wanna websocket, but we don't define WebSocketProxyHandler")
            self.set_status(500)

        body = self.request.body
        if not body:
            if self.request.method == 'POST':
                body = b''
            else:
                body = None

        client = httpclient.AsyncHTTPClient()

        # Set up handlers so we can progressively flush result

        headers_raw = []

        def dump_headers(headers_raw):
            for line in headers_raw:
                r = re.match('^([a-zA-Z0-9\-_]+)\s*\:\s*([^\r\n]+)[\r\n]*$', line)
                if r:
                    k,v = r.groups([1,2])
                    if k not in ('Content-Length', 'Transfer-Encoding',
                                  'Content-Encoding', 'Connection'):
                        # some header appear multiple times, eg 'Set-Cookie'
                        self.set_header(k,v)
                else:
                    r = re.match('^HTTP[^\s]* ([0-9]+)', line)
                    if r:
                        status_code = r.group(1)
                        self.set_status(int(status_code))
            headers_raw.clear()

        # clear tornado default header
        self._headers = httputil.HTTPHeaders()

        def header_callback(line):
            headers_raw.append(line)

        def streaming_callback(chunk):
            # Do this here, not in header_callback so we can be sure headers are out of the way first
            dump_headers(headers_raw) # array will be empty if this was already called before
            self.write(chunk)
            self.flush()

        # Now make the request

        req = self._build_proxy_request(host, port, proxied_path, body, 
                    streaming_callback=streaming_callback, 
                    header_callback=header_callback)

        try:
            response = await client.fetch(req, raise_error=False)
        except httpclient.HTTPError as err:
            if err.code == 599:
                self._record_activity()
                self.set_status(599)
                self.write(str(err))
                return
            else:
                raise

        # record activity at start and end of requests
        self._record_activity()

        # For all non http errors...
        if response.error and type(response.error) is not httpclient.HTTPError:
            self.set_status(500)
            self.write(str(response.error))
        else:
            self.set_status(response.code, response.reason) # Should already have been set

            dump_headers(headers_raw) # Should already have been emptied

            if response.body: # Likewise, should already be chunked out and flushed
                self.write(response.body)

    async def ws_get(self, *args: Any, **kwargs: Any) -> None:
        """
        A version of WebSocketHandler.get that also opens the underlying process' websocket so that
        any GET headers can also be passed back to the client.
        """
        self.open_args = args
        self.open_kwargs = kwargs

        # Upgrade header should be present and should be equal to WebSocket
        if self.request.headers.get("Upgrade", "").lower() != "websocket":
            self.set_status(400)
            log_msg = 'Can "Upgrade" only to "WebSocket".'
            self.finish(log_msg)
            gen_log.debug(log_msg)
            return

        # Connection header should be upgrade.
        # Some proxy servers/load balancers
        # might mess with it.
        headers = self.request.headers
        connection = map(
            lambda s: s.strip().lower(), headers.get("Connection", "").split(",")
        )
        if "upgrade" not in connection:
            self.set_status(400)
            log_msg = '"Connection" must be "Upgrade".'
            self.finish(log_msg)
            gen_log.debug(log_msg)
            return

        # Handle WebSocket Origin naming convention differences
        # The difference between version 8 and 13 is that in 8 the
        # client sends a "Sec-Websocket-Origin" header and in 13 it's
        # simply "Origin".
        if "Origin" in self.request.headers:
            origin = self.request.headers.get("Origin")
        else:
            origin = self.request.headers.get("Sec-Websocket-Origin", None)

        # If there was an origin header, check to make sure it matches
        # according to check_origin. When the origin is None, we assume it
        # did not come from a browser and that it can be passed on.
        if origin is not None and not self.check_origin(origin):
            self.set_status(403)
            log_msg = "Cross origin websockets not allowed"
            self.finish(log_msg)
            gen_log.debug(log_msg)
            return

        # Now open connection to underlying web process from ourself - BESPOKE
        path = ''
        if len(args) > 0:
            path = args[0]
        elif 'path' in kwargs:
            path = kwargs['path']

        await self._ws_open_proxy('localhost', self.port, path)

        if hasattr(self, 'handshake_headers'):
            # Any headers need passing on?
            for header, v in self.handshake_headers.get_all():
                if header in ('Set-Cookie', 'Vary'):
                    # some header appear multiple times, eg 'Set-Cookie'
                    self.add_header(header, v)

        # Now establish websocket between client and ourself - BACK TO ORIGINAL CODE NOW
        self.ws_connection = self.get_websocket_protocol()
        if self.ws_connection:
            await self.ws_connection.accept_connection(self)
        else:
            self.set_status(426, "Upgrade Required")
            self.set_header("Sec-WebSocket-Version", "7, 8, 13")
            if hasattr(self, 'ws'):
                self.ws.close()

    async def proxy_open(self, host, port, proxied_path=''):
        """
        Called when a client opens a websocket connection.
        """
        pass

    async def _ws_open_proxy(self, host, port, proxied_path=''):
        """
        Open the websocket of the underlying process.
        """

        if not self._check_host_whitelist(host):
            self.set_status(403)
            self.log.info("Host '{host}' is not whitelisted. "
                          "See https://jupyter-server-proxy.readthedocs.io/en/latest/arbitrary-ports-hosts.html for info.".format(host=host))
            self.close()
            return

        if not proxied_path.startswith('/'):
            proxied_path = '/' + proxied_path

        headers, query_args = self._filter_headers_and_query(self.proxy_request_headers(), self.proxy_query_arguments())

        client_uri = self.get_client_uri('ws', host, port, proxied_path, urllib.parse.urlencode(query_args, doseq=True))

        current_loop = ioloop.IOLoop.current()
        ws_connected = current_loop.asyncio_loop.create_future()

        def headers_cb(headers):
            self.handshake_headers = headers

        def message_cb(message):
            """
            Callback when the backend sends messages to us
            We just pass it back to the frontend
            """
            # Websockets support both string (utf-8) and binary data, so let's
            # make sure we signal that appropriately when proxying
            self._record_activity()
            if message is None:
                self.close()
            else:
                self.write_message(message, binary=isinstance(message, bytes))

        def ping_cb(data):
            """
            Callback when the backend sends pings to us.
            We just pass it back to the frontend.
            """
            self._record_activity()
            self.ping(data)

        self.log.info('Trying to establish websocket connection to {}'.format(client_uri))
        self._record_activity()
        request = httpclient.HTTPRequest(url=client_uri, headers=headers)
        self.ws = await pingable_ws_connect(request=request,
                                            on_message_callback=message_cb, on_ping_callback=ping_cb,
                                            on_get_headers_callback=headers_cb,
                                            subprotocols=self.subprotocols)
        self._record_activity()
        self.log.info('Websocket connection established to {}'.format(client_uri))

        # We really need the underlying process websocket AND the one between client and proxy
        # to be opened at the same time to avoid messages being proxied before one end is open.
        # Return the future and hopefully find a way to synchronise...

    def proxy_request_headers(self):
        '''A dictionary of headers to be used when constructing
        a tornado.httpclient.HTTPRequest instance for the proxy request.'''
        return self.request.headers.copy()

    def proxy_query_arguments(self):
        '''A dictionary of query args to be used when constructing
        a tornado.httpclient.HTTPRequest instance for the proxy request.'''
        return self.request.query_arguments.copy()

    def proxy_request_options(self):
        '''A dictionary of options to be used when constructing
        a tornado.httpclient.HTTPRequest instance for the proxy request.'''
        return dict(follow_redirects=False, request_timeout=self.settings['request_timeout'])

    def check_xsrf_cookie(self):
        '''
        http://www.tornadoweb.org/en/stable/guide/security.html
        Defer to proxied apps.
        '''
        pass

    def select_subprotocol(self, subprotocols):
        '''Select a single Sec-WebSocket-Protocol during handshake.'''
        self.subprotocols = subprotocols
        if isinstance(subprotocols, list) and subprotocols:
            self.log.info('Client sent subprotocols: {}'.format(subprotocols))
            return subprotocols[0]
        return super().select_subprotocol(subprotocols)


class LocalProxyHandler(ProxyHandler):
    """
    A tornado request handler that proxies HTTP and websockets
    from a port on the local system. Same as the above ProxyHandler,
    but specific to 'localhost'.
    """
    async def http_get(self, port, proxied_path):
        return await self.proxy(port, proxied_path)

    async def open(self, port, proxied_path):
        return await self.proxy_open('localhost', port, proxied_path)

    def post(self, port, proxied_path):
        return self.proxy(port, proxied_path)

    def put(self, port, proxied_path):
        return self.proxy(port, proxied_path)

    def delete(self, port, proxied_path):
        return self.proxy(port, proxied_path)

    def head(self, port, proxied_path):
        return self.proxy(port, proxied_path)

    def patch(self, port, proxied_path):
        return self.proxy(port, proxied_path)

    def options(self, port, proxied_path):
        return self.proxy(port, proxied_path)

    def proxy(self, port, proxied_path):
        return super().proxy('localhost', port, proxied_path)


class RemoteProxyHandler(ProxyHandler):
    """
    A tornado request handler that proxies HTTP and websockets
    from a port on a specified remote system.
    """

    async def http_get(self, host, port, proxied_path):
        return await self.proxy(host, port, proxied_path)

    def post(self, host, port, proxied_path):
        return self.proxy(host, port, proxied_path)

    def put(self, host, port, proxied_path):
        return self.proxy(host, port, proxied_path)

    def delete(self, host, port, proxied_path):
        return self.proxy(host, port, proxied_path)

    def head(self, host, port, proxied_path):
        return self.proxy(host, port, proxied_path)

    def patch(self, host, port, proxied_path):
        return self.proxy(host, port, proxied_path)

    def options(self, host, port, proxied_path):
        return self.proxy(host, port, proxied_path)

    async def open(self, host, port, proxied_path):
        return await self.proxy_open(host, port, proxied_path)

    def proxy(self, host, port, proxied_path):
        return super().proxy(host, port, proxied_path)


class SuperviseAndProxyHandler(LocalProxyHandler):
    '''Manage a given process and requests to it '''

    error_template = """<!DOCTYPE html>
<html>
    <head>
        <title>Error report from ContainDS Dashboards</title>
    </head>
    <body>

<h2>Error report from ContainDS Dashboards</h2>

    <h3>Command Running:</h2>
    <pre>
{cmd}
    </pre>

    <h3>Error output:</h3>
    <pre>
{stderr}
    </pre>

    <h3>Standard output:</h3>
    <pre>
{stdout}
    </pre>
    
    </body>
</html>"""

    gitpulling_template = """<!DOCTYPE html>
<html>
    <head>
        <title>Status page from ContainDS Dashboards</title>
        <meta http-equiv="Refresh" content="2">
    </head>
    <body>

    <h3>Pulling content from git</h2>

    <p>Please wait.... refreshing page in 2 seconds</p>
    
    </body>
</html>"""

    def __init__(self, *args, **kwargs):
        self.requested_port = 0
        self.mappath = {}

        self.stderr_str = None
        self.stdout_str = None

        self.origin_host = None

        self.ready_check_path = '/'

        super().__init__(*args, **kwargs)

    def initialize(self, state, authtype, *args, **kwargs):
        self.state = state
        if 'proc_lock' not in state:
            state['proc_lock'] = Lock()

        self.authtype = authtype

        super().initialize(*args, **kwargs)

    name = 'process'

    @property
    def port(self):
        """
        Allocate either the requested port or a random empty port for use by
        application
        """
        if 'port' not in self.state:
            sock = socket.socket()
            sock.bind(('', self.requested_port))
            self.state['port'] = sock.getsockname()[1]
            sock.close()
        return self.state['port']

    def get_cwd(self):
        """Get the current working directory for our process
        Override in subclass to launch the process in a directory
        other than the current.
        """
        return os.getcwd()

    def get_env(self):
        '''Set up extra environment variables for process. Typically
           overridden in subclasses.'''
        return {}

    def get_timeout(self):
        """
        Return timeout (in s) to wait before giving up on process readiness
        """
        return 5

    async def _http_ready_func(self, p):
        url = 'http://localhost:{}{}'.format(self.port, self.ready_check_path)
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url) as resp:
                    # We only care if we get back *any* response, not just 200
                    # If there's an error response, that can be shown directly to the user
                    self.log.debug('Got code {} back from {}'.format(resp.status, url))
                    return True
            except aiohttp.ClientConnectionError:
                self.log.debug('Connection to {} refused'.format(url))
                return False

    async def ensure_process(self):
        """
        Start the process
        """
        # We don't want multiple requests trying to start the process at the same time
        # FIXME: Make sure this times out properly?
        # Invariant here should be: when lock isn't being held, either 'proc' is in state &
        # running, or not.
        async with self.state['proc_lock']:
            if 'proc' not in self.state:
                # FIXME: Prevent races here
                # FIXME: Handle graceful exits of spawned processes here
                cmd = self.get_cmd()
                server_env = os.environ.copy()

                # Set up extra environment variables for process
                server_env.update(self.get_env())

                timeout = self.get_timeout()

                self.log.info(cmd)

                proc = SupervisedProcess(self.name, *cmd, env=server_env, ready_func=self._http_ready_func, ready_timeout=timeout, log=self.log,
                                            stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                self.state['proc'] = proc

                try:
                    await proc.start()

                    is_ready = await proc.ready()

                    if not is_ready:

                        self.stderr_str = None
                        self.stdout_str = None

                        stderr, stdout = await proc.proc.communicate()

                        if stderr:
                            self.stderr_str = str(stderr.decode("utf-8"))
                            self.log.info('Process {} failed with stderr: {}'.format(self.name, self.stderr_str))

                        if stdout:
                            self.stdout_str = str(stdout.decode("utf-8"))
                            self.log.info('Process {} failed with stdout: {}'.format(self.name, self.stdout_str))

                        await proc.kill()

                        del self.state['proc']
                        return False

                    else:
                        # Make sure we empty the buffers periodically

                        async def pipe_output(proc, pipename, log):
                            while True:
                                if proc.proc:
                                    stream = getattr(proc.proc, pipename, None)
                                    if stream:
                                        try:
                                            line = await stream.readline()
                                            if line:
                                                if pipename == 'stdout':
                                                    log.info(line)
                                                else:
                                                    log.error(line)
                                            else:
                                                break
                                        except ValueError:
                                            log.info('Truncated log line from subprocess')

                        ensure_future(pipe_output(proc, 'stderr', self.log))
                        ensure_future(pipe_output(proc, 'stdout', self.log))

                except:
                    # Make sure we remove proc from state in any error condition
                    del self.state['proc']
                    raise
            return True

    @web.authenticated
    async def oauth_proxy(self, port, path):
        return await self.core_proxy(port, path)

    async def core_proxy(self, port, path):

        if self.origin_host is None:
            # Get origin from this request
            self.store_origin_host()

        if not path.startswith('/'):
            path = '/' + path

        if self.mappath:
            if callable(self.mappath):
                raise Exception("Not implemented: path = call_with_asked_args(self.mappath, {'path': path})")
            else:
                path = self.mappath.get(path, path)

        if self.gitwrapper:
            if not self.gitwrapper.finished:
                self.set_status(200)
                return self.write(self.gitpulling_template)
            elif self.gitwrapper.error:
                from tornado.escape import xhtml_escape
                html = self.error_template.format(
                    cmd=xhtml_escape(" ".join(self.get_cmd())),
                    stderr=xhtml_escape("\n".join(self.gitwrapper.logs)),
                    stdout=''
                )
                self.set_status(500)
                return self.write(html)

        if not await self.ensure_process():
            from tornado.escape import xhtml_escape
            html = self.error_template.format(
                cmd=xhtml_escape(" ".join(self.get_cmd())),
                stderr=xhtml_escape(self.stderr_str or 'None'),
                stdout=xhtml_escape(self.stdout_str or 'None')
            )
            self.set_status(500)
            return self.write(html)

        return await super().proxy(self.port, path)

    async def proxy(self, port, path):
        if self.authtype == 'oauth':
            return await self.oauth_proxy(port, path)
        else:
            return await self.core_proxy(port, path)

    async def http_get(self, path):
        self.log.info('SuperviseAndProxyHandler http_get {} {}'.format(self.port, path))
        return await self.proxy(self.port, path)

    async def open(self, path):
        if self.origin_host is None:
            # Get origin from this request
            self.store_origin_host()
        
        if self.gitwrapper and not self.gitwrapper.finished:
            raise web.HTTPError(500, 'Git checkout is not finished')

        if await self.ensure_process():
            return await super().open(self.port, path)
        raise web.HTTPError(500, 'could not start {} in time'.format(self.name))

    def post(self, path):
        return self.proxy(self.port, path)

    def put(self, path):
        return self.proxy(self.port, path)

    def delete(self, path):
        return self.proxy(self.port, path)

    def head(self, path):
        return self.proxy(self.port, path)

    def patch(self, path):
        return self.proxy(self.port, path)

    def options(self, path):
        return self.proxy(self.port, path)

    def store_origin_host(self):
        self.log.debug('Storing origin host {}'.format(self.request.host))
        self.origin_host = self.request.host


def _make_serverproxy_handler(name, command, environment, timeout, absolute_url, port, ready_check_path, gitwrapper, mappath):
    """
    Create a SuperviseAndProxyHandler subclass with given parameters
    """
    # FIXME: Set 'name' properly
    class _Proxy(SuperviseAndProxyHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.name = name
            self.proxy_base = name
            self.absolute_url = absolute_url
            self.requested_port = port
            self.mappath = mappath
            self.ready_check_path = ready_check_path
            self.gitwrapper = gitwrapper

        @property
        def process_args(self):
            return {
                'port': self.port,
                'base_url': self.base_url,
                'presentation_path': self.presentation_path,
                'presentation_basename': self.presentation_basename,
                'presentation_dirname': self.presentation_dirname,
                'origin_host': self.origin_host,
                '-': '-',
                '--': '--'
            }

        @property
        def base_url(self):
            return self.settings.get('base_url', '/')

        @property
        def presentation_path(self):
            return self.settings.get('presentation_path', '.')

        @property
        def presentation_basename(self):
            return self.settings.get('presentation_basename', '')

        @property
        def presentation_dirname(self):
            return self.settings.get('presentation_dirname', '.')

        @property
        def hub_users(self):
            return {self.settings['user']}

        @property
        def hub_groups(self):
            if self.settings['group']:
                return {self.settings['group']}
            return set()

        @property
        def allow_all(self):
            if 'anyone' in self.settings:
                return self.settings['anyone'] == '1'
            return super().allow_all

        def _render_template(self, value):
            args = self.process_args
            if type(value) is str:
                return value.format(**args)
            elif type(value) is list:
                return [self._render_template(v) for v in value]
            elif type(value) is dict:
                return {
                    self._render_template(k): self._render_template(v)
                    for k, v in value.items()
                }
            else:
                raise ValueError('Value of unrecognized type {}'.format(type(value)))

        def get_cmd(self):
            if callable(command):
                raise Exception("Not implemented: self._render_template(call_with_asked_args(command, self.process_args))")
            else:
                return self._render_template(command)

        def get_env(self):
            if callable(environment):
                raise Exception("return self._render_template(call_with_asked_args(environment, self.process_args))")
            else:
                return self._render_template(environment)

        def get_timeout(self):
            return timeout

    return _Proxy

