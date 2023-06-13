# jhsingle-native-proxy

Wrap an arbitrary webapp so it can be used in place of jupyter-singleuser in a JupyterHub setting.

Within JupyterHub this allows similar operation to [jupyter-server-proxy](https://github.com/jupyterhub/jupyter-server-proxy) except it also removes the Jupyter notebook itself, so is working directly with the arbitrary web service.

OAuth authentication is enforced based on JUPYTERHUB_* environment variables.

This project is used in [ContainDS Dashboards](https://github.com/ideonate/cdsdashboards), which is a user-friendly 
way to launch Jupyter notebooks as shareable dashboards inside JupyterHub. Also works with Streamlit and other 
visualization frameworks.

## Install and Run

Install using pip.

```
pip install jhsingle-native-proxy
```

The process to start is specified on the command line, for example a [streamlit](https://streamlit.io/) web app:

```
jhsingle-native-proxy streamlit hello
```

By default the jhsingle-native-proxy server will listen on port 8888, forwarding to port 8500.

But you will normally need to tell jhsingle-native-proxy which port the end process will run in, and maybe tell the 
end process which port you want it to use (which you can do with the substitution variable {port}).

Note the use of -- to signal the end of command line options to jhsingle-native-proxy. Then the third party command line 
itself can contain options starting with dashes. An alternative is to use the substitution {--}

```
jhsingle-native-proxy -- streamlit hello --server.port {port} --server.headless True --server.enableCORS False
```

To run jhsingle-native-proxy itself listening on a different port use:

```
jhsingle-native-proxy --port 8000 streamlit hello
```

To run jhsingle-native-proxy on port 8000, and the end process on 8505:

```
jhsingle-native-proxy --port 8000 --destport 8505 -- streamlit hello --server.port {port} --server.headless True --server.enableCORS False
```

Use the JUPYTERHUB_SERVICE_PREFIX env var to specify the first part of the URL to listen to (and then strip before forwarding). E.g. 
JUPYTERHUB_SERVICE_PREFIX=/user/dan will mean requests on http://localhost:8888/user/dan/something will forward to http://localhost:8500/something

You can also specify --ip 0.0.0.0 for the address to listen on.

Below we use the substitution {--} for the command to run, allowing us to specify --ip to jhsingle-native-proxy instead of the 
command being run.  

```
jhsingle-native-proxy --port 8000 --destport 8505 streamlit hello {--}server.port {port} {--}server.headless True {--}server.enableCORS False --ip 0.0.0.0 
```

Similarly, use e.g. {-}m to represent -m in the final command.

### Voila example:

Running voila at the subfolder URL e.g. /user/dan/:

```
python -m jhsingle_native_proxy.main --destport 0 voila ./Presentation.ipynb {--}port={port} {--}no-browser {--}Voila.server_url=/ {--}Voila.base_url={base_url}/ {--}debug
```

'destport 0' above instructs jhsingle-native-proxy to choose a random free port on which to run the sub-process (Voila), and of course substitutes that as {port} in the Voila command line so it knows which port to listen on. destport 0 is the default anyway.

Or specify presentation_path as a substitution instead of hard-coding, which is sometimes easier in your wrapper code:

```
python -m jhsingle_native_proxy.main --destport 0 voila {presentation_path} {--}port={port} {--}no-browser {--}Voila.server_url=/ {--}Voila.base_url={base_url}/ {--}debug --presentation_path=./Presentation.ipynb
```

In addition, if presentation_path is provided, two further substitution variables are available: presentation_dirname and 
presentation_basename. These are computed using Python's os.path.dirname and os.path.basename functions on presentation_path.

## Authentication

The above examples all assume OAuth will be enforced, as per the JUPYTERHUB_* env vars.

Alternatives can be specified via the authtype flag:

Same as default:

```
jhsingle-native-proxy --authtype=oauth streamlit hello
```

No auth required at all:

```
jhsingle-native-proxy --authtype=none streamlit hello
```

### Specifying Authorized Users

The env vars JUPYTERHUB_USER and JUPYTERHUB_GROUP can be used, as typical for any JupyterHub single server, to specify user/groups of 
JupyterHub that should be allowed access via OAuth. There is an additional bespoke env var called JUPYTERHUB_ANYONE which can be set to 1 
to allow any authenticated user access. (i.e. anyone who has an account on the JupyterHub)

### Extra Arguments

--request-timeout=300 specifies the timeout in seconds that it waits for the underlying subprocess to return when proxying normal requests. Default is 300.

{origin_host} in the command argument will be replaced with the first 'host' seen in any request to the jhsingle-native-proxy server.

--last-activity-interval=300 specifies how often in seconds to update the hub to provide the last time any traffic passed through 
the proxy (default 300). Specify 0 to never update.
--force-keep-alive or --no-force-keep-alive: the former (default) ensures that the hub is notified of recent activity even if there wasn't any - only works if last-activity-interval is not 0.

--ready-check-path (default /) to change the URL on the subprocess used to poll with an HTTP request to check for readiness.

--repo - use git to check out a repo before running the sub process

--repofolder - the path of a folder (to be created if necessary) to contain the git repo contents

--forward-user-info - forward to the underlying process an X-CDSDASHBOARDS-JH-USER HTTP header containing JupyterHub user info as JSON-encoded string

--query-user-info - add a GET query param named CDSDASHBOARDS_JH_USER when calling underlying process containing JupyterHub user info as JSON-encoded string

--ready-timeout - integer timeout for period of checking the process is running at startup (default 10). Increase if your process is not able to return anything at --ready-check-path until a longer time after it first starts up. Be aware that the process must (once ready) return its HTTP response within 1 second. Note this argument is different from --request-timeout which applies to individual HTTP proxy calls during normal operation (not just at startup).

--websocket-max-message-size - message size in bytes allowed by websocket connections made to the underlying process (default is to rely on the tornado library defaults).

 --progressive - flush buffer from underlying service whenever chunks appear (this is useful to see results from Voila sooner)

## Changelog

### v0.8.1 released 13 Jun 2023

- Pin simpervisor version to avoid conflict with version 1.0. Thanks to [dangercrow](https://github.com/dangercrow).

### v0.8.0 released 8 Nov 2021

- Change to work with JupyterHub 2 (detects port from JUPYTERHUB_SERVICE_URL env var if no --port set)

### v0.7.6 released 20 Apr 2021

- New command-line options --ready-timeout and --websocket-max-message-size

### v0.7.3 released 9 Apr 2021

- New command-line option --progressive to flush buffer from underlying service whenever chunks appear (this is useful to see results from Voila sooner)
- oauth_callback URL now accessible when running with JUPYTERHUB_BASE_URL of /

### v0.7.1 released 22 Feb 2021

- New command-line option --query-user-info to add a CDSDASHBOARDS_JH_USER GET query param to the http
  request to the underlying service.

### v0.7.0 released 12 Feb 2021

- New command-line option --forward-user-info to add a X-CDSDASHBOARDS-JH-USER header to the http request to the underlying service. 
  The header value is a JSON-encoded dict containing kind, name, admin, groups fields from the logged-in JupyterHub user if available.

### v0.6.1 released 6 Jan 2021

- Require simpervisor >= 0.4 to ensure Python 3.9 compat.

### v0.6.0 released 20 Nov 2020

- Displays INFO level logs by default, which includes output of the subprocess (turn off with --no-logs) [Issue #7](https://github.com/ideonate/jhsingle-native-proxy/issues/7)
- Logs from subprocess written out at different level depending on source (stderr -> error, stdout -> info)
- Long subprocess logs are handled and truncated instead of throwing an error [cdsdashboards issue #44](https://github.com/ideonate/cdsdashboards/issues/44)
- Different handling of branch checkout when using git repo source, when switching brances compared to what was checked out before

### v0.5.6 released 18 Sep 2020

- Always convert presentation_path to an absolute path (based on CWD) before passing to the sub-command.

### v0.5.5 released 10 Sep 2020

- Also accept URLs at the URL-encoded equivalent of the prefix and redirect to the regular version of the URL.

### v0.5.4 released 3 Sep 2020

- Change working folder to repofolder when specified

### v0.5.2 released 17 Aug 2020

- Require tornado 6.0.4+

### v0.5.1 released 17 Aug 2020

- Fix to ensure both websockets are opened at the same time, to avoid writing to a websocket that's not yet open.

### v0.5.0 released 17 Aug 2020

- Open up underlying process' websocket before connecting our own with the client. This ensures any other GET headers can be passed back to the client. (Fix for Streamlit XSRF problems.)

### v0.4.3 released 30 July 2020

- Added --allow-root option (currently ignored) to avoid errors if this flag is usually passed to jupyter-singleuser

### v0.4.2 released 23 July 2020

- Switch to a Conda env before running subprocess by specifying --conda-env option

### v0.4.1 released 20 July 2020

- fix because subprocess sometimes blocked if too much output generated

### v0.4.0 released 15 July 2020

- repo and repofolder optional arguments added

### v0.3.2 released 25 June 2020

### v0.3.1 released 18 June 2020

- Defaults presentation_path to empty str ('') if not supplied, avoiding error

### v0.3.0 released 17 June 2020

- presentation_path can be provided as a command line argument to become a substitution variable.
- presentation_basename and presentation_dirname are also available when presentation_path is supplied.

### v0.2.0 released 11 June 2020

- Better websocket handling (subprotocols)
- {origin_host} variable added

### v0.1.3 released 1 June 2020

- request-timeout added to the proxy call, and the default set to 300 (20 seconds was the httpclient's default previously)

### v0.1.2 released 29 May 2020

- Now allows single-dash placeholder, e.g. {-}m translates to -m in the final subprocess command.

## Development install

```
git clone https://github.com/ideonate/jhsingle-native-proxy.git
cd jhsingle-native-proxy

pip install -e .
```

To run directly in python: `python -m jhsingle_native_proxy.main <rest of command line>`

Testing git puller:

python -m jhsingle_native_proxy.main --authtype=none --destport=0 --port=8888 voila ./sincosfolder/Presentation.ipynb {--}port={port} {--}no-browser {--}Voila.server_url=/ {--}Voila.base_url={base_url}/ --repo=https://github.com/danlester/binder-sincos --repofolder=sincosfolder
