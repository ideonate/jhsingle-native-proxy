# jhsingle-native-proxy

Wrap an arbitrary webapp so it can be used in place of jupyter-singleuser in a JupyterHub setting.

Within JupyterHub this allows similar operation to [jupyter-server-proxy](https://github.com/jupyterhub/jupyter-server-proxy) except it also removes the Jupyter notebook itself, so is working directly with the arbitrary web service.

OAuth authentication is enforced based on JUPYTERHUB_* environment variables.

This is a very basic alpha version.

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

### Voila example:

Running voila at the subfolder URL e.g. /user/dan/:

```
python -m jhsingle_native_proxy.main --destport 8505 voila ./Presentation.ipynb {--}port={port} {--}no-browser {--}Voila.server_url=/ {--}Voila.base_url={base_url}/ {--}debug
```

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


## Development install

```
git clone https://github.com/ideonate/jhsingle-native-proxy.git
cd jhsingle-native-proxy

pip install -e .
```

To run directly in python: `python -m jhsingle_native_proxy.main <rest of command line>`
