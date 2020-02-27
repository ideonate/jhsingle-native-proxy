# jhsingle-native-proxy

Wrap an arbitrary webapp so it can be used in place of jupyter-singleuser in a JupyterHub setting.

Within JupyterHub this allows similar operation to [jupyter-server-proxy](https://github.com/jupyterhub/jupyter-server-proxy) except it also removes the Jupyter notebook itself, so is working directly with the arbitrary web service.


This is a very basic alpha version.

## Install and Run

Install using pip.

```
pip install jhsingle-native-proxy
```

The process to start is specified on the command line, for example a streamlit web app:

```
jhsingle-native-proxy streamlit hello
```

By default the jhsingle-native-proxy server will listen on port 8888, forwarding to port 8500.

But you will normally need to tell jhsingle-native-proxy which port the end process will run in, and maybe tell the 
end process which port you want it to use (which you can do with the substitution variable {port}).

Note the use of -- to signal the end of command line options to jhsingle-native-proxy. Then the third party command line 
itself can contain options starting with dashes: 

```
jhsingle-native-proxy -- streamlit hello --server.port {port} --server.headless True --server.enableCORS False
```

To run jhsingle-native-proxy itself listening on a different port use:

```
jhsingle-native-proxy --serverport 8000 streamlit hello
```

To run jhsingle-native-proxy on port 8000, and the end process on 8505:

```
jhsingle-native-proxy --serverport 8000 --port 8505 -- streamlit hello --server.port {port} --server.headless True --server.enableCORS False
```

## Development install

```
git clone https://github.com/ideonate/jhsingle-native-proxy.git
cd jhsingle-native-proxy

pip install -e .
```

To run directly in python: `python -m jhsingle-native-proxy.main <rest of command line>`
