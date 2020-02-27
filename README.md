# jhsingle-native-proxy

Wrap an arbitrary webapp so it can be used in place of jupyter-singleuser in a JupyterHub setting.

Within JupyterHub this allows similar operation to [jupyter-server-proxy](https://github.com/jupyterhub/jupyter-server-proxy) except it also removes the Jupyter notebook itself, so is working directly with the arbitrary web service. 

This is a very basic alpha version.

## Install and Run

Install using pip.

```
pip install jhsingle-native-proxy
```

The process to start is specified on the command line:

```
jhsingle-native-proxy streamlit hello
```

To listen on a different port use:

```
jhsingle-native-proxy --port 8000 streamlit hello
```

## Development install

```
git clone https://github.com/ideonate/jhsingle-native-proxy.git
cd jhsingle-native-proxy

pip install -e .
```

To run directly in python: `python -m jhsingle-native-proxy.main <command to run>`
