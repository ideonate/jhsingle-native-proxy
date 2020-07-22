import os
import sys
import logging
import json
import subprocess

try:
    from shlex import quote
except ImportError:
    from pipes import quote

def get_conda_info():
    conda_info = None

    try:
        CONDA_EXE = os.environ.get("CONDA_EXE", "conda")
        # conda info --json uses the standard JSON escaping
        # mechanism for non-ASCII characters. So it is always
        # valid to decode here as 'ascii', since the JSON loads()
        # method will recover any original Unicode for us.
        p = subprocess.check_output([CONDA_EXE, "info", "--json"], shell=False).decode('ascii')
        conda_info = json.loads(p)
    except Exception as err:
        print("jhsingle_native_proxy.conda_runner couldn't call conda:\n%s", err)
        return None

    return conda_info

def get_conda_prefix_and_env(envname, conda_info=None):

    if conda_info is None:
        conda_info = get_conda_info()

    # Find conda env
    conda_prefix = conda_info['conda_prefix']
    all_envs = conda_info['envs']

    env_path = os.path.join(conda_prefix, 'envs', envname) # Guess at a default

    for env in all_envs:
        last_name = env.split('/')[-1]
        if last_name == envname:
            env_path = env
            break

    return conda_prefix, env_path

def exec_in_env(conda_prefix, env_path, *command):
    # Run the standard conda activation script, and print the
    # resulting environment variables to stdout for reading.

    # Build final command
    command = ' '.join(quote(c) for c in command)
    activate = os.path.join(conda_prefix, 'bin', 'activate')
    ecomm = ". '{}' '{}' && echo CONDA_PREFIX=$CONDA_PREFIX && exec {}".format(activate, env_path, command)
    ecomm = ['sh' if 'bsd' in sys.platform else 'bash', '-c', ecomm]
    os.execvp(ecomm[0], ecomm)


if __name__ == '__main__':
    exec_in_env(*(sys.argv[1:]))