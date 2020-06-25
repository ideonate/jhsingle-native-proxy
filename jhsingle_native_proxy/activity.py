import os
import json
from datetime import datetime

from tornado.ioloop import PeriodicCallback
from tornado import httpclient

from jupyterhub.utils import make_ssl_context, exponential_backoff, isoformat

def configure_http_client():
    keyfile = os.environ.get('JUPYTERHUB_SSL_KEYFILE', '')
    certfile = os.environ.get('JUPYTERHUB_SSL_CERTFILE', '')
    client_ca = os.environ.get('JUPYTERHUB_SSL_CLIENT_CA', '')

    if keyfile == '' and certfile == '' and client_ca == '':
        return

    ssl_context = make_ssl_context(keyfile, certfile, cafile=client_ca)
    httpclient.AsyncHTTPClient.configure(None, defaults={"ssl_options": ssl_context})

def start_keep_alive(last_activity_interval, force_alive, settings):

    client = httpclient.AsyncHTTPClient()

    hub_activity_url = os.environ.get('JUPYTERHUB_ACTIVITY_URL', '')
    server_name = os.environ.get('JUPYTERHUB_SERVER_NAME', '')
    api_token = os.environ.get('JUPYTERHUB_API_TOKEN', '')

    if api_token == '' or server_name == '' or hub_activity_url == '':
        print("The following env vars are required to report activity back to the hub for keep alive: "
                "JUPYTERHUB_ACTIVITY_URL ({}), JUPYTERHUB_SERVER_NAME({})".format(hub_activity_url, server_name, api_token))
        return

    async def send_activity():
        async def notify():
            print("About to notify Hub of activity")

            last_activity_timestamp = None

            if force_alive:
                last_activity_timestamp = datetime.utcnow()
            else:
                last_activity_timestamp = settings.get('api_last_activity', None)

            if last_activity_timestamp:
                last_activity_timestamp = isoformat(last_activity_timestamp)
                req = httpclient.HTTPRequest(
                    url=hub_activity_url,
                    method='POST',
                    headers={
                        "Authorization": "token {}".format(api_token),
                        "Content-Type": "application/json",
                    },
                    body=json.dumps(
                        {
                            'servers': {
                                server_name: {'last_activity': last_activity_timestamp}
                            },
                            'last_activity': last_activity_timestamp,
                        }
                    ),
                )
                try:
                    await client.fetch(req)
                except Exception as e:
                    print("Error notifying Hub of activity: {}".format(e))
                    return False
                else:
                    return True

            return True # Nothing to report, so really it worked

        await exponential_backoff(
            notify,
            fail_message="Failed to notify Hub of activity",
            start_wait=1,
            max_wait=15,
            timeout=60,
        )


    pc = PeriodicCallback(send_activity, 1e3 * last_activity_interval, 0.1)
    pc.start()
