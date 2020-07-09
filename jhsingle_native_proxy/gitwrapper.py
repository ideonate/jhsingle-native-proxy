from queue import Queue, Empty
import threading
from asyncio import sleep
import traceback

from .pull import GitPuller


class GitWrapper():

    finished = False

    def __init__(self, repo, repofolder):
        self.repo = repo
        self.finished = False
        self.logs = []
        self.pullfuture = None
        self.gitpuller = GitPuller(repo, 'master', repofolder)

    async def start_pull(self):

        print("In start_pull")

        try:

            q = Queue()
            def pull():
                try:
                    print("In start_pull.pull")
                    for line in self.gitpuller.pull():
                        q.put_nowait(line)
                    # Sentinel when we're done
                    q.put_nowait(None)
                except Exception as e:
                    q.put_nowait(e)
                    raise e
            self.gp_thread = threading.Thread(target=pull)

            self.gp_thread.start()

            while True:
                try:
                    progress = q.get_nowait()
                    print(progress)
                except Empty:
                    await sleep(0.5)
                    continue
                if progress is None:
                    break
                if isinstance(progress, Exception):
                    error = '\n'.join([
                            l.strip()
                            for l in traceback.format_exception(
                                type(progress), progress, progress.__traceback__
                            )
                        ])
                    return
        finally:
            self.finished = True
