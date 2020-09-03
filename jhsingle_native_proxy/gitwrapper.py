from queue import Queue, Empty
import threading
from asyncio import sleep
import traceback
import os

from .pull import GitPuller


class GitWrapper():

    def __init__(self, repo, repobranch, repofolder):
        self.repo = repo
        self.finished = False
        self.error = False
        self.logs = []
        self.gitpuller = GitPuller(repo, repobranch, repofolder)
        self.repofolder = repofolder

    async def start_pull(self):

        print("Pulling from git repo")

        # We don't need a lock on git puller since we only call it from this object.

        try:

            q = Queue()
            def pull():
                try:
                    for line in self.gitpuller.pull():
                        q.put_nowait(line)
                    q.put_nowait(None) # Signal we are done
                except Exception as e:
                    q.put_nowait(e)
                    raise e
            self.gp_thread = threading.Thread(target=pull)

            self.gp_thread.start()

            while True:
                try:
                    progress = q.get_nowait()
                except Empty:
                    await sleep(0.5)
                    continue
                if progress is None:
                    os.chdir(self.repofolder)
                    break
                if isinstance(progress, Exception):
                    self.logs.extend([
                            l.strip()
                            for l in traceback.format_exception(
                                type(progress), progress, progress.__traceback__
                            )
                        ])
                    self.error = True
                    return
                print(progress)
                self.logs.append(progress)
        finally:
            self.finished = True
