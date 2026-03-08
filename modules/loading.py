# This is a simple loading spinner that can be used to indicate progress during long-running operations.
import sys
import time
import threading
import itertools

class Spinner:
    def __init__(self, message="Loading..."):
        self.message = message
        self.spinner_cycle = itertools.cycle(['|', '/', '-', '\\'])
        self.running = False
        self.thread = None

    def _spin(self):
        while self.running:
            sys.stdout.write(f"\r{self.message} {next(self.spinner_cycle)}")
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b' * (len(self.message) + 2))

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        sys.stdout.write('\r' + ' ' * (len(self.message) + 2) + '\r') # Clear the line
        sys.stdout.flush()