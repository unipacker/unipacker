import os
import shutil
import sys
import threading

from unipacker.core import UnpackerEngine, SimpleClient, Sample
from unipacker.imagedump import NoDump
from unipacker.unpackers import get_unpacker
from unipacker.utils import RepeatedTimer

# TODO remove with new architecture

class FreeEmulationHandler(object):

    def __init__(self, path, start_addr, end_addr):
        self.sample = self.create_sample(path, start_addr, end_addr)
        self.uc = self.free_emu_sample()

    def create_sample(self, path, start_addr, end_addr):
        sample = Sample(path, auto_default_unpacker=True)
        sample.unpacker.startaddr = start_addr
        sample.unpacker.endaddr = end_addr
        sample.unpacker.section_hopping_control = 0
        sample.unpacker.allowed_sections = [s.Name for s in sample.unpacker.secs]
        sample.unpacker.allowed_addr_ranges = sample.unpacker.get_allowed_addr_ranges()
        sample.unpacker.dumper = NoDump()


        return sample


    # TODO setup
    def free_emu_sample(self):
        event = threading.Event()
        client = SimpleClient(event)
        heartbeat = RepeatedTimer(120, print, "- still running -", file=sys.stderr)
        engine = UnpackerEngine(self.sample)
        engine.register_client(client)
        heartbeat.start()
        threading.Thread(target=engine.emu).start()
        event.wait()
        heartbeat.stop()
        engine.stop()
        return engine.uc
