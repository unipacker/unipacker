import os
import shutil
import sys
import threading

from unipacker.core import UnpackerEngine, SimpleClient
from unipacker.unpackers import get_unpacker
from unipacker.utils import RepeatedTimer


class IOHandler(object):

    def __init__(self, samples, dest_dir, partition_by_packer):
        os.makedirs(dest_dir, exist_ok=True)
        for sample in samples:
            print(f"Next up: {sample}")
            self.handle_sample(sample, dest_dir, partition_by_packer)

    def handle_sample(self, sample, dest_dir, partition_by_packer):
        unpacker, _ = get_unpacker(sample)
        event = threading.Event()
        client = SimpleClient(event)
        heartbeat = RepeatedTimer(120, print, "- still running -", file=sys.stderr)

        engine = UnpackerEngine(sample)
        engine.register_client(client)
        heartbeat.start()
        threading.Thread(target=engine.emu).start()
        event.wait()
        heartbeat.stop()
        engine.stop()
        if partition_by_packer:
            dest_dir = os.path.join(dest_dir, sample.unpacker.name)
            os.makedirs(dest_dir, exist_ok=True)
        dest_file = os.path.join(dest_dir, f"unpacked_{os.path.basename(sample.path)}")
        print(f"\nEmulation of {os.path.basename(sample.path)} finished.\n"
              f"--- Saving to {dest_file} ---\n")
        shutil.move("unpacked.exe", dest_file)
