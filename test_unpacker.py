import threading
from unittest import TestCase

import yara

from unipacker import State, UnpackerEngine, UnpackerClient
from unpackers import get_unpacker


class Client(UnpackerClient):

    def __init__(self, event):
        super()
        self.event = event

    def emu_paused(self):
        self.event.set()

    def emu_done(self):
        self.event.set()


class Test(TestCase):

    def test_fsg(self):
        state = State()
        sample = "Sample/FSG/Lab18-02.exe"
        unpacker, _ = get_unpacker(sample)
        event = threading.Event()
        client = Client(event)
        engine = UnpackerEngine(state, sample, unpacker)
        engine.register_client(client)
        threading.Thread(target=engine.emu).start()
        event.wait()
        engine.stop()
        print(f"\n--- Done, checking for success ---")
        rules = yara.compile(filepath="malwrsig.yar")
        result = str(rules.match("unpacked.exe"))
        print(f"Yara matches: {result}")
        self.assertTrue("practicalmalwareanalysis" in result, f"Expected 'practicalmalwareanalysis, got {result}")
