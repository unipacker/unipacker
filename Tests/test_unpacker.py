import hashlib
import os
import sys
import threading
from unittest import TestCase

import pytest

from unipacker.core import UnpackerEngine, UnpackerClient, Sample
from unipacker.unpackers import get_unpacker


class Client(UnpackerClient):

    def __init__(self, event):
        super()
        self.event = event

    def emu_paused(self):
        self.event.set()

    def emu_done(self):
        self.event.set()


class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = threading.Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


class EngineTest(TestCase):

    def prepare_test(self, sample_path):
        sample = Sample(sample_path)
        unpacker, _ = get_unpacker(sample)
        event = threading.Event()
        client = Client(event)
        heartbeat = RepeatedTimer(120, print, "- still running -", file=sys.stderr)

        engine = UnpackerEngine(sample)
        engine.register_client(client)
        heartbeat.start()
        threading.Thread(target=engine.emu).start()
        event.wait()
        heartbeat.stop()
        engine.stop()
        print(f"\n--- Emulation of {os.path.basename(sample_path)} finished ---")

    def calc_md5(self, sample):
        BUF_SIZE = 65536
        md5 = hashlib.md5()
        with open(sample, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                md5.update(data)
        return md5

    def perform_test(self, packer, ignore):
        curr_path = os.getcwd()
        if "Tests" in curr_path:
            os.chdir(curr_path.split("Tests")[0])
        sample = "Sample/"
        directory = sample + packer
        hashes = []
        for file in os.listdir(directory):
            if file in ignore:
                print(f"{file} not supported")
                continue
            print(f"Testing file: {file}")
            self.prepare_test(directory + file)
            new_md5 = self.calc_md5("unpacked.exe").hexdigest()
            old_md5 = self.calc_md5("Tests/UnpackedSample/" + packer + "unpacked_" + file).hexdigest()
            hashes.append((file, old_md5, new_md5))
        print(f"\n--- Done, checking for success ---")
        return hashes

    @pytest.mark.skip()
    def test_aspack(self):
        hash_list = self.perform_test("ASPack/", [])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    @pytest.mark.skip()
    def test_fsg(self):
        hash_list = self.perform_test("FSG/", ["Lab18-02.exe"])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    @pytest.mark.skip()
    def test_mew(self):
        hash_list = self.perform_test("MEW/", [])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    @pytest.mark.skip()
    def test_mpress(self):
        hash_list = self.perform_test("MPRESS/", [])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    def test_upx(self):
        hash_list = self.perform_test("UPX/", ["Lab18-01.exe"])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    @pytest.mark.skip()
    def test_yzpack(self):
        hash_list = self.perform_test("YZPack/", ["YZpack2.0Unpackme.exe"])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")
