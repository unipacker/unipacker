import hashlib
import multiprocessing
import os
import sys
import threading
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from colorama import Fore

from unipacker.core import Sample, SimpleClient, UnpackerEngine
from unipacker.utils import RepeatedTimer


def calc_md5(sample):
    BUF_SIZE = 65536
    md5 = hashlib.md5()
    with open(sample, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
    return md5


class IntegrityTest(TestCase):
    hashes = {
        "VMProtect/UnPackMe_VMProtect_1.53.exe": "b1db0a24d4e1488b1704767ba0688910",
        "ASPack/lbop20_aspack.exe": "7681ec362dca4db23c62a239eddcc67f",
        "UPX/lbop20_UPX.exe": "9c87102ddc1cc88870a96530b52ad42a",
        "UPX/Lab18-01.exe": "9035bed8ee6dc82b04ab1119a221974d",
        "PEtite/lbop20_PEtite.exe": "d8c1e7448af314f0e4f1bb3c75bc139b",
        "MPRESS/UnPackMe32_MPRESS.exe": "1e7b70d782d2bb33eb7d5342d28446f0",
        "MPRESS/lbop20_MPRESS.exe": "466706bcff4e3e71697bce07edf9ed83",
        "YZPack/UnPackMe_YZPack_1.1.exe": "e1f007249c0d635beb4b013298deac47",
        "YZPack/YZpack2.0Unpackme.exe": "306e3708b05b2741ab00c8159100a0aa",
        "MEW/lbop20_MEW.exe": "57ae14034ee436da9da34f5195bc5f35",
        "Armadillo/1.71/VirusShare_c1d33d3d4b68ee64540e9d1409e2afe5": "c1d33d3d4b68ee64540e9d1409e2afe5",
        "Armadillo/1.71/armadillo_zusy.exe": "42399e7be5557bf0d45e9e8306d3a6b6",
        "Armadillo/1.71/VirusShare_875265e919c0f4b72b3e81ae04884a91": "875265e919c0f4b72b3e81ae04884a91",
        "Armadillo/v1.xx-v2.xx/VirusShare_f24fd316a5f18600c148d57a40ae8c5d": "f24fd316a5f18600c148d57a40ae8c5d",
        "Armadillo/v1.xx-v2.xx/VirusShare_08f64117915eaa552cb5af37ce7291eb": "08f64117915eaa552cb5af37ce7291eb",
        "Armadillo/v1.xx-v2.xx/armadillo_zusy.exe": "e2a32c6b35c073b85634f7a86ee8e1e6",
        "FSG/unpackme- FSG 1.31 - dulek.exe": "ed6c6067974ed35016ab025d4e08ac02",
        "FSG/unpackme- FSG 1.33 - dulek.exe": "ae293061d9cca63a18e17bc4bcb98c6a",
        "FSG/Lab18-02.exe": "9c5c27494c28ed0b14853b346b113145",
        "PECompact/lbop20_PECompact.exe": "8d374b20bc6b68255ed4d869aeb93eac",
    }

    def generate_integrity(self):
        curr_path = os.getcwd()
        if "Tests" in curr_path:
            os.chdir(curr_path.split("Tests")[0])
        for rt, dir, _ in os.walk(os.getcwd() + "/Sample/"):
            for d in dir:
                for rt2, dir2, f2 in os.walk(rt + d):
                    for f in f2:
                        print(f"\"{(rt2 + '/' + f).split('Sample/')[1]}\": \"{calc_md5(rt2 + '/' + f).hexdigest()}\",")

    def test_integrity(self):
        sample_path = Path(__file__).parent.parent.joinpath('Sample')
        for rt, dir, _ in os.walk(str(sample_path)):
            for d in dir:
                for rt2, dir2, f2 in os.walk(rt + d):
                    for f in f2:
                        test_path = os.path.join(rt2, f)
                        relative_test_path = test_path.split(f"Sample{os.path.sep}")[1]
                        if relative_test_path not in self.hashes:
                            print(
                                f"{Fore.LIGHTRED_EX}Warning: Unknown file {relative_test_path} found in sample directory{Fore.RESET}")
                            continue
                        self.assertTrue(calc_md5(test_path).hexdigest() == self.hashes[relative_test_path],
                                        f"Tested file: {relative_test_path}. Expected: {self.hashes[relative_test_path]}, got: {calc_md5(test_path).hexdigest()}")
                        print(f"Tested:{relative_test_path}, MD5: {calc_md5(test_path).hexdigest()}")


def _unpack(t):
    with TemporaryDirectory() as unpack_dir:
        file, unpacked_file = t
        unpacked = f"{unpack_dir}/unpacked.exe"
        sample = Sample(file)
        event = threading.Event()
        client = SimpleClient(event)
        heartbeat = RepeatedTimer(120, print, "- still running -", file=sys.stderr)

        engine = UnpackerEngine(sample, unpacked)
        engine.register_client(client)
        heartbeat.start()
        threading.Thread(target=engine.emu).start()
        event.wait()
        heartbeat.stop()
        engine.stop()
        assert os.path.exists(unpacked)
        assert not os.path.exists(sample.unpacker.dumper.brokenimport_dump_file)
        if os.path.exists(unpacked):
            return file, calc_md5(unpacked).hexdigest(), calc_md5(unpacked_file).hexdigest()
        else:
            return file, '', calc_md5(unpacked_file)


class EngineTest(TestCase):

    def perform_test(self, packer, ignore):
        curr_path = os.getcwd()
        if "Tests" in curr_path:
            os.chdir(curr_path.split("Tests")[0])
        sample = "Sample/"
        directory = sample + packer
        hashes = []

        files = [f for f in os.listdir(directory) if f not in ignore]
        files_unpacked = ["Tests/UnpackedSample/" + packer + "unpacked_" + f for f in files]
        files = [directory + f for f in files]
        tuples = list(zip(files, files_unpacked))

        with multiprocessing.Pool(
                processes=min(multiprocessing.cpu_count(), 12)) as pool:
            for file, new_md5, old_md5 in pool.imap_unordered(_unpack, tuples):
                hashes.append((file, old_md5, new_md5))

        print(f"\n--- Done, checking for success ---")
        return hashes

    def test_aspack(self):
        hash_list = self.perform_test("ASPack/", [])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    def test_fsg(self):
        hash_list = self.perform_test("FSG/", ["Lab18-02.exe"])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    def test_mew(self):
        hash_list = self.perform_test("MEW/", [])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    def test_mpress(self):
        hash_list = self.perform_test("MPRESS/", [])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    def test_petite(self):
        hash_list = self.perform_test("PEtite/", [])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    def test_upx(self):
        hash_list = self.perform_test("UPX/", ["Lab18-01.exe"])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")

    def test_yzpack(self):
        hash_list = self.perform_test("YZPack/", ["YZpack2.0Unpackme.exe"])
        for name, old_md5, new_md5 in hash_list:
            self.assertTrue(new_md5 == old_md5, f"Expected: {old_md5}, got {new_md5}")
            print(f"{name}:\n\told_md5: {old_md5}\n\tnew_md5: {new_md5}")
