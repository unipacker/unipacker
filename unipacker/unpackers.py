import os
import sys

import yara

import unipacker
from unipacker.imagedump import ImageDump, YZPackDump, ASPackDump, FSGDump, MEWDump, UPXDump, MPRESSDump, PEtiteDump
from unipacker.utils import InvalidPEFile


class DefaultUnpacker(object):

    def __init__(self, sample):
        self.name = "unknown"
        self.sample = sample

        self.secs = sample.sections
        self.BASE_ADDR = sample.opt_header.ImageBase
        self.ep = sample.opt_header.AddressOfEntryPoint + self.BASE_ADDR
        self.allowed_sections = [s.Name for s in self.secs if
                                 s.VirtualAddress + self.BASE_ADDR <= self.ep < s.VirtualAddress + s.VirtualSize + self.BASE_ADDR]

        self.section_hopping_control = len(self.allowed_sections) > 0
        self.dumper = ImageDump()
        self.write_execute_control = False
        self.allowed_addr_ranges = []
        self.virtualmemorysize = None

        self.startaddr = self.get_entrypoint()
        self.endaddr = self.get_tail_jump()

    def get_tail_jump(self):
        while True:
            try:
                endaddr = input("Define manual end address for emulation (leave empty for max value): ")
                if endaddr == "":
                    return sys.maxsize
                endaddr = int(endaddr, 0)
                break
            except ValueError:
                print("Incorrect end address!")
        return endaddr

    def get_entrypoint(self):
        while True:
            try:
                startaddr = input(
                    "Define manual start address for emulation or enter ep to use the entry point of the binary: ")
                if startaddr == 'ep' or startaddr == "":
                    return
                else:
                    startaddr = int(startaddr, 0)
                break
            except ValueError:
                print("Incorrect start address!")
        return startaddr

    def dump(self, uc, apicall_handler, sample, path="unpacked.exe"):
        self.dumper.dump_image(uc, self.BASE_ADDR, self.virtualmemorysize, apicall_handler, sample, path)

    def is_allowed(self, address):
        for start, end in self.allowed_addr_ranges:
            if start <= address <= end:
                return True
        return False

    def allow(self, address):
        sec_name = self.get_section(address)
        curr_section_range = self.get_section_range(sec_name)
        if curr_section_range:
            self.allowed_sections += [sec_name]
            self.allowed_addr_ranges = self.get_allowed_addr_ranges()

    def get_allowed_addr_ranges(self):
        allowed_ranges = []
        for s in self.secs:
            if s.Name in self.allowed_sections:
                start_addr = s.VirtualAddress + self.BASE_ADDR
                end_addr = s.VirtualSize + start_addr + self.BASE_ADDR
                allowed_ranges += [(start_addr, end_addr)]
        return allowed_ranges

    def get_section(self, address):
        for s in self.secs:
            if s.VirtualAddress + self.BASE_ADDR <= address < s.VirtualAddress + s.VirtualSize + self.BASE_ADDR:
                return s.Name
        return "external"

    def get_section_from_addr(self, address):
        for s in self.secs:
            if s.VirtualAddress + self.BASE_ADDR <= address < s.VirtualAddress + s.VirtualSize + self.BASE_ADDR:
                return s.VirtualAddress + self.BASE_ADDR, s.VirtualAddress + s.VirtualSize + self.BASE_ADDR
        return None, None

    def get_section_range(self, section):
        for s in self.secs:
            if s.Name == section:
                return s.VirtualAddress + self.BASE_ADDR, s.VirtualAddress + s.VirtualSize + self.BASE_ADDR
        return None


class AutomaticDefaultUnpacker(DefaultUnpacker):

    def get_entrypoint(self):
        return None  # default binary ep

    def get_tail_jump(self):
        return sys.maxsize


class UPXUnpacker(AutomaticDefaultUnpacker):

    def __init__(self, sample):
        super().__init__(sample)
        self.name = "UPX"
        self.allowed_sections = []
        self.dumper = UPXDump()
        for s in self.secs:
            if s.SizeOfRawData > 0:
                self.allowed_sections += [s.Name]
        self.allowed_addr_ranges = self.get_allowed_addr_ranges()


class PEtiteUnpacker(AutomaticDefaultUnpacker):

    def __init__(self, sample):
        super().__init__(sample)
        self.name = "PEtite"
        ep = sample.opt_header.AddressOfEntryPoint
        for s in self.secs:
            start_addr = s.VirtualAddress
            end_addr = s.VirtualSize + start_addr
            if start_addr <= ep <= end_addr:
                finish = end_addr

        # self.allowed_sections = ['.text']
        # self.allowed_addr_ranges = self.get_allowed_addr_ranges()
        self.allowed_addr_ranges.extend([(ep + self.BASE_ADDR, finish + self.BASE_ADDR)])
        self.dumper = PEtiteDump()

    def is_allowed(self, address):
        for chunk in self.sample.allocated_chunks:
            if chunk not in self.allowed_addr_ranges:
                self.allowed_addr_ranges.append(chunk)
        return super().is_allowed(address)


class ASPackUnpacker(AutomaticDefaultUnpacker):
    def __init__(self, sample):
        super().__init__(sample)
        self.name = "ASPack"
        self.allowed_sections = ['.aspack']
        self.allowed_addr_ranges = self.get_allowed_addr_ranges()
        self.dumper = ASPackDump()


class FSGUnpacker(AutomaticDefaultUnpacker):
    def __init__(self, sample):
        super().__init__(sample)
        self.name = "FSG"
        self.allowed_sections = []
        self.dumper = FSGDump()
        for s in self.secs:
            if s.SizeOfRawData > 0:
                self.allowed_sections += [s.Name]
        self.allowed_addr_ranges = self.get_allowed_addr_ranges()


class YZPackUnpacker(AutomaticDefaultUnpacker):
    def __init__(self, sample):
        super().__init__(sample)
        self.name = "YZPack"
        self.allowed_sections = ['.yzpack', '.yzpack2']
        self.allowed_addr_ranges = self.get_allowed_addr_ranges()
        self.dumper = YZPackDump()


class MEWUnpacker(AutomaticDefaultUnpacker):
    def __init__(self, sample):
        super().__init__(sample)
        self.name = "MEW"
        self.allowed_sections = []
        self.section_hopping_control = True
        self.dumper = MEWDump()

    def is_allowed(self, address):
        return "MEW" not in self.get_section(address)


class MPRESSUnpacker(AutomaticDefaultUnpacker):
    def __init__(self, sample):
        super().__init__(sample)
        self.name = "MPRESS"
        self.allowed_sections = [".MPRESS2"]
        self.allowed_addr_ranges = self.get_allowed_addr_ranges()
        self.dumper = MPRESSDump()
        self.swap_status = 0

    def is_allowed(self, address):
        if not super().is_allowed(address) and self.swap_status == 0:
            self.swap_status = 1
            section_start, section_end = self.get_section_from_addr(address)
            self.allowed_addr_ranges = [(address, section_end)]
            return True

        if not super().is_allowed(address) and self.swap_status == 1:
            return False

        return True


def identifypacker(sample, yar):
    rules = yara.compile(filepath=yar)
    matches = rules.match(sample)
    result = generate_label(matches)
    if result == 'unknown':
        print(f"The packer used for {sample} is unknown. Using default unpacker")
        return 'unknown', matches

    return result, matches


def generate_label(l):
    if 'upx' in str(l):
        return 'upx'
    elif "petite" in str(l):
        return "petite"
    elif 'mew' in str(l):
        return 'mew'
    elif 'mpress' in str(l):
        return 'mpress'
    elif "aspack" in str(l):
        return "aspack"
    elif "fsg" in str(l):
        return "fsg"
    elif "pecompact" in str(l):
        return "pecompact"
    elif "upack" in str(l):
        return "upack"
    elif "yzpack" in str(l):
        return "yzpack"
    else:
        return 'unknown'


def get_unpacker(sample, auto_default_unpacker=True):
    yar = f"{os.path.dirname(unipacker.__file__)}/packer_signatures.yar"
    packer, yara_matches = identifypacker(sample.path, yar)
    packers = {
        "upx": UPXUnpacker,
        "petite": PEtiteUnpacker,
        "aspack": ASPackUnpacker,
        "fsg": FSGUnpacker,
        "yzpack": YZPackUnpacker,
        "mew": MEWUnpacker,
        "mpress": MPRESSUnpacker,
    }

    if "pe32" not in str(yara_matches):
        raise InvalidPEFile("Not a PE32 file!")

    if packer not in packers:
        if auto_default_unpacker:
            return AutomaticDefaultUnpacker(sample), yara_matches
        else:
            return DefaultUnpacker(sample), yara_matches
    else:
        return packers[packer](sample), yara_matches
