import sys

import yara

from imagedump import ImageDump, YZPackDump, ASPackDump, FSGDump, MEWDump, UPXDump, MPRESSDump
from utils import InvalidPEFile


class DefaultUnpacker(object):

    def __init__(self, sample):
        self.sample = sample

        self.secs = sample.sections
        self.BASE_ADDR = sample.opt_header.ImageBase
        self.ep = sample.opt_header.AddressOfEntryPoint + self.BASE_ADDR
        self.allowed_sections = [s.Name for s in self.secs if s.VirtualAddress + self.BASE_ADDR <= self.ep < s.VirtualAddress + s.VirtualSize + self.BASE_ADDR]

        self.section_hopping_control = len(self.allowed_sections) > 0
        self.dumper = ImageDump()
        self.write_execute_control = False
        self.allowed_addr_ranges = []
        self.virtualmemorysize = None

    def get_tail_jump(self):
        while True:
            try:
                endaddr = input("Define manual end address for emulation (leave empty for max value): ")
                if endaddr == "":
                    return sys.maxsize, None
                endaddr = int(endaddr, 0)
                break
            except ValueError:
                print("Incorrect end address!")
        return endaddr, None

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

    def dump(self, uc, apicall_handler, path="unpacked.exe"):
        self.dumper.dump_image(uc, self.BASE_ADDR, self.virtualmemorysize, apicall_handler, path)

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


class UPXUnpacker(DefaultUnpacker):

    def __init__(self, sample):
        super().__init__(sample)
        self.allowed_sections = []
        self.dumper = UPXDump()
        for s in self.secs:
            if s.SizeOfRawData > 0:
                self.allowed_sections += [s.Name]
        self.allowed_addr_ranges = self.get_allowed_addr_ranges()

    def get_tail_jump(self):
        return sys.maxsize, None

    def get_entrypoint(self):
        return None


class PEtiteUnpacker(DefaultUnpacker):

    def get_entrypoint(self):
        return None

    # TODO Petite section hopping not working
    def is_allowed(self, address):
        return True

    def get_tail_jump(self):
        return sys.maxsize, None


class ASPackUnpacker(DefaultUnpacker):
    def __init__(self, sample):
        super().__init__(sample)
        self.allowed_sections = ['.aspack']
        self.allowed_addr_ranges = self.get_allowed_addr_ranges()
        self.dumper = ASPackDump()

    def get_entrypoint(self):
        return None

    def get_tail_jump(self):
        return sys.maxsize, None


class FSGUnpacker(DefaultUnpacker):
    def __init__(self, sample):
        super().__init__(sample)
        self.allowed_sections = []
        self.dumper = FSGDump()
        for s in self.secs:
            if s.SizeOfRawData > 0:
                self.allowed_sections += [s.Name]
        self.allowed_addr_ranges = self.get_allowed_addr_ranges()

    def get_entrypoint(self):
        return None

    def get_tail_jump(self):
        return sys.maxsize, None


class YZPackUnpacker(DefaultUnpacker):
    def __init__(self, sample):
        super().__init__(sample)
        self.allowed_sections = ['.yzpack', '.yzpack2']
        self.allowed_addr_ranges = self.get_allowed_addr_ranges()
        self.dumper = YZPackDump()

    def get_entrypoint(self):
        return None

    def get_tail_jump(self):
        return sys.maxsize, None


class MEWUnpacker(DefaultUnpacker):
    def __init__(self, sample):
        super().__init__(sample)
        self.allowed_sections = []
        self.section_hopping_control = True
        self.dumper = MEWDump()

    def is_allowed(self, address):
        return "MEW" not in self.get_section(address)

    def get_entrypoint(self):
        return None

    def get_tail_jump(self):
        return sys.maxsize, None


class MPRESSUnpacker(DefaultUnpacker):
    def __init__(self, sample):
        super().__init__(sample)
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

    def get_entrypoint(self):
        return None

    def get_tail_jump(self):
        return sys.maxsize, None


def identifypacker(sample, yar):
    rules = yara.compile(filepath=yar)
    matches = rules.match(sample)
    result = generate_label(matches)
    if result == 'unknown':
        print("This packer is unknown. Using default unpacker")
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
    yar = "./packer_signatures.yar"
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
