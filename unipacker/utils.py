import random
import string
import struct
import threading

import pefile
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EIP, \
    UC_X86_REG_ESP, UC_X86_REG_EFLAGS, UC_X86_REG_EDI, UC_X86_REG_ESI, UC_X86_REG_EBP


def print_cols(lines):
    max_cols = max(len(line) for line in lines)
    lines = [line + ("", )*(max_cols - len(line)) for line in lines]
    cols = zip(*lines)
    col_widths = [max(len(str(word)) for word in col) + 2 for col in cols]
    for line in lines:
        print("".join(str(word).ljust(col_widths[i]) for i, word in enumerate(line)))


def merge(ranges):
    if not ranges:
        return []
    saved = list(ranges[0])
    for lower, upper in sorted([sorted(t) for t in ranges]):
        if lower <= saved[1] + 1:
            saved[1] = max(saved[1], upper)
        else:
            yield tuple(saved)
            saved[0] = lower
            saved[1] = upper
    yield tuple(saved)


def align(value, page_size=4096):
    m = value % page_size
    f = page_size - m
    aligned_size = value + f
    return aligned_size


def alignments(value, multiple_of):
    if value <= multiple_of:
        return multiple_of
    c = 1
    while value > multiple_of * c:
        c += 1
    return multiple_of * c


def remove_range(old_range, to_remove):
    old_lower, old_upper = old_range
    remove_lower, remove_upper = to_remove
    if old_lower == remove_lower and old_upper == remove_upper:
        return []
    if old_lower < remove_lower and old_upper > remove_upper:
        # deleted range is inside old range
        return [(old_lower, remove_lower - 1), (remove_upper + 1, old_upper)]
    if remove_lower <= old_lower and old_upper > remove_upper:
        # only deleted range upper limit is inside old range
        return [(remove_upper + 1, old_upper)]
    if old_lower < remove_lower and remove_upper >= old_upper:
        # only lower limit is inside old range
        return [(old_lower, remove_lower - 1)]
    # range unaffected
    return [(old_lower, old_upper)]


def convert_to_string(b):
    try:
        return b.rstrip(b'\x00').decode('ascii')
    except UnicodeDecodeError:
        return str(hex(int.from_bytes(b, "little")))


def get_string(ptr, uc, break_on_unprintable=False):
    printable_chars = bytes(string.printable, "ascii")
    buf = ""
    i = 0
    while True:
        item, = struct.unpack("c", uc.mem_read(ptr + i, 1))
        if item == b"\x00" or (break_on_unprintable and item not in printable_chars):
            break
        buf += chr(item[0])
        i += 1
    return buf


def calc_export_offset_of_dll(dllpath, function_name):
    """This function calculates the offset of exported function of a DLL. It is slow, so hardcoded values are used"""
    dll = pefile.PE(dllpath)
    exports = dll.DIRECTORY_ENTRY_EXPORT.symbols
    for e in exports:
        if e.name == bytes(function_name, 'ascii'):
            return e.address
    return None


def print_dllname_to_functionlist(dllname_to_functionlist):
    for dll in dllname_to_functionlist:
        print(dll)
        for fct_name, fct_addr in dllname_to_functionlist[dll]:
            print(f"\t{fct_name}, {hex(fct_addr)}")


def print_addr_list(list_name, list):
    hex = list_name
    hex += ', '.join('0x%02x' % l for l in list)
    print(hex)


def calc_processid():
    x = random.randint(2000, 6000)
    while x % 4 != 0:
        x = random.randint(2000, 6000)

    return x


def calc_threadid():
    x = random.randint(0x500, 0x2000)
    while x % 4 != 0:
        x = random.randint(0x500, 0x2000)

    return x


def fix_section_names(path, offset, num_of_sections):
    with open(path, 'rb+') as f:
        c = 0
        nc = 0
        while c < num_of_sections:
            f.seek(offset)
            if f.read(1) == b'\x00':
                f.seek(offset)
                name = "sect_" + str(nc)
                f.write(name.encode('ascii'))
                nc += 1
            c += 1
            offset += 0x28


def print_chunks(tupel_list):
    print("Allocated Chunks:")
    for e in tupel_list:
        print(f"\t({hex(e[0])}, {hex(e[1])})")


class ImportValues(object):
    def __init__(self, import_struct, name, imports):
        self.Characteristics = getattr(import_struct, "Characteristics")
        self.TimeDateStamp = getattr(import_struct, "TimeDateStamp")
        self.ForwarederChain = getattr(import_struct, "ForwarderChain")
        self.RVAtoName = getattr(import_struct, "Name")
        self.Name = name
        self.RVAtoFirstThunk = getattr(import_struct, "FirstThunk")
        self.imports = imports


class InvalidPEFile(Exception):
    pass


def get_reg_values(uc):
    return {
        "eax": uc.reg_read(UC_X86_REG_EAX),
        "ebx": uc.reg_read(UC_X86_REG_EBX),
        "ecx": uc.reg_read(UC_X86_REG_ECX),
        "edx": uc.reg_read(UC_X86_REG_EDX),
        "eip": uc.reg_read(UC_X86_REG_EIP),
        "esp": uc.reg_read(UC_X86_REG_ESP),
        "efl": uc.reg_read(UC_X86_REG_EFLAGS),
        "edi": uc.reg_read(UC_X86_REG_EDI),
        "esi": uc.reg_read(UC_X86_REG_ESI),
        "ebp": uc.reg_read(UC_X86_REG_EBP)
    }


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