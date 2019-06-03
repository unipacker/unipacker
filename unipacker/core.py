import collections
import os
import struct
import sys
import threading
from time import time

import pefile
from unicorn import *
from unicorn.x86_const import *

import unipacker
from unipacker.apicalls import WinApiCalls
from unipacker.headers import PE, get_disk_headers, conv_to_class_header, parse_disk_to_header
from unipacker.kernel_structs import TEB, PEB, PEB_LDR_DATA, LIST_ENTRY
from unipacker.pe_structs import SectionHeader, IMAGE_SECTION_HEADER, ImportDescriptor, Import
from unipacker.unpackers import get_unpacker
from unipacker.utils import merge, align, convert_to_string, InvalidPEFile


class Sample(object):

    def __init__(self, path, auto_default_unpacker=True):
        self.path = path
        self.init_headers()
        self.imports = set()
        self.dllname_to_functionlist = collections.OrderedDict()  # dll_name -> [(name/ordinal, addr), ...]
        self.original_imports = []
        # setup section dict used for custom memory protection
        self.atn = {}  # Dict Address to Name: (StartVAddr, EndVAddr) -> Name
        self.ntp = {}  # Dict Name to Protection Tupel: Name -> (Execute, Read, Write)
        self.allocated_chunks = []
        self.offsets = parse_disk_to_header(path, "Offsets")

        sec_ctr = 0
        sect_names = []
        for s in self.sections:
            if s.Name == "" or s.Name in sect_names:
                s.Name = "sect_" + str(sec_ctr)
                sec_ctr += 1
                # fix_section_names(path, self.offsets["IMAGE_SECTION_HEADER"], self.pe_header.NumberOfSections)
                # TODO Add to unpackers
            sect_names.append(s.Name)

        # self.init_headers()

        self.unpacker, self.yara_matches = get_unpacker(self, auto_default_unpacker)

    def init_headers(self):
        self.headers = get_disk_headers(self)
        self.dos_header = conv_to_class_header(self.headers["_IMAGE_DOS_HEADER"])
        self.pe_header = conv_to_class_header(self.headers["_IMAGE_FILE_HEADER"])
        self.opt_header = conv_to_class_header(self.headers["_IMAGE_OPTIONAL_HEADER"])
        self.sections = conv_to_class_header(self.headers["IMAGE_SECTION_HEADER"])

    def __str__(self):
        return f"Sample: [{self.unpacker.name}] {self.path}"

    @staticmethod
    def get_samples(path, interactive=True):
        if os.path.isdir(path):
            response = None if not interactive else input(
                "Automatically find packer entry and exit points for unknown packers? [Y/n]: ")
            auto_default_unpacker = not response or response.lower().startswith("y")
            for root, dirs, files in os.walk(path):
                for file in files:
                    try:
                        sample = Sample(os.path.join(root, file), auto_default_unpacker)
                    except InvalidPEFile as e:
                        print(f"Could not initialize {file}: {e}")
                        continue
                    yield sample
        else:
            try:
                sample = Sample(path, auto_default_unpacker=False)
            except InvalidPEFile as e:
                print(f"Could not initialize {path}: {e}")
                return
            yield sample


class UnpackerClient(object):

    def emu_started(self):
        pass

    def emu_paused(self):
        pass

    def emu_resumed(self):
        pass

    def emu_done(self):
        pass

    def address_updated(self, address):
        pass


class SimpleClient(UnpackerClient):

    def __init__(self, event):
        super()
        self.event = event

    def emu_paused(self):
        self.event.set()

    def emu_done(self):
        self.event.set()


class UnpackerEngine(object):

    def __init__(self, sample):
        self.sample = sample
        self.clients = []

        self.emulator_event = threading.Event()
        self.single_instruction = False

        self.breakpoints = set()
        self.mem_breakpoints = []
        self.data_lock = threading.Lock()
        self.single_instruction = False
        self.apicall_handler = None

        self.log_mem_read = False
        self.log_mem_write = False
        self.log_instr = False
        self.log_apicalls = False

        self.sections_read = {}
        self.sections_written = {}
        self.write_targets = []
        self.sections_executed = {}
        self.apicall_counter = {}

        self.start = 0

        self.uc = None
        self.HOOK_ADDR = 0
        self.STACK_ADDR = 0
        self.STACK_SIZE = 0
        self.PEB_BASE = 0
        self.TEB_BASE = 0

        self.init_uc()

    def register_client(self, client):
        self.clients += [client]

    def pause(self):
        for client in self.clients:
            client.emu_paused()
        self.emulator_event.clear()
        self.emulator_event.wait()

    def stop(self):
        self.uc.emu_stop()
        self.emulator_event.set()

    def stopped(self):
        for client in self.clients:
            client.emu_done()

    def resume(self, single_instruction=False):
        self.single_instruction = single_instruction
        for client in self.clients:
            client.emu_resumed()
        self.emulator_event.set()

    def update_address(self, address):
        for client in self.clients:
            client.address_updated(address)

    def getVirtualMemorySize(self):
        sections = self.sample.sections
        min_offset = sys.maxsize
        total_size = 0
        for sec in sections:
            if sec.VirtualAddress < min_offset:
                min_offset = sec.VirtualAddress
            total_size += sec.VirtualSize
        total_size += min_offset

        return total_size

    def entrypoint(self, pe):
        return pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase

    def hook_code(self, uc, address, size, user_data):
        self.update_address(address)
        self.emulator_event.wait()

        with self.data_lock:
            breakpoint_hit = address in self.breakpoints
        if breakpoint_hit:
            print("\x1b[31mBreakpoint hit!\x1b[0m")
            self.pause()
        if address == self.sample.unpacker.endaddr:
            print("\x1b[31mEnd address hit! Unpacking should be done\x1b[0m")
            self.sample.unpacker.dump(uc, self.apicall_handler, self.sample)
            self.pause()

        if self.sample.unpacker.write_execute_control and address not in self.apicall_handler.hooks and (
                address < self.HOOK_ADDR or address > self.HOOK_ADDR + 0x1000):
            if any(lower <= address <= upper for (lower, upper) in sorted(self.write_targets)):
                print(f"\x1b[31mTrying to execute at 0x{address:02x}, which has been written to before!\x1b[0m")
                self.sample.unpacker.dump(uc, self.apicall_handler, self.sample)
                self.pause()

        if self.sample.unpacker.section_hopping_control and address not in self.apicall_handler.hooks and address - 0x7 not in self.apicall_handler.hooks and (
                address < self.HOOK_ADDR or address > self.HOOK_ADDR + 0x1000):  # address-0x7 corresponding RET
            if not self.sample.unpacker.is_allowed(address):
                sec_name = self.sample.unpacker.get_section(address)
                print(f"\x1b[31mSection hopping detected into {sec_name}! Address: " + hex(address) + "\x1b[0m")
                self.sample.unpacker.allow(address)
                self.sample.unpacker.dump(uc, self.apicall_handler, self.sample)
                self.pause()

        curr_section = self.sample.unpacker.get_section(address)
        if curr_section not in self.sections_executed:
            self.sections_executed[curr_section] = 1
        else:
            self.sections_executed[curr_section] += 1

        if address in self.apicall_handler.hooks:
            esp = uc.reg_read(UC_X86_REG_ESP)
            api_call_name = self.apicall_handler.hooks[address]
            ret, esp = self.apicall_handler.apicall(address, api_call_name, uc, esp, self.log_apicalls)

            if api_call_name not in self.apicall_counter:
                self.apicall_counter[api_call_name] = 1
            else:
                self.apicall_counter[api_call_name] += 1
            if ret is not None:  # might be a void function
                # print("RET: " + str(ret) + " APICALL_NAME: " + api_call_name)
                uc.mem_write(self.HOOK_ADDR, struct.pack("<I", ret))
            uc.reg_write(UC_X86_REG_ESP, esp)
        self.log_instr and print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))

        if self.single_instruction:
            self.pause()

    # Method is executed before memory access
    def hook_mem_access(self, uc, access, address, size, value, user_data):
        curr_section = self.sample.unpacker.get_section(address)
        access_type = ""
        if access == UC_MEM_READ:
            access_type = "READ"
            if curr_section not in self.sections_read:
                self.sections_read[curr_section] = 1
            else:
                self.sections_read[curr_section] += 1
            self.log_mem_read and print(">>> Memory is being READ at 0x%x, data size = %u" % (address, size))
        elif access == UC_MEM_WRITE:
            access_type = "WRITE"
            self.write_targets = list(merge(self.write_targets + [(address, address + size)]))
            if curr_section not in self.sections_written:
                self.sections_written[curr_section] = 1
            else:
                self.sections_written[curr_section] += 1
            self.log_mem_write and print(
                ">>> Memory is being WRITTEN at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        else:
            for access_name, val in unicorn_const.__dict__.items():
                if val == access and "UC_MEM" in access_name:
                    access_type = access_name[6:]  # remove UC_MEM from the access type
                    print(f"Unexpected mem access type {access_type}, addr: 0x{address:02x}")
        if any(lower <= address <= upper for lower, upper in self.mem_breakpoints):
            print(f"\x1b[31mMemory breakpoint hit! Access {access_type} to 0x{address:02x}")
            self.pause()

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        for access_name, val in unicorn_const.__dict__.items():
            if val == access and "UC_MEM" in access_name:
                print(f"Invalid memory access {access_name}, addr: 0x{address:02x}")
                self.uc.emu_stop()
                return

    def emu(self):
        try:
            for client in self.clients:
                client.emu_started()
            self.emulator_event.set()
            self.start = time()
            if self.sample.unpacker.endaddr == sys.maxsize:
                print(f"Emulation starting at {hex(self.sample.unpacker.startaddr)}")
            else:
                print(f"Emulation starting. Bounds: "
                      f"from {hex(self.sample.unpacker.startaddr)} to {hex(self.sample.unpacker.endaddr)}")
            # Start emulation from self.sample.unpacker.startaddr
            self.uc.emu_start(self.sample.unpacker.startaddr, sys.maxsize)
        except UcError as e:
            print(f"Error: {e}")
        finally:
            self.stopped()
            self.emulator_event.clear()

    def setup_processinfo(self):
        self.TEB_BASE = 0x200000
        self.PEB_BASE = self.TEB_BASE + 0x1000
        LDR_PTR = self.PEB_BASE + 0x1000
        LIST_ENTRY_BASE = LDR_PTR + 0x1000

        teb = TEB(
            -1,  # fs:00h
            self.STACK_ADDR + self.STACK_SIZE,  # fs:04h
            self.STACK_ADDR,  # fs:08h
            0,  # fs:0ch
            0,  # fs:10h
            0,  # fs:14h
            self.TEB_BASE,  # fs:18h (teb base)
            0,  # fs:1ch
            0xdeadbeef,  # fs:20h (process id)
            0xdeadbeef,  # fs:24h (current thread id)
            0,  # fs:28h
            0,  # fs:2ch
            self.PEB_BASE,  # fs:3ch (peb base)
        )

        peb = PEB(
            0,
            0,
            0,
            0,
            0xffffffff,
            self.sample.BASE_ADDR,
            LDR_PTR,
        )

        ntdll_entry = LIST_ENTRY(
            LIST_ENTRY_BASE + 12,
            LIST_ENTRY_BASE + 24,
            0x77400000,
        )

        kernelbase_entry = LIST_ENTRY(
            LIST_ENTRY_BASE + 24,
            LIST_ENTRY_BASE + 0,
            0x73D00000,

        )

        kernel32_entry = LIST_ENTRY(
            LIST_ENTRY_BASE + 0,
            LIST_ENTRY_BASE + 12,
            0x755D0000,
        )

        ldr = PEB_LDR_DATA(
            0x30,
            0x1,
            0x0,
            LIST_ENTRY_BASE,
            LIST_ENTRY_BASE + 24,
            LIST_ENTRY_BASE,
            LIST_ENTRY_BASE + 24,
            LIST_ENTRY_BASE,
            LIST_ENTRY_BASE + 24,
        )

        teb_payload = bytes(teb)
        peb_payload = bytes(peb)

        ldr_payload = bytes(ldr)

        ntdll_payload = bytes(ntdll_entry)
        kernelbase_payload = bytes(kernelbase_entry)
        kernel32_payload = bytes(kernel32_entry)

        self.uc.mem_map(self.TEB_BASE, align(0x5000))
        self.uc.mem_write(self.TEB_BASE, teb_payload)
        self.uc.mem_write(self.PEB_BASE, peb_payload)
        self.uc.mem_write(LDR_PTR, ldr_payload)
        self.uc.mem_write(LIST_ENTRY_BASE, ntdll_payload)
        self.uc.mem_write(LIST_ENTRY_BASE + 12, kernelbase_payload)
        self.uc.mem_write(LIST_ENTRY_BASE + 24, kernel32_payload)
        self.uc.windows_tib = self.TEB_BASE

    def load_dll(self, path_dll, start_addr):
        filename = os.path.splitext(os.path.basename(path_dll))[0]
        if not os.path.exists(f"{os.path.dirname(unipacker.__file__)}/DLLs/{filename}.ldll"):
            dll = pefile.PE(path_dll)
            loaded_dll = dll.get_memory_mapped_image(ImageBase=start_addr)
            with open(f"{os.path.dirname(unipacker.__file__)}/DLLs/{filename}.ldll", 'wb') as f:
                f.write(loaded_dll)
            self.uc.mem_map(start_addr, align(len(loaded_dll) + 0x1000))
            self.uc.mem_write(start_addr, loaded_dll)
        else:
            with open(f"{os.path.dirname(unipacker.__file__)}/DLLs/{filename}.ldll", 'rb') as dll:
                loaded_dll = dll.read()
                self.uc.mem_map(start_addr, align((len(loaded_dll) + 0x1000)))
                self.uc.mem_write(start_addr, loaded_dll)

    def init_uc(self):
        # Calculate required memory
        pe = pefile.PE(self.sample.path)
        self.sample.BASE_ADDR = pe.OPTIONAL_HEADER.ImageBase  # 0x400000
        self.sample.unpacker.BASE_ADDR = self.sample.BASE_ADDR
        self.sample.virtualmemorysize = self.getVirtualMemorySize()
        self.STACK_ADDR = 0x0
        self.STACK_SIZE = 1024 * 1024
        STACK_START = self.STACK_ADDR + self.STACK_SIZE
        # self.sample.unpacker.secs += [{"name": "stack", "vaddr": self.STACK_ADDR, "vsize": self.STACK_SIZE}]
        stack_sec_header = IMAGE_SECTION_HEADER(
            "stack".encode('ascii'),
            self.STACK_SIZE,
            self.STACK_ADDR,
            self.STACK_SIZE,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        self.sample.unpacker.secs.append(SectionHeader(stack_sec_header))
        self.HOOK_ADDR = STACK_START + 0x3000 + 0x1000

        # Start unicorn emulator with x86-32bit architecture
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        if self.sample.unpacker.startaddr is None:
            self.sample.unpacker.startaddr = self.entrypoint(pe)
        self.sample.loaded_image = pe.get_memory_mapped_image(ImageBase=self.sample.BASE_ADDR)
        self.sample.virtualmemorysize = align(self.sample.virtualmemorysize + 0x10000,
                                              page_size=4096)  # Space possible IAT rebuilding
        self.sample.unpacker.virtualmemorysize = self.sample.virtualmemorysize
        self.uc.mem_map(self.sample.BASE_ADDR, self.sample.virtualmemorysize)
        self.uc.mem_write(self.sample.BASE_ADDR, self.sample.loaded_image)

        self.setup_processinfo()

        # Load DLLs
        self.load_dll(f"{os.path.dirname(unipacker.__file__)}/DLLs/KernelBase.dll", 0x73D00000)
        self.load_dll(f"{os.path.dirname(unipacker.__file__)}/DLLs/kernel32.dll", 0x755D0000)
        self.load_dll(f"{os.path.dirname(unipacker.__file__)}/DLLs/ntdll.dll", 0x77400000)

        # initialize machine registers
        self.uc.mem_map(self.STACK_ADDR, self.STACK_SIZE)
        self.uc.reg_write(UC_X86_REG_ESP, self.STACK_ADDR + int(self.STACK_SIZE / 2))
        self.uc.reg_write(UC_X86_REG_EBP, self.STACK_ADDR + int(self.STACK_SIZE / 2))
        self.uc.mem_write(self.uc.reg_read(UC_X86_REG_ESP) + 0x8, bytes([1]))  # -> PEtite Stack Operations?
        self.uc.reg_write(UC_X86_REG_EAX, self.sample.unpacker.startaddr)
        self.uc.reg_write(UC_X86_REG_EBX, self.PEB_BASE)
        self.uc.reg_write(UC_X86_REG_ECX, self.sample.unpacker.startaddr)
        self.uc.reg_write(UC_X86_REG_EDX, self.sample.unpacker.startaddr)
        self.uc.reg_write(UC_X86_REG_ESI, self.sample.unpacker.startaddr)
        self.uc.reg_write(UC_X86_REG_EDI, self.sample.unpacker.startaddr)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 0x244)

        new_pe = PE(self.uc, self.sample.BASE_ADDR)
        prot_val = lambda x, y: True if x & y != 0 else False
        for s in new_pe.section_list:
            self.sample.atn[(
                s.VirtualAddress + self.sample.BASE_ADDR,
                s.VirtualAddress + self.sample.BASE_ADDR + s.VirtualSize)] = convert_to_string(
                s.Name)
            self.sample.ntp[convert_to_string(s.Name)] = (
                prot_val(s.Characteristics, 0x20000000), prot_val(s.Characteristics, 0x40000000),
                prot_val(s.Characteristics, 0x80000000))

        # for s in pe.sections:
        #    atn[(s.VirtualAddress + self.sample.BASE_ADDR, s.VirtualAddress + self.sample.BASE_ADDR + s.Misc_VirtualSize)] = s.Name
        #    ntp[s.Name] = (s.IMAGE_SCN_MEM_EXECUTE, s.IMAGE_SCN_MEM_READ, s.IMAGE_SCN_MEM_WRITE)

        # init syscall handling and prepare hook memory for return values
        self.apicall_handler = WinApiCalls(self)
        self.uc.mem_map(self.HOOK_ADDR, 0x1000)
        # self.sample.unpacker.secs += [{"name": "hooks", "vaddr": self.HOOK_ADDR, "vsize": 0x1000}]
        hook_sec_header = IMAGE_SECTION_HEADER(
            "hooks".encode('ascii'),
            0x1000,
            self.HOOK_ADDR,
            0x1000,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        self.sample.unpacker.secs.append(SectionHeader(stack_sec_header))

        hexstr = bytes.fromhex('000000008b0425') + struct.pack('<I', self.HOOK_ADDR) + bytes.fromhex(
            'c3')  # mov eax, [HOOK]; ret -> values of syscall are stored in eax
        self.uc.mem_write(self.HOOK_ADDR, hexstr)

        # handle imports
        # TODO Update when custom loader available
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            descriptor = ImportDescriptor(None, lib.struct.Characteristics, lib.struct.TimeDateStamp,
                                          lib.struct.ForwarderChain, lib.struct.Name, lib.struct.FirstThunk)
            fct_list = []
            for i in lib.imports:
                fct_list.append(i.name)
            imp = Import(descriptor, lib.dll.decode('ascii'), fct_list)
            self.sample.original_imports.append(imp)
            for func in lib.imports:
                func_name = func.name.decode() if func.name is not None else f"no name: 0x{func.address:02x}"
                dll_name = lib.dll.decode() if lib.dll is not None else "-- unknown --"
                self.sample.imports.add(func_name)
                curr_hook_addr = self.apicall_handler.add_hook(self.uc, func_name, dll_name)
                self.uc.mem_write(func.address, struct.pack('<I', curr_hook_addr))

        hdr = PE(self.uc, self.sample.BASE_ADDR)

        # Patch DLLs with hook
        # Hardcoded values used for speed improvement -> Offsets can be calculated with utils.calc_export_offset_of_dll
        self.apicall_handler.add_hook(self.uc, "VirtualProtect", "KernelBase.dll", 0x73D00000 + 0x1089f0)
        self.apicall_handler.add_hook(self.uc, "VirtualAlloc", "KernelBase.dll", 0x73D00000 + 0xd4600)
        self.apicall_handler.add_hook(self.uc, "VirtualFree", "KernelBase.dll", 0x73D00000 + 0xd4ae0)
        self.apicall_handler.add_hook(self.uc, "LoadLibraryA", "KernelBase.dll", 0x73D00000 + 0xf20d0)
        self.apicall_handler.add_hook(self.uc, "GetProcAddress", "KernelBase.dll", 0x73D00000 + 0x102870)

        self.apicall_handler.add_hook(self.uc, "VirtualProtect", "kernel32.dll", 0x755D0000 + 0x16760)
        self.apicall_handler.add_hook(self.uc, "VirtualAlloc", "kernel32.dll", 0x755D0000 + 0x166a0)
        self.apicall_handler.add_hook(self.uc, "VirtualFree", "kernel32.dll", 0x755D0000 + 0x16700)
        self.apicall_handler.add_hook(self.uc, "LoadLibraryA", "kernel32.dll", 0x755D0000 + 0x157b0)
        self.apicall_handler.add_hook(self.uc, "GetProcAddress", "kernel32.dll", 0x755D0000 + 0x14ee0)

        # Add hooks
        self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH, self.hook_mem_access)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)


if __name__ == '__main__':
    from unipacker.shell import Shell

    Shell()
