import os
import struct
import sys
import threading
from time import time

import pefile
import r2pipe
from unicorn import *
from unicorn.x86_const import *

from apicalls import WinApiCalls
from headers import PE
from kernel_structs import TEB, PEB, PEB_LDR_DATA, LIST_ENTRY
from unpackers import get_unpacker
from utils import merge, align, convert_to_string, InvalidPEFile


class State(object):

    def __init__(self):
        self.imports = set()
        self.uc = None
        self.sample = None
        self.unpacker = None
        self.yara_matches = None
        self.virtualmemorysize = 0
        self.loaded_image = 0
        self.BASE_ADDR = 0
        self.HOOK_ADDR = 0
        self.STACK_ADDR = 0
        self.STACK_SIZE = 0
        self.PEB_BASE = 0
        self.TEB_BASE = 0

        self.section_hopping_control = True
        self.write_execute_control = False

        self.breakpoints = set()
        self.mem_breakpoints = []
        self.data_lock = threading.Lock()
        self.instruction_lock = threading.Lock()  # TODO unused, do we need this?
        self.single_instruction = False
        self.apicall_handler = None
        self.startaddr = 0
        self.endaddr = 0

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


class Sample(object):

    def __init__(self, path, auto_default_unpacker=True):
        self.path = path
        self.unpacker, self.yara_matches = get_unpacker(path, auto_default_unpacker)

    def __str__(self):
        return f"Sample: [{self.yara_matches[-1]}] {self.path}"

    @staticmethod
    def get_samples(path):
        if os.path.isdir(path):
            response = input("Automatically find packer entry and exit points for unknown packers? [Y/n]: ")
            auto_default_unpacker = not response or response.lower().startswith("y")
            for file in os.listdir(path):
                try:
                    sample = Sample(os.path.join(path, file), auto_default_unpacker)
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


class UnpackerEngine(object):

    def __init__(self, state, sample):
        self.state = state
        self.sample = sample
        self.clients = []

        self.emulator_event = threading.Event()
        self.single_instruction = False

        self.state.startaddr = self.sample.unpacker.get_entrypoint()
        self.state.endaddr, _ = self.sample.unpacker.get_tail_jump()
        self.state.write_execute_control = self.sample.unpacker.write_execute_control
        self.state.section_hopping_control = self.sample.unpacker.section_hopping_control

        self.init_uc()

    def register_client(self, client):
        self.clients += [client]

    def pause(self):
        for client in self.clients:
            client.emu_paused()
        self.emulator_event.clear()
        self.emulator_event.wait()

    def stop(self):
        self.state.uc.emu_stop()
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
        r2 = r2pipe.open(self.sample.path)
        sections = r2.cmdj("iSj")
        min_offset = sys.maxsize
        total_size = 0
        for sec in sections:
            if sec['vaddr'] < min_offset:
                min_offset = sec['vaddr']
            if 'vsize' in sec:
                total_size += sec['vsize']
        r2.quit()
        total_size += (min_offset - self.state.BASE_ADDR)

        return total_size

    def entrypoint(self, pe):
        return pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase

    def hook_code(self, uc, address, size, user_data):
        self.update_address(address)
        self.emulator_event.wait()

        with self.state.data_lock:
            breakpoint_hit = address in self.state.breakpoints
        if breakpoint_hit:
            print("\x1b[31mBreakpoint hit!\x1b[0m")
            self.pause()
        if address == self.state.endaddr:
            print("\x1b[31mEnd address hit! Unpacking should be done\x1b[0m")
            self.sample.unpacker.dump(uc, self.state.apicall_handler)
            self.pause()

        if self.state.write_execute_control and address not in self.state.apicall_handler.hooks and (
                address < self.state.HOOK_ADDR or address > self.state.HOOK_ADDR + 0x1000):
            if any(lower <= address <= upper for (lower, upper) in sorted(self.state.write_targets)):
                print(f"\x1b[31mTrying to execute at 0x{address:02x}, which has been written to before!\x1b[0m")
                self.sample.unpacker.dump(uc, self.state.apicall_handler)
                self.pause()

        if self.state.section_hopping_control and address not in self.state.apicall_handler.hooks and address - 0x7 not in self.state.apicall_handler.hooks and (
                address < self.state.HOOK_ADDR or address > self.state.HOOK_ADDR + 0x1000):  # address-0x7 corresponding RET
            if not self.sample.unpacker.is_allowed(address):
                sec_name = self.sample.unpacker.get_section(address)
                print(f"\x1b[31mSection hopping detected into {sec_name}! Address: " + hex(address) + "\x1b[0m")
                self.sample.unpacker.allow(address)
                self.sample.unpacker.dump(uc, self.state.apicall_handler)
                self.pause()

        curr_section = self.sample.unpacker.get_section(address)
        if curr_section not in self.state.sections_executed:
            self.state.sections_executed[curr_section] = 1
        else:
            self.state.sections_executed[curr_section] += 1

        if address in self.state.apicall_handler.hooks:
            esp = uc.reg_read(UC_X86_REG_ESP)
            api_call_name = self.state.apicall_handler.hooks[address]
            ret, esp = self.state.apicall_handler.apicall(address, api_call_name, uc, esp, self.state.log_apicalls)

            if api_call_name not in self.state.apicall_counter:
                self.state.apicall_counter[api_call_name] = 1
            else:
                self.state.apicall_counter[api_call_name] += 1
            if ret is not None:  # might be a void function
                uc.mem_write(self.state.HOOK_ADDR, struct.pack("<I", ret))
            uc.reg_write(UC_X86_REG_ESP, esp)
        self.state.log_instr and print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))

        if self.single_instruction:
            self.pause()

    # Method is executed before memory access
    def hook_mem_access(self, uc, access, address, size, value, user_data):
        curr_section = self.sample.unpacker.get_section(address)
        access_type = ""
        if access == UC_MEM_READ:
            access_type = "READ"
            if curr_section not in self.state.sections_read:
                self.state.sections_read[curr_section] = 1
            else:
                self.state.sections_read[curr_section] += 1
            self.state.log_mem_read and print(">>> Memory is being READ at 0x%x, data size = %u" % (address, size))
        elif access == UC_MEM_WRITE:
            access_type = "WRITE"
            self.state.write_targets = list(merge(self.state.write_targets + [(address, address + size)]))
            if curr_section not in self.state.sections_written:
                self.state.sections_written[curr_section] = 1
            else:
                self.state.sections_written[curr_section] += 1
            self.state.log_mem_write and print(
                ">>> Memory is being WRITTEN at 0x%x, data size = %u, data value = 0x%x" % (address, size, value))
        else:
            for access_name, val in unicorn_const.__dict__.items():
                if val == access and "UC_MEM" in access_name:
                    access_type = access_name[6:]  # remove UC_MEM from the access type
                    print(f"Unexpected mem access type {access_type}, addr: 0x{address:02x}")
        if any(lower <= address <= upper for lower, upper in self.state.mem_breakpoints):
            print(f"\x1b[31mMemory breakpoint hit! Access {access_type} to 0x{address:02x}")
            self.pause()

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        for access_name, val in unicorn_const.__dict__.items():
            if val == access and "UC_MEM" in access_name:
                print(f"Invalid memory access {access_name}, addr: 0x{address:02x}")
                self.state.uc.emu_stop()
                return

    def emu(self):
        try:
            for client in self.clients:
                client.emu_started()
            self.emulator_event.set()
            self.state.start = time()
            if self.state.endaddr == sys.maxsize:
                print(f"Emulation starting at {hex(self.state.startaddr)}")
            else:
                print(f"Emulation starting. Bounds: from {hex(self.state.startaddr)} to {hex(self.state.endaddr)}")
            # Start emulation from self.state.startaddr
            self.state.uc.emu_start(self.state.startaddr, sys.maxsize)
        except UcError as e:
            print(f"Error: {e}")
        finally:
            self.stopped()
            self.emulator_event.clear()

    def setup_processinfo(self):
        self.state.TEB_BASE = 0x200000
        self.state.PEB_BASE = self.state.TEB_BASE + 0x1000
        LDR_PTR = self.state.PEB_BASE + 0x1000
        LIST_ENTRY_BASE = LDR_PTR + 0x1000

        teb = TEB(
            -1,  # fs:00h
            self.state.STACK_ADDR + self.state.STACK_SIZE,  # fs:04h
            self.state.STACK_ADDR,  # fs:08h
            0,  # fs:0ch
            0,  # fs:10h
            0,  # fs:14h
            self.state.TEB_BASE,  # fs:18h (teb base)
            0,  # fs:1ch
            0xdeadbeef,  # fs:20h (process id)
            0xdeadbeef,  # fs:24h (current thread id)
            0,  # fs:28h
            0,  # fs:2ch
            self.state.PEB_BASE,  # fs:3ch (peb base)
        )

        peb = PEB(
            0,
            0,
            0,
            0,
            0xffffffff,
            self.state.BASE_ADDR,
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

        self.state.uc.mem_map(self.state.TEB_BASE, align(0x5000))
        self.state.uc.mem_write(self.state.TEB_BASE, teb_payload)
        self.state.uc.mem_write(self.state.PEB_BASE, peb_payload)
        self.state.uc.mem_write(LDR_PTR, ldr_payload)
        self.state.uc.mem_write(LIST_ENTRY_BASE, ntdll_payload)
        self.state.uc.mem_write(LIST_ENTRY_BASE + 12, kernelbase_payload)
        self.state.uc.mem_write(LIST_ENTRY_BASE + 24, kernel32_payload)
        self.state.uc.windows_tib = self.state.TEB_BASE

    def load_dll(self, path_dll, start_addr):
        filename = os.path.splitext(os.path.basename(path_dll))[0]
        if not os.path.exists(f"DLLs/{filename}.ldll"):
            dll = pefile.PE(path_dll)
            loaded_dll = dll.get_memory_mapped_image(ImageBase=start_addr)
            with open(f"DLLs/{filename}.ldll", 'wb') as f:
                f.write(loaded_dll)
            self.state.uc.mem_map(start_addr, align(len(loaded_dll) + 0x1000))
            self.state.uc.mem_write(start_addr, loaded_dll)
        else:
            with open(f"DLLs/{filename}.ldll", 'rb') as dll:
                loaded_dll = dll.read()
                self.state.uc.mem_map(start_addr, align((len(loaded_dll) + 0x1000)))
                self.state.uc.mem_write(start_addr, loaded_dll)

    def init_uc(self):
        # Calculate required memory
        pe = pefile.PE(self.sample.path)
        self.state.BASE_ADDR = pe.OPTIONAL_HEADER.ImageBase  # 0x400000
        self.sample.unpacker.BASE_ADDR = self.state.BASE_ADDR
        self.state.virtualmemorysize = self.getVirtualMemorySize()
        self.state.STACK_ADDR = 0x0
        self.state.STACK_SIZE = 1024 * 1024
        STACK_START = self.state.STACK_ADDR + self.state.STACK_SIZE
        self.sample.unpacker.secs += [{"name": "stack", "vaddr": self.state.STACK_ADDR, "vsize": self.state.STACK_SIZE}]
        self.state.HOOK_ADDR = STACK_START + 0x3000 + 0x1000

        # Start unicorn emulator with x86-32bit architecture
        self.state.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        if self.state.startaddr is None:
            self.state.startaddr = self.entrypoint(pe)
        self.state.loaded_image = pe.get_memory_mapped_image(ImageBase=self.state.BASE_ADDR)
        self.state.virtualmemorysize = align(self.state.virtualmemorysize + 0x10000,
                                             page_size=4096)  # Space possible IAT rebuilding
        self.sample.unpacker.virtualmemorysize = self.state.virtualmemorysize
        self.state.uc.mem_map(self.state.BASE_ADDR, self.state.virtualmemorysize)
        self.state.uc.mem_write(self.state.BASE_ADDR, self.state.loaded_image)

        self.setup_processinfo()

        # Load DLLs
        self.load_dll("DLLs/KernelBase.dll", 0x73D00000)
        self.load_dll("DLLs/kernel32.dll", 0x755D0000)
        self.load_dll("DLLs/ntdll.dll", 0x77400000)

        # initialize machine registers
        self.state.uc.mem_map(self.state.STACK_ADDR, self.state.STACK_SIZE)
        self.state.uc.reg_write(UC_X86_REG_ESP, self.state.STACK_ADDR + int(self.state.STACK_SIZE / 2))
        self.state.uc.reg_write(UC_X86_REG_EBP, self.state.STACK_ADDR + int(self.state.STACK_SIZE / 2))
        self.state.uc.mem_write(self.state.uc.reg_read(UC_X86_REG_ESP) + 0x8, bytes([1]))
        self.state.uc.reg_write(UC_X86_REG_ECX, self.state.startaddr)
        self.state.uc.reg_write(UC_X86_REG_EDX, self.state.startaddr)
        self.state.uc.reg_write(UC_X86_REG_ESI, self.state.startaddr)
        self.state.uc.reg_write(UC_X86_REG_EDI, self.state.startaddr)

        # setup section dict used for custom memory protection
        atn = {}  # Dict Address to Name: (StartVAddr, EndVAddr) -> Name
        ntp = {}  # Dict Name to Protection Tupel: Name -> (Execute, Read, Write)

        new_pe = PE(self.state.uc, self.state.BASE_ADDR)
        prot_val = lambda x, y: True if x & y != 0 else False
        for s in new_pe.section_list:
            atn[(
                s.VirtualAddress + self.state.BASE_ADDR,
                s.VirtualAddress + self.state.BASE_ADDR + s.VirtualSize)] = convert_to_string(
                s.Name)
            ntp[convert_to_string(s.Name)] = (
                prot_val(s.Characteristics, 0x20000000), prot_val(s.Characteristics, 0x40000000),
                prot_val(s.Characteristics, 0x80000000))

        # for s in pe.sections:
        #    atn[(s.VirtualAddress + self.state.BASE_ADDR, s.VirtualAddress + self.state.BASE_ADDR + s.Misc_VirtualSize)] = s.Name
        #    ntp[s.Name] = (s.IMAGE_SCN_MEM_EXECUTE, s.IMAGE_SCN_MEM_READ, s.IMAGE_SCN_MEM_WRITE)

        # init syscall handling and prepare hook memory for return values
        self.state.apicall_handler = WinApiCalls(self.state.BASE_ADDR, self.state.virtualmemorysize,
                                                 self.state.HOOK_ADDR, self.state.breakpoints,
                                                 self.sample.path, atn, ntp)
        self.state.uc.mem_map(self.state.HOOK_ADDR, 0x1000)
        self.sample.unpacker.secs += [{"name": "hooks", "vaddr": self.state.HOOK_ADDR, "vsize": 0x1000}]
        hexstr = bytes.fromhex('000000008b0425') + struct.pack('<I', self.state.HOOK_ADDR) + bytes.fromhex(
            'c3')  # mov eax, [HOOK]; ret -> values of syscall are stored in eax
        self.state.uc.mem_write(self.state.HOOK_ADDR, hexstr)

        # handle imports
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for func in lib.imports:
                func_name = func.name.decode() if func.name is not None else f"no name: 0x{func.address:02x}"
                dll_name = lib.dll.decode() if lib.dll is not None else "-- unknown --"
                self.state.imports.add(func_name)
                curr_hook_addr = self.state.apicall_handler.add_hook(self.state.uc, func_name, dll_name)
                self.state.uc.mem_write(func.address, struct.pack('<I', curr_hook_addr))

        hdr = PE(self.state.uc, self.state.BASE_ADDR)

        # TODO below new version but needs testing as it is crashing
        # import_table = get_imp(self.state.uc, hdr.data_directories[1].VirtualAddress, self.state.BASE_ADDR, hdr.data_directories[1].Size, True)
        # for lib in import_table:
        #    for func_name, func_addr in lib.imports:
        #        func_name = func_name if func_name is not None else f"no name: 0x{func_addr:02x}"
        #        dll_name = lib.Name if lib.Name is not None else "-- unknown --"
        #        self.state.imports.add(func_name)
        #        curr_hook_addr = self.state.apicall_handler.add_hook(self.state.uc, func_name, dll_name)
        #        self.state.uc.mem_write(func_addr, struct.pack('<I', curr_hook_addr))

        # Patch DLLs with hook
        # Hardcoded values used for speed improvement -> Offsets can be calculated with utils.calc_export_offset_of_dll
        self.state.apicall_handler.add_hook(self.state.uc, "VirtualProtect", "KernelBase.dll", 0x73D00000 + 0x1089f0)
        self.state.apicall_handler.add_hook(self.state.uc, "VirtualAlloc", "KernelBase.dll", 0x73D00000 + 0xd4600)
        self.state.apicall_handler.add_hook(self.state.uc, "VirtualFree", "KernelBase.dll", 0x73D00000 + 0xd4ae0)
        self.state.apicall_handler.add_hook(self.state.uc, "LoadLibraryA", "KernelBase.dll", 0x73D00000 + 0xf20d0)
        self.state.apicall_handler.add_hook(self.state.uc, "GetProcAddress", "KernelBase.dll", 0x73D00000 + 0x102870)

        self.state.apicall_handler.add_hook(self.state.uc, "VirtualProtect", "kernel32.dll", 0x755D0000 + 0x16760)
        self.state.apicall_handler.add_hook(self.state.uc, "VirtualAlloc", "kernel32.dll", 0x755D0000 + 0x166a0)
        self.state.apicall_handler.add_hook(self.state.uc, "VirtualFree", "kernel32.dll", 0x755D0000 + 0x16700)
        self.state.apicall_handler.add_hook(self.state.uc, "LoadLibraryA", "kernel32.dll", 0x755D0000 + 0x157b0)
        self.state.apicall_handler.add_hook(self.state.uc, "GetProcAddress", "kernel32.dll", 0x755D0000 + 0x14ee0)

        # Add hooks
        self.state.uc.hook_add(UC_HOOK_CODE, self.hook_code)
        self.state.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH, self.hook_mem_access)
        self.state.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)


if __name__ == '__main__':
    from shell import Shell

    Shell()
