import struct

import pefile
from unicorn.x86_const import *


class WinApiCalls(object):

    def __init__(self, base_addr, virtualmemorysize, hook_addr, breakpoints, sample):
        self.apicall_mapping = {
            "IsDebuggerPresent": self.IsDebuggerPresent,
            "VirtualProtect": self.VirtualProtect,
            "GlobalAlloc": self.GlobalAlloc,
            "GetModuleHandleA": self.GetModuleHandleA,
            "VirtualAlloc": self.VirtualAlloc,
            "VirtualFree": self.VirtualFree,
            "GetProcAddress": self.GetProcAddress,
            "LoadLibraryA": self.LoadLibraryA,
            "LoadLibraryW": self.LoadLibraryA
        }
        self.base_addr = base_addr
        self.virtualmemorysize = virtualmemorysize
        self.hook_addr = hook_addr
        self.next_hook_offset = 4
        self.hooks = {}
        self.module_handle_offset = 0
        self.module_handles = {}
        self.module_for_function = {}
        self.dynamic_mem_offset = 0x4000
        self.alloc_size = {}
        self.pending_breakpoints = set()
        self.breakpoints = breakpoints
        self.sample = sample

    def apicall(self, name, uc, esp, log):
        return self.apicall_mapping[name](uc, esp, log)

    def IsDebuggerPresent(self, uc, esp, log):
        """No arguments"""
        return 0, esp

    def VirtualProtect(self, uc, esp, log):
        """4 arguments, we have to clean up"""
        eip, address, size, new_protect, old_protect_ptr = struct.unpack("<IIIII", uc.mem_read(esp, 20))
        log and print(f"VirtualProtect: address 0x{address:02x}, size 0x{size:02x}, mode 0x{new_protect:02x}, "
                      f"write old mode to 0x{old_protect_ptr:02x}")
        uc.mem_write(esp + 16, struct.pack("<I", eip))
        return new_protect, esp + 16

    def GlobalAlloc(self, uc, esp, log):
        """2 arguments, we have to clean up"""
        eip, flags, size = struct.unpack("<III", uc.mem_read(esp, 12))
        log and print(f"GlobalAlloc: eip 0x{eip:02x} flags 0x{flags:02x}, size 0x{size:02x}")
        uc.mem_write(esp + 8, struct.pack("<I", eip))
        aligned_address = self.alloc(log, size, uc)
        return aligned_address, esp + 8

    def GetModuleHandleA(self, uc, esp, log):
        """1 argument, we have to clean up"""
        eip, module_name_ptr = struct.unpack("<II", uc.mem_read(esp, 8))
        module_name = self.get_string(module_name_ptr, uc)
        log and print(f"GetModuleHandleA: 0x{eip:02x} module_name_ptr 0x{module_name_ptr:02x}: {module_name}")
        uc.mem_write(esp + 4, struct.pack("<I", eip))

        if not module_name_ptr:
            pe = pefile.PE(self.sample)
            loaded = pe.get_memory_mapped_image(ImageBase=self.base_addr)
            handle = self.alloc(log, len(loaded), uc)
            uc.mem_write(handle, loaded)
            return handle, esp + 4
        handle = self.base_addr + self.module_handle_offset
        self.module_handle_offset += 1
        self.module_handles[handle] = self.get_string(module_name_ptr, uc)
        return handle, esp + 4

    def get_string(self, ptr, uc):
        module_name = ""
        i = 0
        while True:
            item, = struct.unpack("c", uc.mem_read(ptr + i, 1))
            if item == b"\x00":
                break
            module_name += chr(item[0])
            i += 1
        return module_name

    def VirtualAlloc(self, uc, esp, log):
        eip, address, size, t, protection = struct.unpack("<IIIII", uc.mem_read(esp, 20))
        log and print(
            f"VirtualAlloc: 0x{eip:02x} address: 0x{address:02x}, size 0x{size:02x}, type 0x{t:02x}, protection 0x{protection:02x}")
        uc.mem_write(esp + 16, struct.pack("<I", eip))
        if address == 0:
            aligned_address = self.alloc(log, size, uc)
            uc.reg_write(UC_X86_REG_EAX, aligned_address)
            return aligned_address, esp + 16
        else:
            log and print("\tSpecific address requested")
            return 0, esp + 16

    def alloc(self, log, size, uc):
        padding = 4 * 1024
        m = size % padding
        f = padding - m
        aligned_size = size + f
        log and print(f"\tUnaligned size: {size:02x}, by {m:02x} bytes. Aligned size: {aligned_size:02x}")
        new_offset = self.base_addr + self.virtualmemorysize + self.dynamic_mem_offset
        self.dynamic_mem_offset += aligned_size + 0x1000
        new_offset_m = new_offset % padding
        aligned_address = new_offset - new_offset_m
        uc.mem_map(aligned_address, aligned_size)
        log and print(f"\tfrom {aligned_address:02x} to {(aligned_address + aligned_size):02x}")
        self.alloc_size[aligned_address] = aligned_size
        return aligned_address

    def VirtualFree(self, uc, esp, log):
        eip, address, size, free_type = struct.unpack("<IIII", uc.mem_read(esp, 16))
        uc.mem_write(esp + 12, struct.pack("<I", eip))
        if address not in self.alloc_size:
            return 0, esp + 12
        else:
            uc.mem_unmap(address, self.alloc_size[address])
            return 1, esp + 12

    def GetProcAddress(self, uc, esp, log):
        eip, module_handle, proc_name_ptr = struct.unpack("<III", uc.mem_read(esp, 12))
        proc_name = self.get_string(proc_name_ptr, uc)
        try:
            module_name = self.module_handles[module_handle]
        except KeyError:
            module_name = "?"
        log and print(
            f"GetProcAddress: 0x{eip:02x} module handle 0x{module_handle:02x}: {module_name}, proc_name_ptr 0x{proc_name_ptr}: {proc_name}")

        hook_addr = None
        for addr, name in self.hooks.items():
            if name == proc_name:
                hook_addr = addr
                log and print(f"\tRe-used previously added hook at 0x{hook_addr:02x}")
        if hook_addr is None:
            hook_addr = self.add_hook(uc, proc_name, module_name)
            log and print(f"\tAdded new hook at 0x{hook_addr:02x}")
        if proc_name in self.pending_breakpoints:
            print(f"Pending breakpoint attached for new dynamic import {proc_name} at 0x{hook_addr:02x}")
            self.breakpoints.add(hook_addr)
            self.pending_breakpoints.remove(proc_name)
        uc.mem_write(esp + 8, struct.pack("<I", eip))
        return hook_addr, esp + 8

    def LoadLibraryA(self, uc, esp, log):
        eip, mod_name_ptr = struct.unpack("<II", uc.mem_read(esp, 8))
        mod_name = self.get_string(mod_name_ptr, uc)
        log and print(f"LoadLibraryA: 0x{eip:02x} mod_name_ptr 0x{mod_name_ptr}: {mod_name}")
        uc.mem_write(esp + 4, struct.pack("<I", eip))

        handle = self.base_addr + self.module_handle_offset
        self.module_handle_offset += 1
        self.module_handles[handle] = self.get_string(mod_name_ptr, uc)
        log and print(f"\tHandle: 0x{handle:02x}")
        return handle, esp + 4

    def add_hook(self, uc, name, module_name):
        curr_hook_addr = self.hook_addr + self.next_hook_offset
        hexstr = bytes.fromhex('8b0425') + struct.pack('<I', self.hook_addr) + bytes.fromhex(
            'c3')  # mov eax, [HOOK]; ret -> values of syscall are stored in eax
        uc.mem_write(curr_hook_addr, hexstr)
        self.hooks[curr_hook_addr] = name
        self.module_for_function[name] = module_name
        self.next_hook_offset += len(hexstr)
        return curr_hook_addr

    def register_pending_breakpoint(self, target):
        self.pending_breakpoints.add(target)
