import struct
from inspect import signature

import pefile
from unicorn.x86_const import UC_X86_REG_EAX

from utils import align, merge, remove_range, print_cols, get_string

apicall_mapping = {}


def api_call(*names):
    def apicall_wrapper(func):
        def wrapper(self, uc, esp, log, *args):
            # get the return address and the emulated args from the stack (total: 4B ret_addr + 4B * #args)
            num_args = len(signature(func).parameters) - 4  # self, uc, esp and log are not of interest
            ret_addr, *args = struct.unpack(f"<I{'I' * num_args}", uc.mem_read(esp, 4 * (num_args + 1)))

            # let the API call see the original stack
            original_esp = esp + 4 * (num_args + 1)
            # pass the collected arguments to the API call and retrieve the return value
            ret_value = func(self, uc, original_esp, log, *args)
            log and print(f"\tReturn address: 0x{ret_addr:02x}")

            # re-place the return address on the stack (decrements esp by 4)
            uc.mem_write(original_esp - 4, struct.pack("<I", ret_addr))
            return ret_value, original_esp - 4

        if not names:
            apicall_mapping[func.__name__] = wrapper
        else:
            for name in names:
                apicall_mapping[name] = wrapper
        return wrapper

    return apicall_wrapper


class WinApiCalls(object):

    def __init__(self, base_addr, virtualmemorysize, hook_addr, breakpoints, sample):
        self.base_addr = base_addr
        self.virtualmemorysize = virtualmemorysize
        self.hook_addr = hook_addr
        self.next_hook_offset = 4
        self.hooks = {}
        self.module_handle_offset = 0
        self.module_handles = {}
        self.module_for_function = {}
        self.dynamic_mem_offset = self.base_addr + self.virtualmemorysize + 0x4000
        self.allocated_chunks = []
        self.alloc_sizes = {}
        self.pending_breakpoints = set()
        self.breakpoints = breakpoints
        self.sample = sample
        self.heaps = {}
        self.next_heap_handle = self.hook_addr + 0x10000

    def apicall(self, address, name, uc, esp, log):
        try:
            return apicall_mapping[name](self, uc, esp, log)
        except KeyError:
            args = struct.unpack("<IIIIII", uc.mem_read(esp + 4, 24))
            print(f"Unimplemented API call at 0x{address:02x}: {name}, first 6 stack items: {list(map(hex, args))}")
            return 0, esp

    @api_call()
    def IsDebuggerPresent(self, uc, esp, log):
        """Not present, of course"""
        return 0

    @api_call()
    def VirtualProtect(self, uc, esp, log, address, size, new_protect, old_protect_ptr):
        log and print(f"VirtualProtect: address 0x{address:02x}, size 0x{size:02x}, mode 0x{new_protect:02x}, "
                      f"write old mode to 0x{old_protect_ptr:02x}")
        return new_protect

    @api_call()
    def GlobalAlloc(self, uc, esp, log, flags, size):
        log and print(f"GlobalAlloc: flags 0x{flags:02x}, size 0x{size:02x}")
        aligned_address = self.alloc(log, size, uc)
        return aligned_address

    @api_call()
    def GetModuleHandleA(self, uc, esp, log, module_name_ptr):
        module_name = get_string(module_name_ptr, uc)
        log and print(f"GetModuleHandleA: module_name_ptr 0x{module_name_ptr:02x}: {module_name}")

        if not module_name_ptr:
            pe = pefile.PE(self.sample)
            loaded = pe.get_memory_mapped_image(ImageBase=self.base_addr)
            handle = self.alloc(log, len(loaded), uc)
            uc.mem_write(handle, loaded)
            return handle, esp + 4
        handle = self.base_addr + self.module_handle_offset
        self.module_handle_offset += 1
        self.module_handles[handle] = get_string(module_name_ptr, uc)
        return handle

    @api_call()
    def VirtualAlloc(self, uc, esp, log, address, size, t, protection):
        log and print(
            f"VirtualAlloc: address: 0x{address:02x}, size 0x{size:02x}, type 0x{t:02x}, protection 0x{protection:02x}")
        if address == 0:
            offset = None
        else:
            offset = address
        aligned_address = self.alloc(log, size, uc, offset)
        uc.reg_write(UC_X86_REG_EAX, aligned_address)
        return aligned_address

    def alloc(self, log, size, uc, offset=None):
        page_size = 4 * 1024
        aligned_size = align(size, page_size)
        log and print(f"\tUnaligned size: 0x{size:02x}, aligned size: 0x{aligned_size:02x}")
        if offset is None:
            for chunk_start, chunk_end in self.allocated_chunks:
                if chunk_start <= self.dynamic_mem_offset <= chunk_end:
                    # we have to push back the dynamic mem offset as it is inside an already allocated chunk!
                    self.dynamic_mem_offset = chunk_end + 1
            offset = self.dynamic_mem_offset
            self.dynamic_mem_offset += aligned_size
        new_offset_m = offset % page_size
        aligned_address = offset - new_offset_m

        # check if we have mapped parts of it already
        mapped_partial = False
        for chunk_start, chunk_end in self.allocated_chunks:
            if chunk_start <= aligned_address < chunk_end:
                if aligned_address + aligned_size <= chunk_end:
                    log and print(f"\tAlready fully mapped")
                else:
                    log and print(
                        f"\tMapping missing piece 0x{chunk_end + 1:02x} to 0x{aligned_address + aligned_size:02x}")
                    uc.mem_map(chunk_end, aligned_address + aligned_size - chunk_end)
                mapped_partial = True
                break

        if not mapped_partial:
            uc.mem_map(aligned_address, aligned_size)
        log and print(f"\tfrom 0x{aligned_address:02x} to 0x{(aligned_address + aligned_size):02x}")
        self.allocated_chunks = list(merge(self.allocated_chunks + [(aligned_address, aligned_address + aligned_size)]))
        log and self.print_allocs()
        self.alloc_sizes[aligned_address] = aligned_size
        return aligned_address

    @api_call()
    def VirtualFree(self, uc, esp, log, address, size, free_type):
        log and print(f"VirtualFree: chunk to free: 0x{address:02x}, size 0x{size:02x}, type 0x{free_type:02x}")
        new_chunks = []
        success = False
        for start, end in sorted(self.allocated_chunks):
            if start <= address <= end:
                if free_type & 0x8000 and size == 0:  # MEM_RELEASE, clear whole allocated range
                    if address in self.alloc_sizes:
                        end_addr = self.alloc_sizes[address]
                        uc.mem_unmap(address, align(size))
                        new_chunks += remove_range((start, end), (address, end_addr))
                        success = True
                    else:
                        log and print(f"\t0x{address} is not an alloc base address!")
                        new_chunks += [(start, end)]
                elif free_type & 0x4000 and size > 0:  # MEM_DECOMMIT, free requested size
                    end_addr = address + align(size)
                    uc.mem_unmap(address, align(size))
                    new_chunks += remove_range((start, end), (address, end_addr))
                    success = True
                else:
                    log and print("\tIncorrect size + type combination!")
                    new_chunks += [(start, end)]
            else:
                new_chunks += [(start, end)]

        self.allocated_chunks = list(merge(new_chunks))
        log and self.print_allocs()
        if success:
            return 1
        log and print("\tAddress range not allocated!")
        return 0

    @api_call()
    def GetProcAddress(self, uc, esp, log, module_handle, proc_name_ptr):
        proc_name = get_string(proc_name_ptr, uc)
        try:
            module_name = self.module_handles[module_handle]
        except KeyError:
            module_name = "?"
        log and print(
            f"GetProcAddress: module handle 0x{module_handle:02x}: {module_name}, proc_name_ptr 0x{proc_name_ptr:02x}: {proc_name}")

        hook_addr = None
        for addr, name in self.hooks.items():
            if name == proc_name:
                hook_addr = addr
                log and print(f"\tRe-used previously added hook at 0x{hook_addr:02x}")
        if hook_addr is None:
            hook_addr = self.add_hook(uc, proc_name, module_name)
            log and print(f"\tAdded new hook at 0x{hook_addr:02x}")
        if proc_name in self.pending_breakpoints:
            print(f"\x1b[31mPending breakpoint attached for new dynamic import {proc_name} at 0x{hook_addr:02x}\x1b[0m")
            self.breakpoints.add(hook_addr)
            self.pending_breakpoints.remove(proc_name)
        return hook_addr

    @api_call("LoadLibraryA", "LoadLibraryW")
    def LoadLibraryA(self, uc, esp, log, mod_name_ptr):
        # TODO: does not actually load the library
        mod_name = get_string(mod_name_ptr, uc)
        log and print(f"LoadLibraryA: mod_name_ptr 0x{mod_name_ptr}: {mod_name}")

        handle = self.base_addr + self.module_handle_offset
        self.module_handle_offset += 1
        self.module_handles[handle] = get_string(mod_name_ptr, uc)
        log and print(f"\tHandle: 0x{handle:02x}")
        return handle

    @api_call()
    def GetVersion(self, uc, esp, log):
        log and print(f"GetVersion: Returning 6.1 (Windows 7)")
        return 0x00000106

    @api_call()
    def HeapCreate(self, uc, esp, log, options, initial_size, max_size):
        # TODO only creates dummy handles, no actual heap creation
        log and print(
            f"HeapCreate: options 0x{options:02x}, initial size: 0x{initial_size:02x}, max size: 0x{max_size:02x}")
        curr_handle = self.next_heap_handle
        self.next_heap_handle += 1
        self.heaps[curr_handle] = (initial_size, max_size)
        return curr_handle

    @api_call()
    def HeapDestroy(self, uc, esp, log, handle):
        # TODO also operates on dummy handles
        success = self.heaps.pop(handle, None)
        return 1 if success else 0

    @api_call()
    def MessageBoxA(self, uc, esp, log, owner, text_ptr, title_ptr, type):
        text = get_string(text_ptr, uc)
        title = get_string(title_ptr, uc)
        print(f"\x1b[31mMessage Box ({title}): {text}\x1b[0m")
        return 1

    @api_call()
    def GetModuleFileNameA(self, uc, esp, log, handle, path_buf, buf_size):
        if not handle:
            path = "C:/Users/unipacker/hxp.exe"
        else:
            try:
                module_name = self.module_handles[handle]
            except KeyError:
                module_name = "somefakename.dll"
            path = f"C:/Windows/System32/{module_name}"
        log and print(f"GetModuleFileNameA: handle 0x{handle:02x}. Returning {path} into 0x{path_buf}")
        uc.mem_write(path_buf, path.encode())
        return len(path)

    @api_call()
    def GetActiveWindow(self, uc, esp, log):
        log and print(f"GetActiveWindow: Returning 1")
        return 1

    @api_call()
    def GetLastActivePopup(self, uc, esp, log, handle):
        log and print(f"GetLastActivePopup: owner handle 0x{handle:02x}")
        return handle, esp + 4

    @api_call()
    def InitializeCriticalSection(self, uc, esp, log, section_ptr):
        log and print(f"InitializeCriticalSection: pointer 0x{section_ptr:02x}, doing nothing")

    def add_hook(self, uc, name, module_name, curr_hook_addr=None):
        hexstr = bytes.fromhex('8b0425') + struct.pack('<I', self.hook_addr) + bytes.fromhex(
            'c3')  # mov eax, [HOOK]; ret -> values of syscall are stored in eax
        if curr_hook_addr is None:
            curr_hook_addr = self.hook_addr + self.next_hook_offset
            self.next_hook_offset += len(hexstr)
        uc.mem_write(curr_hook_addr, hexstr)
        self.hooks[curr_hook_addr] = name
        self.module_for_function[name] = module_name
        return curr_hook_addr

    def register_pending_breakpoint(self, target):
        self.pending_breakpoints.add(target)

    def print_allocs(self):
        print("Currently allocated:")
        lines = []
        for start, end in self.allocated_chunks:
            lines += [(hex(start), "-", hex(end))]
        print_cols(lines)
