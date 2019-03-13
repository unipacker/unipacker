import collections

import pefile
import os
from unicorn.x86_const import *
import struct


class ImageDump(object):

    def fix_section(self, section, next_section_vaddr):
        sec_name = section.Name.decode().strip("\x00")
        print(f"Size of raw data ({sec_name}): 0x{section.SizeOfRawData:02x}, "
              f"fixed: 0x{next_section_vaddr - section.VirtualAddress:02x}")
        section.SizeOfRawData = next_section_vaddr - section.VirtualAddress
        section.PointerToRawData = section.VirtualAddress

    def set_protections(self, section, protection):
        x, r, w = protection
        section.IMAGE_SCN_MEM_EXECUTE = x
        section.IMAGE_SCN_MEM_READ = r
        section.IMAGE_SCN_MEM_WRITE = w

    def fix_section_mem_protection(self, pe, ntp):
        for s in pe.sections:
            if s.Name in ntp:
                self.set_protections(s, ntp[s.Name])

    # Returns list of addresses where search has been found
    def find_occurences(self, binary, search):
        occ = []
        if isinstance(search, str):
            search = bytes(search, 'ascii')
        x = binary.find(search)
        while x != -1:
            occ.append(x)
            x = binary.find(search, (x+1), len(binary))
        return occ

    def locate_ptr_to_occurences(self, binary, addresslist):
        ptrs = []
        possible_ptr = []
        for a in addresslist:
            ptrs.append(self.find_occurences(binary, struct.pack("I", a)))

        for p1 in ptrs:
            for p2 in p1:
                possible_ptr.append(p2)
        return possible_ptr

    def search_offset_two(self, addrlist1, addrlist2, offset):
        for a1 in addrlist1:
            for a2 in addrlist2:
                if a1 + offset == a2:
                    return a1, a2
        return None, None

    # Fix imports by DLL Name
    def fix_imports_by_dllname(self, pe, dllname_to_functionlist):  # TODO give options to user if other (valid) addresses are found
        addr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
        pe.write(".unipacker_brokenimport.exe")
        with open(".unipacker_brokenimport.exe", 'rb') as f:
            b = f.read()

        dllname_to_ptrs = []

        for k in dllname_to_functionlist.keys():
            dllname_to_ptrs.append((k, self.locate_ptr_to_occurences(b, self.find_occurences(b, k))))

        if len(dllname_to_ptrs) == 1 and len(dllname_to_ptrs[0][1]) == 1:
            addr = dllname_to_ptrs[0][1]
        elif len(dllname_to_ptrs) == 1:
            # TODO Try Fix Imports by Imported Function Names
            print("FAILED here")
            return None  # FAILED
        else:
            addrlist = dllname_to_ptrs[0][1]
            addrlist2 = dllname_to_ptrs[1][1]
            a1, a2 = self.search_offset_two(addrlist, addrlist2, 0x14)
            if a1 is None and a2 is None:
                print(f"FAILED a1: {a1}, a2: {a2}")
                return None  # FAILED

            dllname_to_ptrs[0] = (dllname_to_ptrs[0][0], [a1])
            dllname_to_ptrs[1] = (dllname_to_ptrs[1][0], [a2])

            offset = 0x14

            for i in range(len(dllname_to_ptrs)):
                if i+1 < len(dllname_to_ptrs):
                    cmp = dllname_to_ptrs[i][1][0]
                    val = None
                    for e in dllname_to_ptrs[i+1][1]:
                        if cmp + 0x14 == e:
                            val = e
                    dllname_to_ptrs[i+1] = (dllname_to_ptrs[i+1][0], [val])

            # select pointer
            addr = dllname_to_ptrs[0][1][0]
            for i in range(len(dllname_to_ptrs)):
                if addr > dllname_to_ptrs[i][1][0]:
                    addr = dllname_to_ptrs[i][1][0]

        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = addr - 0xC
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size = len(dllname_to_functionlist) * 5 * 4
        # Per Dll 1 IMAGE_IMPORT_DESCRIPTOR (THUNK_DATA), Per IMAGE_IMPORT_DESCRIPTOR 5 DWORDS, Size in bytes so time 4
        os.remove(".unipacker_brokenimport.exe")
        return pe

    def fix_imports_by_rebuilding(self, uc, pe, dllname_to_function_list):
        return pe

    def fix_imports(self, uc, pe, dllname_to_functionlist):
        pe.write(".unipacker_brokenimport.exe")
        with open(".unipacker_brokenimport.exe", 'rb') as f:
            b = f.read()

        print(dllname_to_functionlist)

        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = 0x60000

        os.remove(".unipacker_brokenimport.exe")
        return pe

    def dump_image(self, uc, base_addr, virtualmemorysize, apicall_handler, path="unpacked.exe"):
        ntp = apicall_handler.ntp
        dllname_to_functionlist = apicall_handler.dllname_to_functionlist
        if len(apicall_handler.allocated_chunks) == 0:
            total_size = virtualmemorysize
        else:
            total_size = sorted(apicall_handler.allocated_chunks)[:-1][1] - base_addr
        loaded_img = uc.mem_read(base_addr, total_size)
        pe = pefile.PE(data=loaded_img)

        pe.OPTIONAL_HEADER.AddressOfEntryPoint = uc.reg_read(UC_X86_REG_EIP)

        print("Fixing sections")
        for i in range(len(pe.sections) - 1):
            curr_section = pe.sections[i]
            next_section = pe.sections[i + 1]
            self.fix_section(curr_section, next_section.VirtualAddress)

        # handle last section differently: we have no next section's virtual address. Thus we take the end of the image
        self.fix_section(pe.sections[-1], virtualmemorysize)

        print("Fixing Memory Protection of Sections")
        self.fix_section_mem_protection(pe, ntp)

        print("Fixing Imports...")
        pe = self.fix_imports(uc, pe, dllname_to_functionlist)

        # Set IAT-Directory to 0 (VA and Size)
        for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if directory.name == "IMAGE_DIRECTORY_ENTRY_IAT":
                directory.Size = 0
                directory.VirtualAddress = 0

        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()

        print(f"Dumping state to {path}")
        pe.write(path)


class YZPackDump(ImageDump):
    def fix_imports(self, uc, pe, dllname_to_functionlist):
        return super().fix_imports_by_dllname(pe, dllname_to_functionlist)

