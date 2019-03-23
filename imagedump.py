import collections

import pefile
import os
from unicorn.x86_const import *
import struct
import sys

from headers import print_dos_header, print_all_headers, hdr_read, PE, pe_write
from pe_structs import _IMAGE_DOS_HEADER, _IMAGE_FILE_HEADER, _IMAGE_DATA_DIRECTORY, _IMAGE_OPTIONAL_HEADER, \
    IMAGE_SECTION_HEADER
from utils import align, alignments, InvalidPEFile, convert_to_string


class ImageDump(object):

    def fix_section(self, section, next_section_vaddr):
        sec_name = section.Name.decode().strip("\x00")
        print(f"Size of raw data ({sec_name}): 0x{section.SizeOfRawData:02x}, "
              f"fixed: 0x{next_section_vaddr - section.VirtualAddress:02x}")
        section.SizeOfRawData = next_section_vaddr - section.VirtualAddress
        section.PointerToRawData = section.VirtualAddress

    def set_protections(self, section, protection):
        x, r, w = protection
        new_protection = section.Characteristics
        if x:
            new_protection = new_protection | 0x20000000
        if r:
            new_protection = new_protection | 0x40000000
        if w:
            new_protection = new_protection | 0x80000000

        return new_protection

    def fix_section_mem_protections(self, hdr, ntp):
        for i in range(len(hdr.section_list)):
            section_name = convert_to_string(hdr.section_list[i].Name)
            print(section_name)
            if section_name in ntp.keys():
                print(f"Fixing protections for: {section_name} with {ntp[section_name][0], ntp[section_name][1], ntp[section_name][2]}")
                hdr.section_list[i].Characteristics = self.set_protections(hdr.section_list[i], ntp[section_name])
        return hdr

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
    # TODO give options to user if other (valid) addresses are found
    def fix_imports_by_dllname(self, uc, hdr, total_size, dllname_to_functionlist):
        pe_write(uc, hdr.opt_header.ImageBase, total_size, ".unipacker_brokenimport.exe")
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

        hdr.data_directories[1].VirtualAddress = addr - 0xC
        hdr.data_directories[1].Size = len(dllname_to_functionlist) * 5 * 4
        # Per Dll 1 IMAGE_IMPORT_DESCRIPTOR (THUNK_DATA), Per IMAGE_IMPORT_DESCRIPTOR 5 DWORDS, Size in bytes so time 4
        os.remove(".unipacker_brokenimport.exe")
        return hdr

    def fix_imports_by_rebuilding(self, uc, hdr, total_size, dllname_to_function_list):
        return hdr

    # TODO Dummy
    def fix_imports(self, uc, hdr, total_size, dllname_to_functionlist):
        pe_write(uc, hdr.opt_header.ImageBase, total_size, ".unipacker_brokenimport.exe")
        with open(".unipacker_brokenimport.exe", 'rb') as f:
            b = f.read()

        print(dllname_to_functionlist)

        hdr.data_directories[1].VirtualAddress = 0x60000
        hdr.data_directories[1].Size = len(dllname_to_functionlist) * 5 * 4

        os.remove(".unipacker_brokenimport.exe")
        return hdr


    def chunk_to_image_section_hdr(self, hdr, base_addr, allocated_chunks):
        number_of_added_sections = 0
        for chunk_start, chunk_end in allocated_chunks:
            chunk_vaddr = chunk_start - base_addr
            chunk_size = chunk_end - chunk_start
            hdr = self.add_section(hdr, f".ach{number_of_added_sections}", chunk_size, chunk_vaddr)
            number_of_added_sections += 1
        return hdr

    # TODO Set characteristics from VirtualAlloc
    def add_section(self, hdr, name, VirtualSize, VirtualAddress, Characteristics=0xe0000020):
        if len(name) > 8:
            print("Error section name too long")
            return
        import_section_hdr = IMAGE_SECTION_HEADER(
            bytes(name, 'ascii'),  # Name
            VirtualSize,  # VirtualSize
            VirtualAddress,  # VirtualAddress
            VirtualSize,  # SizeOfRawData
            VirtualAddress,  # PointerToRawData
            0,  # PointerToRelocations
            0,  # PointerToLinenumbers
            0,  # NumberOfRelocations
            0,  # NumberOfLinenumbers
            Characteristics,  # Characteristics
        )

        hdr.section_list.append(import_section_hdr)

        # Correct Value of Number of Sections
        hdr.pe_header.NumberOfSections += 1

        # Fix SizeOfHeaders
        hdr.opt_header.SizeOfHeaders = alignments(hdr.opt_header.SizeOfHeaders + len(bytes(IMAGE_SECTION_HEADER())),
                                                  hdr.opt_header.FileAlignment)

        return hdr

    def add_import_section_api(self, hdr, virtualmemorysize, totalsize, check_space=True):
        # Set check_space to false if the pe-header was relocated

        if check_space:
            rva_to_section_table = hdr.dos_header.e_lfanew + len(bytes(_IMAGE_FILE_HEADER())) + len(bytes(_IMAGE_OPTIONAL_HEADER()))
            number_of_sections = hdr.pe_header.NumberOfSections
            end_of_section_table = rva_to_section_table + len(bytes(IMAGE_SECTION_HEADER())) * number_of_sections

            beginning_of_first_section = sys.maxsize

            for section in hdr.section_list:
                if section.VirtualAddress < beginning_of_first_section:
                    beginning_of_first_section = section.VirtualAddress

            if end_of_section_table + len(bytes(IMAGE_SECTION_HEADER())) >= beginning_of_first_section:
                print("Not enough space for additional section")
                return

        import_section = IMAGE_SECTION_HEADER(
            bytes(".impdata", 'ascii'),  # Name
            0x10000,  # VirtualSize
            virtualmemorysize - 0x10000,  # VirtualAddress
            0x10000,  # SizeOfRawData
            virtualmemorysize - 0x10000,  # PointerToRawData
            0,  # PointerToRelocations
            0,  # PointerToLinenumbers
            0,  # NumberOfRelocations
            0,  # NumberOfLinenumbers
            0xe0000020,  # Characteristics
        )

        hdr.section_list.append(import_section)

        # Correct Value of Number of Sections
        hdr.pe_header.NumberOfSections += 1

        # Fix SizeOfHeaders
        hdr.opt_header.SizeOfHeaders = alignments(hdr.opt_header.SizeOfHeaders + len(bytes(IMAGE_SECTION_HEADER())),
                                  hdr.opt_header.FileAlignment)

        return hdr

    def fix_sections(self, hdr, old_number_of_sections, virtualmemorysize):
        for i in range(old_number_of_sections - 1):
            curr_section = hdr.section_list[i]
            next_section = hdr.section_list[i + 1]
            self.fix_section(curr_section, next_section.VirtualAddress)

        # handle last section differently: we have no next section's virtual address. Thus we take the end of the image
        self.fix_section(hdr.section_list[old_number_of_sections - 1], virtualmemorysize - 0x10000)

    def fix_checksum(self, uc, hdr, base_addr, total_size):
        loaded_img = uc.mem_read(base_addr, total_size)
        pe = pefile.PE(data=loaded_img)
        hdr.opt_header.CheckSum = pe.generate_checksum()
        return hdr

    def dump_image(self, uc, base_addr, virtualmemorysize, apicall_handler, path="unpacked.exe"):
        ntp = apicall_handler.ntp
        dllname_to_functionlist = apicall_handler.dllname_to_functionlist
        if len(apicall_handler.allocated_chunks) == 0:
            total_size = virtualmemorysize
        else:
            total_size = sorted(apicall_handler.allocated_chunks)[:-1][1] - base_addr

        try:
            hdr = PE(uc, base_addr)
        except InvalidPEFile as i:
            print("Invalid PE File... Cannot dump")
            return

        old_number_of_sections = hdr.pe_header.NumberOfSections

        print("Setting unpacked Entry Point")
        hdr.opt_header.AddressOfEntryPoint = uc.reg_read(UC_X86_REG_EIP) - base_addr

        print("Fixing Imports...")
        hdr = self.fix_imports(uc, hdr, total_size, dllname_to_functionlist)

        print("Fixing sections")
        self.fix_sections(hdr, old_number_of_sections, virtualmemorysize)

        print("Set IAT-Directory to 0 (VA and Size)")
        hdr.data_directories[12].VirtualAddress = 0
        hdr.data_directories[12].Size = 0

        if virtualmemorysize <= hdr.data_directories[1].VirtualAddress <= total_size or len(apicall_handler.allocated_chunks) != 0:
            print("Relocating Headers to End of Image")
            hdr.dos_header.e_lfanew = virtualmemorysize - 0x10000
            hdr = self.add_section(hdr, '.newhdr', 0x2000, virtualmemorysize-0x10000)
            print("Adding new import section")
            hdr = self.add_section(hdr, '.nimdata', 0x8000, (virtualmemorysize - 0x10000) + 0x2000)
            print("Appending allocated chunks at the end of the image")
            hdr = self.chunk_to_image_section_hdr(hdr, base_addr, apicall_handler.allocated_chunks)

        else:
            virtualmemorysize -= 0x10000
            total_size = virtualmemorysize

        hdr.sync(uc)


        print("Fixing SizeOfImage...")
        hdr.opt_header.SizeOfImage = alignments(total_size, hdr.opt_header.SectionAlignment)

        print("Fixing Memory Protection of Sections")
        hdr = self.fix_section_mem_protections(hdr, ntp)

        hdr.sync(uc)

        print("Fixing Checksum")
        hdr = self.fix_checksum(uc, hdr, base_addr, total_size)
        hdr.sync(uc)

        print(f"Dumping state to {path}")
        pe_write(uc, base_addr, total_size, path)


class YZPackDump(ImageDump):
    def fix_imports(self, uc, hdr, total_size, dllname_to_functionlist):
        return super().fix_imports_by_dllname(uc, hdr, total_size, dllname_to_functionlist)

