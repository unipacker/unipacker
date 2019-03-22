import collections

import pefile
import os
from unicorn.x86_const import *
import struct
import sys

from headers import print_dos_header, print_all_headers, hdr_read, PE
from pe_structs import _IMAGE_DOS_HEADER, _IMAGE_FILE_HEADER, _IMAGE_DATA_DIRECTORY, _IMAGE_OPTIONAL_HEADER, \
    IMAGE_SECTION_HEADER
from utils import align, alignments, InvalidPEFile


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

    # TODO Fix
    def fix_imports(self, uc, pe, dllname_to_functionlist):
        pe.write(".unipacker_brokenimport.exe")
        with open(".unipacker_brokenimport.exe", 'rb') as f:
            b = f.read()

        print(dllname_to_functionlist)

        pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = 0x60000

        os.remove(".unipacker_brokenimport.exe")
        return pe

    def fix_header(self, uc, parse_pe, base_addr, virtualmemorysize, total_size, chunk_sections, number_of_added_sections):

        custom_import_table = False

        if parse_pe.OPTIONAL_HEADER.AddressOfEntryPoint == virtualmemorysize - 0x10000:
            number_of_added_sections += 1
            custom_import_table = True

        total_sections_c = parse_pe.FILE_HEADER.NumberOfSections + number_of_added_sections

        dos_header = _IMAGE_DOS_HEADER(
            parse_pe.DOS_HEADER.e_magic,
            parse_pe.DOS_HEADER.e_cblp,
            parse_pe.DOS_HEADER.e_cp,
            parse_pe.DOS_HEADER.e_crlc,
            parse_pe.DOS_HEADER.e_cparhdr,
            parse_pe.DOS_HEADER.e_minalloc,
            parse_pe.DOS_HEADER.e_maxalloc,
            parse_pe.DOS_HEADER.e_ss,
            parse_pe.DOS_HEADER.e_sp,
            parse_pe.DOS_HEADER.e_csum,
            parse_pe.DOS_HEADER.e_ip,
            parse_pe.DOS_HEADER.e_cs,
            parse_pe.DOS_HEADER.e_lfarlc,
            parse_pe.DOS_HEADER.e_ovno,
            parse_pe.DOS_HEADER.e_res,
            parse_pe.DOS_HEADER.e_oemid,
            parse_pe.DOS_HEADER.e_oeminfo,
            parse_pe.DOS_HEADER.e_res2,
            virtualmemorysize - 0x19000,  # PTR to new PE Header
        )

        pe_header = _IMAGE_FILE_HEADER(
            0x4550,
            parse_pe.FILE_HEADER.Machine,
            parse_pe.FILE_HEADER.NumberOfSections + number_of_added_sections,
            parse_pe.FILE_HEADER.TimeDateStamp,
            parse_pe.FILE_HEADER.PointerToSymbolTable,
            parse_pe.FILE_HEADER.NumberOfSymbols,
            parse_pe.FILE_HEADER.SizeOfOptionalHeader,  # SizeOfOptionalHeader
            parse_pe.FILE_HEADER.Characteristics,
        )

        # No changes in the import direcotory. Import fixing later
        data_directory_list = []

        for data_directory_entry in parse_pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            entry = _IMAGE_DATA_DIRECTORY(
                data_directory_entry.VirtualAddress,
                data_directory_entry.Size,
            )
            data_directory_list.append(entry)

        data_directory_array = _IMAGE_DATA_DIRECTORY * 16
        data_directory = data_directory_array(*list(data_directory_list))

        opt_header = _IMAGE_OPTIONAL_HEADER(
            parse_pe.OPTIONAL_HEADER.Magic,
            parse_pe.OPTIONAL_HEADER.MajorLinkerVersion,
            parse_pe.OPTIONAL_HEADER.MinorLinkerVersion,
            parse_pe.OPTIONAL_HEADER.SizeOfCode,
            parse_pe.OPTIONAL_HEADER.SizeOfInitializedData,
            parse_pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            parse_pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            parse_pe.OPTIONAL_HEADER.BaseOfCode,
            parse_pe.OPTIONAL_HEADER.BaseOfData,
            parse_pe.OPTIONAL_HEADER.ImageBase,
            parse_pe.OPTIONAL_HEADER.SectionAlignment,
            parse_pe.OPTIONAL_HEADER.FileAlignment,
            parse_pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            parse_pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            parse_pe.OPTIONAL_HEADER.MajorImageVersion,
            parse_pe.OPTIONAL_HEADER.MinorImageVersion,
            parse_pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            parse_pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            0,
            align(total_size, page_size=parse_pe.OPTIONAL_HEADER.SectionAlignment),  # SizeOfImage
            align(4 + 4 + len(bytes(_IMAGE_FILE_HEADER())) + len(bytes(_IMAGE_OPTIONAL_HEADER())) + (total_sections_c * len(bytes(IMAGE_SECTION_HEADER()))), page_size=parse_pe.OPTIONAL_HEADER.FileAlignment),  # SizeOfHeaders
            parse_pe.OPTIONAL_HEADER.CheckSum,
            parse_pe.OPTIONAL_HEADER.Subsystem,
            parse_pe.OPTIONAL_HEADER.DllCharacteristics,
            parse_pe.OPTIONAL_HEADER.SizeOfStackReserve,
            parse_pe.OPTIONAL_HEADER.SizeOfStackCommit,
            parse_pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            parse_pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            parse_pe.OPTIONAL_HEADER.LoaderFlags,
            parse_pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
            data_directory
        )

        original_section_structs = []
        original_sections = parse_pe.sections
        for os in original_sections:
            section_struct = IMAGE_SECTION_HEADER(
                os.Name,  # Name
                os.Misc_VirtualSize,  # VirtualSize
                os.VirtualAddress,  # VirtualAddress
                os.SizeOfRawData,  # SizeOfRawData
                os.PointerToRawData,  # PointerToRawData
                os.PointerToRelocations,  # PointerToRelocations
                os.PointerToLinenumbers,  # PointerToLinenumbers
                os.NumberOfRelocations,  # NumberOfRelocations
                os.NumberOfLinenumbers,  # NumberOfLinenumbers
                os.Characteristics,  # Characteristics
            )
            original_section_structs.append(section_struct)

        # TODO Create Section for new import table
        if custom_import_table:
            pass

        # Write into memory
        dos_header_payload = bytes(dos_header)
        pe_header_payload = bytes(pe_header)
        opt_header_payload = bytes(opt_header)
        section_list = original_section_structs + chunk_sections
        section_array = IMAGE_SECTION_HEADER * total_sections_c
        section_payload = bytes(section_array(*list(section_list)))

        new_start_addr = (base_addr + virtualmemorysize) - 0x19000

        uc.mem_write(base_addr, dos_header_payload)
        uc.mem_write(new_start_addr, pe_header_payload + opt_header_payload + section_payload)

        print(f"virtualmemorysize = {virtualmemorysize}, base_addr = {base_addr}, totalsize = {total_size}")

        correct_loaded_img = uc.mem_read(base_addr, total_size)
        with open(f"unp.dump", 'wb') as f:
            f.write(correct_loaded_img)
        with open("newhdr.dump", 'wb') as f:
            f.write(pe_header_payload + opt_header_payload + section_payload)
        pe = pefile.PE(data=correct_loaded_img)
        return pe

    def chunk_to_image_section_hdr(self, base_addr, allocated_chunks):
        chunk_sections = []
        number_of_added_sections = 0
        for chunk_start, chunk_end in allocated_chunks:
            chunk_vaddr = chunk_start - base_addr
            chunk_size = chunk_end - chunk_start
            chunk_section_struct = IMAGE_SECTION_HEADER(
                bytes(f".ach{number_of_added_sections}", 'ascii'),  # Name
                chunk_size,  # VirtualSize
                chunk_vaddr,  # VirtualAddress
                chunk_size,  # SizeOfRawData
                chunk_vaddr,  # PointerToRawData
                0,  # PointerToRelocations
                0,  # PointerToLinenumbers
                0,  # NumberOfRelocations
                0,  # NumberOfLineNumbers
                0xe0000020,  # Characteristics
            )
            chunk_sections.append(chunk_section_struct)
            number_of_added_sections += 1
        return chunk_sections



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
        print(f"Size of headers: {hdr.opt_header.SizeOfHeaders}")

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
        hdr = self.add_import_section_api(hdr, virtualmemorysize, total_size, False)
        hdr.opt_header.AddressOfEntryPoint = uc.reg_read(UC_X86_REG_EIP) - base_addr
        hdr.dos_header.e_lfanew = virtualmemorysize - 0x10000
        hdr.sync(uc)

        loaded_img = uc.mem_read(base_addr, total_size)
        pe = pefile.PE(data=loaded_img)


        print("Fixing sections")
        for i in range(old_number_of_sections - 1):
            curr_section = pe.sections[i]
            next_section = pe.sections[i + 1]
            self.fix_section(curr_section, next_section.VirtualAddress)

        # handle last section differently: we have no next section's virtual address. Thus we take the end of the image
        self.fix_section(pe.sections[old_number_of_sections - 1], virtualmemorysize - 0x10000)

        print("Fixing Memory Protection of Sections")
        self.fix_section_mem_protection(pe, ntp)

        # Not working new section header in windows loader
        # chunk_sections = self.chunk_to_image_section_hdr(base_addr, apicall_handler.allocated_chunks)

        print("Fixing Imports...")
        pe = self.fix_imports(uc, pe, dllname_to_functionlist)

        # Set IAT-Directory to 0 (VA and Size)
        for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if directory.name == "IMAGE_DIRECTORY_ENTRY_IAT":
                directory.Size = 0
                directory.VirtualAddress = 0
                break

        # Not working new section header in windows loader
        # pe = self.fix_header(uc, pe, base_addr, virtualmemorysize, total_size, chunk_sections, number_of_added_sections)

        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()

        print(f"Dumping state to {path}")
        pe.write(path)



class YZPackDump(ImageDump):
    def fix_imports(self, uc, pe, dllname_to_functionlist):
        return super().fix_imports_by_dllname(pe, dllname_to_functionlist)

