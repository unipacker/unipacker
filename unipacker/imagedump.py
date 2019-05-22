import os
import struct
import sys

import pefile
from unicorn.x86_const import *

from unipacker.headers import PE, pe_write
from unipacker.pe_structs import _IMAGE_FILE_HEADER, _IMAGE_OPTIONAL_HEADER, \
    IMAGE_SECTION_HEADER, IMAGE_IMPORT_DESCRIPTOR
from unipacker.utils import alignments, InvalidPEFile, convert_to_string, print_addr_list, print_chunks


class ImageDump(object):

    def fix_section(self, section, next_section_vaddr):
        # sec_name = section.Name.decode().strip("\x00")
        sec_name = convert_to_string(section.Name)
        print(f"Size of raw data ({sec_name}): 0x{section.SizeOfRawData:02x}, "
              f"fixed: 0x{next_section_vaddr - section.VirtualAddress:02x}")
        section.SizeOfRawData = next_section_vaddr - section.VirtualAddress
        section.PointerToRawData = section.VirtualAddress
        section.VirtualSize = section.SizeOfRawData

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
                print(f"Fixing protections for: {section_name} "
                      f"with {ntp[section_name][0], ntp[section_name][1], ntp[section_name][2]}")
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
            x = binary.find(search, (x + 1), len(binary))
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
    # TODO implement multiple LoadLibrary of same dll
    def fix_imports_by_dllname(self, uc, hdr, total_size, dllname_to_functionlist):
        pe_write(uc, hdr.opt_header.ImageBase, total_size, ".unipacker_brokenimport.exe")
        with open(".unipacker_brokenimport.exe", 'rb') as f:
            b = f.read()

        dllname_to_ptrs = []

        for k in dllname_to_functionlist.keys():
            k = k.split('#')[0]
            dllname_to_ptrs.append((k, self.locate_ptr_to_occurences(b, self.find_occurences(b, k))))

        if len(dllname_to_ptrs) == 1 and len(dllname_to_ptrs[0][1]) == 1:
            addr = dllname_to_ptrs[0][1]
        elif len(dllname_to_ptrs) == 1:
            # TODO Try Fix Imports by Imported Function Names
            print("FAILED here")
            return None  # FAILED
        else:
            for i in range(len(dllname_to_ptrs) - 1):
                addrlist = dllname_to_ptrs[i][1]
                addrlist2 = dllname_to_ptrs[i + 1][1]
                a1, a2 = self.search_offset_two(addrlist, addrlist2, 0x14)
                if a1 is not None and a2 is not None:
                    break

            if a1 is None and a2 is None:
                print(f"FAILED a1: {a1}, a2: {a2}")
                return None  # FAILED

            dllname_to_ptrs[0] = (dllname_to_ptrs[0][0], [a1])
            dllname_to_ptrs[1] = (dllname_to_ptrs[1][0], [a2])

            offset = 0x14

            for i in range(len(dllname_to_ptrs)):
                if i + 1 < len(dllname_to_ptrs):
                    cmp = dllname_to_ptrs[i][1][0]
                    val = None
                    for e in dllname_to_ptrs[i + 1][1]:
                        if cmp + 0x14 == e:
                            val = e
                    dllname_to_ptrs[i + 1] = (dllname_to_ptrs[i + 1][0], [val])

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

    def find_iat(self, uc, base_addr, total_size, iat_array, dll_name, offset=0x4):
        # hex = ' '.join('0x%02x' % hx for hx in iat_array)
        # print(f"IAT_ARRAY:{hex}")
        pe_write(uc, base_addr, total_size, ".unipacker_brokenimport.exe")
        with open(".unipacker_brokenimport.exe", 'rb') as f:
            b = f.read()

        # Part 1: Find all possible ptrs

        possible_ptrs = []
        for iat_entry in iat_array:
            found_ptr = -1
            possible_addr = []
            while True:
                found_ptr = b.find(struct.pack("I", iat_entry), (found_ptr + 1), len(b))
                if found_ptr == -1:
                    break
                else:
                    possible_addr.append(found_ptr)

            possible_ptrs.append(possible_addr)

        # Part 2: Validate with offset
        if len(possible_ptrs) == 1:
            if len(possible_ptrs[0]) == 0:
                return None
            return possible_ptrs[0][0]  # TODO Default first check with allocated section
        ptrs = []
        for i in range(len(possible_ptrs) - 1):
            l1 = possible_ptrs[i]
            l2 = possible_ptrs[i + 1]
            a1, a2 = self.search_offset_two(l1, l2, offset)
            if a1 is None:
                print("Not Found!")
            ptrs.append(a1)

        lx = possible_ptrs[-1]
        for elem in lx:
            if elem - offset == ptrs[-1]:
                ptrs.append(elem)

        # print_addr_list(f"Printing possible ptrs for {dll_name}: ", ptrs)

        return ptrs[0]

    def patch_iat(self, uc, base_addr, patches, ptr_to_iat, offset=0x4):
        for p in patches:
            uc.mem_write(ptr_to_iat + base_addr, struct.pack("<I", p))
            ptr_to_iat += offset

    def generate_iat_array(self, dllname_to_function_list, dll_name):
        iat = []
        for name, addr in dllname_to_function_list[dll_name]:
            iat.append(addr)
        return iat

    # TODO Add original imports
    # TODO Fix IAT Finding algorithm -> full imports must be available
    def fix_imports_by_rebuilding(self, uc, hdr, virtualmemorysize, total_size, dllname_to_function_list):
        rva_to_image_import_descriptor = (virtualmemorysize - 0x10000) + 0x2000
        curr_addr_to_image_import_descriptor = rva_to_image_import_descriptor + hdr.base_addr
        num_of_image_import_descriptor = len(dllname_to_function_list)
        size_of_image_import_descriptor = len(bytes(IMAGE_IMPORT_DESCRIPTOR())) * num_of_image_import_descriptor

        rva_of_dll_name = rva_to_image_import_descriptor + size_of_image_import_descriptor + 20
        size_of_dll_name_array = 0
        for dll_name in dllname_to_function_list.keys():
            size_of_dll_name_array += len(dll_name.split('#')[0]) + 1

        rva_of_hint_name = rva_of_dll_name + size_of_dll_name_array + 0x10

        for dll_name in dllname_to_function_list.keys():
            iat_array = self.generate_iat_array(dllname_to_function_list, dll_name)
            # print(f"IAT_ARRAY for {dll_name}")
            ptr_iat = self.find_iat(uc, hdr.base_addr, total_size, iat_array, dll_name)

            if ptr_iat is None:
                continue

            orva_to_hint_name = rva_of_hint_name
            dll_name_b = dll_name.split('#')[0].encode('ascii') + b'\x00'
            print(f"writing dllname {dll_name} to: {hex(rva_of_dll_name)}")
            uc.mem_write(rva_of_dll_name + hdr.base_addr, dll_name_b)
            size_of_hint_name_array = len(dllname_to_function_list[dll_name]) * 0x4
            rva_to_image_import_by_name = rva_of_hint_name + size_of_hint_name_array + 0x10
            patch_addr = []
            for fct_name, fct_addr in dllname_to_function_list[dll_name]:
                if "/" not in fct_name:  # Import by Name
                    import_by_name = b'\x00\x00' + fct_name.encode('ascii') + b'\x00'
                    uc.mem_write(rva_to_image_import_by_name + hdr.base_addr, import_by_name)
                    uc.mem_write(rva_of_hint_name + hdr.base_addr, struct.pack("<I", rva_to_image_import_by_name))
                    patch_addr.append(rva_to_image_import_by_name)
                    rva_to_image_import_by_name += len(import_by_name)
                else:  # Import by ordinal
                    ordinal = int(fct_name.split("/")[2],
                                  10) + 0x80000000  # Import Lookup Table 1 bit defines ordinals (0x80000000)
                    uc.mem_write(rva_of_hint_name + hdr.base_addr, struct.pack("<I", ordinal))
                    patch_addr.append(ordinal)
                rva_of_hint_name += 4

            rva_of_hint_name = rva_to_image_import_by_name + 0x8

            self.patch_iat(uc, hdr.base_addr, patch_addr, ptr_iat)

            import_struct = IMAGE_IMPORT_DESCRIPTOR(
                orva_to_hint_name,
                0,
                0,
                rva_of_dll_name,
                ptr_iat,
            )

            print_addr_list("patch_addr: ", patch_addr)
            print(f"ptr_iat: {hex(ptr_iat)}")

            import_struct_payload = bytes(import_struct)

            uc.mem_write(curr_addr_to_image_import_descriptor, import_struct_payload)

            rva_of_dll_name += len(dll_name_b)

            curr_addr_to_image_import_descriptor += len(bytes(IMAGE_IMPORT_DESCRIPTOR()))

        hdr.data_directories[1].VirtualAddress = rva_to_image_import_descriptor
        hdr.data_directories[1].Size = size_of_image_import_descriptor
        # hdr.data_directories[1].VirtualAddress = 0
        # hdr.data_directories[1].Size = 0
        hdr.sync(uc)
        return hdr

    def append_original_imports(self, uc, hdr, original_imp):
        rva_to_imp_table = hdr.data_directories[1].VirtualAddress
        size_of_imp_table = hdr.data_directories[1].Size
        base_addr = hdr.opt_header.ImageBase

        new_size = size_of_imp_table + len(original_imp) * len(bytes(IMAGE_IMPORT_DESCRIPTOR()))

        rva_end = rva_to_imp_table + size_of_imp_table
        total_new_offset = rva_end + new_size + 0x100

        fct_name_offset = total_new_offset

        for imp_desc in original_imp:
            image_import_by_name_offsets = []

            for imp in imp_desc.imports:
                fct_name = b'\x00\x00' + imp + b'\x00'
                uc.mem_write(fct_name_offset + base_addr, fct_name)
                image_import_by_name_offsets.append(fct_name_offset)
                fct_name_offset += len(fct_name)

            fct_name_offset += 0x50
            imp_desc.Import_Descriptor.Characteristics = fct_name_offset

            iat_offset = 0 + imp_desc.Import_Descriptor.FirstThunk

            for addr in image_import_by_name_offsets:
                uc.mem_write(fct_name_offset + base_addr, struct.pack("<I", addr))

                uc.mem_write(iat_offset + base_addr, struct.pack("<I", addr))

                fct_name_offset += 4
                iat_offset += 4

            fct_name_offset += 0x10

            imp_desc.Import_Descriptor.Name = fct_name_offset
            new_name = imp_desc.name.encode('ascii') + b'\x00'
            uc.mem_write(fct_name_offset + base_addr, new_name)

            fct_name_offset += 0x20
            image_import_descriptor = IMAGE_IMPORT_DESCRIPTOR(
                imp_desc.Import_Descriptor.Characteristics,
                imp_desc.Import_Descriptor.TimeDateStamp,
                imp_desc.Import_Descriptor.ForwarderChain,
                imp_desc.Import_Descriptor.Name,
                imp_desc.Import_Descriptor.FirstThunk,
            )
            uc.mem_write(rva_end + base_addr, bytes(image_import_descriptor))
            rva_end += len(bytes(image_import_descriptor))

        hdr.data_directories[1].Size = new_size
        hdr.sync(uc)
        return hdr


    # TODO Dummy
    def fix_imports(self, uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, original_imports):
        # pe_write(uc, hdr.opt_header.ImageBase, total_size, ".unipacker_brokenimport.exe")
        # with open(".unipacker_brokenimport.exe", 'rb') as f:
        #    b = f.read()

        # print(dllname_to_functionlist)

        # hdr.data_directories[1].VirtualAddress = 0x60000
        # hdr.data_directories[1].Size = len(dllname_to_functionlist) * 5 * 4

        # os.remove(".unipacker_brokenimport.exe")
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
            rva_to_section_table = hdr.dos_header.e_lfanew + len(bytes(_IMAGE_FILE_HEADER())) + len(
                bytes(_IMAGE_OPTIONAL_HEADER()))
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
        self.fix_section(hdr.section_list[old_number_of_sections - 1], virtualmemorysize)  # TODO set again to -0x10000

    def fix_checksum(self, uc, hdr, base_addr, total_size):
        loaded_img = uc.mem_read(base_addr, total_size)
        pe = pefile.PE(data=loaded_img)
        hdr.opt_header.CheckSum = pe.generate_checksum()
        return hdr

    def dump_image(self, uc, base_addr, virtualmemorysize, apicall_handler, sample, path="unpacked.exe"):
        ntp = apicall_handler.ntp
        dllname_to_functionlist = sample.dllname_to_functionlist
        if len(sample.allocated_chunks) == 0:
            total_size = virtualmemorysize
        else:
            total_size = sorted(sample.allocated_chunks)[-1][1] - base_addr
            virtualmemorysize = total_size

        print(f"Totalsize:{hex(total_size)}, "
              f"VirtualMemorySize:{hex(virtualmemorysize)}")

        print_chunks(sample.allocated_chunks)

        try:
            hdr = PE(uc, base_addr)
        except InvalidPEFile as i:
            print("Invalid PE File... Cannot dump")
            return

        old_number_of_sections = hdr.pe_header.NumberOfSections

        print("Setting unpacked Entry Point")
        print(f"OEP:{hex(uc.reg_read(UC_X86_REG_EIP) - base_addr)}")
        hdr.opt_header.AddressOfEntryPoint = uc.reg_read(UC_X86_REG_EIP) - base_addr

        print("Fixing Imports...")
        hdr = self.fix_imports(uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, sample.original_imports)

        print("Fixing sections")
        self.fix_sections(hdr, old_number_of_sections, virtualmemorysize)

        print("Set IAT-Directory to 0 (VA and Size)")
        hdr.data_directories[12].VirtualAddress = 0
        hdr.data_directories[12].Size = 0

        print(f"RVA to import table: {hex(hdr.data_directories[1].VirtualAddress)}")

        if (virtualmemorysize - 0xE000) <= hdr.data_directories[1].VirtualAddress <= virtualmemorysize or len(
                sample.allocated_chunks) != 0 or True:
            print(f"Totalsize:{hex(total_size)}, "
                  f"VirtualMemorySize:{hex(virtualmemorysize)}, "
                  f"Allocated chunks: {sample.allocated_chunks}")
            # print("Relocating Headers to End of Image")
            # hdr.dos_header.e_lfanew = virtualmemorysize - 0x10000
            # hdr = self.add_section(hdr, '.newhdr', 0x10000, virtualmemorysize-0x10000)
            # print("Adding new import section")
            # hdr = self.add_section(hdr, '.nimdata', 0xe000, (virtualmemorysize - 0x10000) + 0x2000)
            # print("Appending allocated chunks at the end of the image")
            # hdr = self.chunk_to_image_section_hdr(hdr, base_addr, sample.allocated_chunks)
            # TODO Fix chunk unmapped space with 0
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

        dllcharacteristics = hdr.opt_header.DllCharacteristics & 0xFFBF
        hdr.opt_header.DllCharacteristics = dllcharacteristics  # Remove Dynamic Base
        hdr.sync(uc)

        print(f"Dumping state to {path}")
        pe_write(uc, base_addr, total_size, path)


# YZPackDump can use fix_imports_by_rebuilding as well
class YZPackDump(ImageDump):
    def fix_imports(self, uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, original_imp):
        return super().fix_imports_by_dllname(uc, hdr, total_size, dllname_to_functionlist)
        # return super().fix_imports_by_rebuilding(uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist)


class ASPackDump(ImageDump):
    def fix_imports(self, uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, original_imp):
        return super().fix_imports_by_rebuilding(uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist)


class FSGDump(ImageDump):
    def fix_imports(self, uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, original_imp):
        return super().fix_imports_by_rebuilding(uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist)


class PEtiteDump(ImageDump):
    def fix_section_mem_protections(self, hdr, ntp):
        for s in ntp.keys():
            ntp[s] = (True, True, True)
        return super().fix_section_mem_protections(hdr, ntp)

    def fix_imports(self, uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, original_imp):
        print(dllname_to_functionlist)
        #return super().append_original_imports(uc, super().fix_imports_by_rebuilding(uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist), original_imp)
        return super().fix_imports_by_rebuilding(uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist)


class MEWDump(ImageDump):
    def fix_imports(self, uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, original_imp):
        return super().fix_imports_by_rebuilding(uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist)

    def fix_section_mem_protections(self, hdr, ntp):
        for section in ntp:
            ntp[section] = (True, True, True)
        return super().fix_section_mem_protections(hdr, ntp)

class MPRESSDump(ImageDump):
    def fix_imports(self, uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, original_imp):
        return super().fix_imports_by_rebuilding(uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist)

class UPXDump(ImageDump):
    def fix_imports(self, uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist, original_imp):
        print(dllname_to_functionlist)
        return super().fix_imports_by_rebuilding(uc, hdr, virtualmemorysize, total_size, dllname_to_functionlist)
