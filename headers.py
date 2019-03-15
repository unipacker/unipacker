from pe_structs import _IMAGE_DOS_HEADER, _IMAGE_FILE_HEADER, _IMAGE_OPTIONAL_HEADER, IMAGE_SECTION_HEADER, \
    _IMAGE_DATA_DIRECTORY
from ctypes import *

header_sizes = {
    "_IMAGE_DOS_HEADER": len(bytes(_IMAGE_DOS_HEADER())),  # 0x40
    "_IMAGE_FILE_HEADER": len(bytes(_IMAGE_FILE_HEADER())),  # 0x18
    "_IMAGE_OPTIONAL_HEADER": len(bytes(_IMAGE_OPTIONAL_HEADER())),  # 0xE0
    "IMAGE_SECTION_HEADER": len(bytes(IMAGE_SECTION_HEADER())),  # 0x28
    "_IMAGE_DATA_DIRECTORY": len(bytes(_IMAGE_DATA_DIRECTORY())),  # 0x8
}


def calc_offset():
    pass


# TODO
def check_valid_pe():
    pass


def parse_momery_to_header(uc, base_addr, query_header=None):
    # Read DOS Header
    uc_dos = uc.mem_read(base_addr, header_sizes["_IMAGE_DOS_HEADER"])
    dos_header = _IMAGE_DOS_HEADER.from_buffer(uc_dos)

    if getattr(dos_header, "e_magic") != 0x5A4D:
        print(f"e_magic = {getattr(dos_header, 'e_magic')}")
        print("Wrong DOS Magic Value (MZ). Aborting...")
        return None

    e_lfanew = getattr(dos_header, "e_lfanew")

    if query_header == "e_lfanew":
        return e_lfanew

    if query_header == "_IMAGE_DOS_HEADER":
        return dos_header

    # Read PE Header
    pe_hdr_offset = base_addr + e_lfanew
    uc_pe = uc.mem_read(pe_hdr_offset, header_sizes["_IMAGE_FILE_HEADER"])
    pe_header = _IMAGE_FILE_HEADER.from_buffer(uc_pe)

    if getattr(pe_header, "Signature") != 0x4550:
        print(f"Signature: {getattr(pe_header, 'Signature')}")
        print("Wrong PE Header Signature. Aborting...")
        return None

    number_of_sections = getattr(pe_header, "NumberOfSections")

    if query_header == "_IMAGE_FILE_HEADER":
        return pe_header

    # Read Optional Header
    opt_hdr_offset = pe_hdr_offset + header_sizes["_IMAGE_FILE_HEADER"]
    uc_opt = uc.mem_read(opt_hdr_offset, header_sizes["_IMAGE_OPTIONAL_HEADER"])
    opt_header = _IMAGE_OPTIONAL_HEADER.from_buffer(uc_opt)

    if getattr(opt_header, "Magic") != 0x10B:
        print(f"OPT Magic: {getattr(opt_header, 'Magic')}")
        print("Wrong Optional Header Magic. Aborting...")
        return None

    if query_header == "_IMAGE_OPTIONAL_HEADER":
        return opt_header

    if query_header == "_IMAGE_DATA_DIRECTORY":
        return getattr(opt_header, "DataDirectory")


    # Read Section Header
    section_hdr_offset = opt_hdr_offset + header_sizes["_IMAGE_OPTIONAL_HEADER"]
    section_headers = []
    for i in range(number_of_sections - 1):
        uc_sec = uc.mem_read(section_hdr_offset, header_sizes["IMAGE_SECTION_HEADER"])
        sec_header = IMAGE_SECTION_HEADER.from_buffer(uc_sec)
        section_headers.append(sec_header)
        section_hdr_offset += header_sizes["IMAGE_SECTION_HEADER"]

    if query_header == "IMAGE_SECTION_HEADER":
        return section_headers

    headers = {"_IMAGE_DOS_HEADER": dos_header, "_IMAGE_FILE_HEADER": pe_header, "_IMAGE_OPTIONAL_HEADER": opt_header,
               "IMAGE_SECTION_HEADER": section_headers}

    return headers


# TODO make recursive
def print_struc(s, offset, name):
    print(name)
    for field_name, field_type in s._fields_:
        if isinstance(getattr(s, field_name), Array):
            print(f"\t +{hex(offset)} {field_name}:")
            sub_offset = offset
            for i in range(len(getattr(s, field_name))):
                for sub_field_name, sub_field_type in getattr(s, field_name)[i]._fields_:
                    print(f"\t\t +{hex(sub_offset)} {sub_field_name}: {getattr(getattr(s, field_name)[i],sub_field_name)}")
                    sub_offset += len(bytes(sub_field_type()))
        else:
            print(f"\t +{hex(offset)} {field_name}: {getattr(s, field_name)}")
        offset += len(bytes(field_type()))


def print_dos_header(uc, base_addr):
    dos_header = parse_momery_to_header(uc, base_addr, "_IMAGE_DOS_HEADER")
    print_struc(dos_header, 0, "_IMAGE_DOS_HEADER")


def print_all_headers(uc, base_addr):
    pass


# TODO Fix
def hdr_read(uc, base_addr, header, field):
    # Read DOS Header
    uc_dos = uc.mem_read(base_addr, header_sizes["_IMAGE_DOS_HEADER"])
    dos_header = _IMAGE_DOS_HEADER.from_buffer(uc_dos)


    if getattr(dos_header, "e_magic") is not 0x5A4D:
        print("Wrong DOS Magic Value (MZ). Aborting...")
        return None

    e_lfanew = getattr(dos_header, "e_lfanew")

    if header is "_IMAGE_DOS_HEADER":
        if hasattr(dos_header, field):
            return getattr(dos_header, field)
        else:
            return None
