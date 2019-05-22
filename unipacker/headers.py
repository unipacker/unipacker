import struct
from ctypes import *
from datetime import datetime

from unicorn import UcError

from unipacker.pe_structs import _IMAGE_DOS_HEADER, _IMAGE_FILE_HEADER, _IMAGE_OPTIONAL_HEADER, IMAGE_SECTION_HEADER, \
    _IMAGE_DATA_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR, SectionHeader, DosHeader, PEHeader, OptionalHeader, \
    ImportDescriptor, DataDirectory
from unipacker.utils import InvalidPEFile, ImportValues, get_string

header_sizes = {
    "_IMAGE_DOS_HEADER": len(bytes(_IMAGE_DOS_HEADER())),  # 0x40
    "_IMAGE_FILE_HEADER": len(bytes(_IMAGE_FILE_HEADER())),  # 0x18
    "_IMAGE_OPTIONAL_HEADER": len(bytes(_IMAGE_OPTIONAL_HEADER())),  # 0xE0
    "IMAGE_SECTION_HEADER": len(bytes(IMAGE_SECTION_HEADER())),  # 0x28
    "_IMAGE_DATA_DIRECTORY": len(bytes(_IMAGE_DATA_DIRECTORY())),  # 0x8
    "IMAGE_IMPORT_DESCRIPTOR": len(bytes(IMAGE_IMPORT_DESCRIPTOR())),
}

short_hdr_names = {
    "DOS": "_IMAGE_DOS_HEADER",
    "DOS_HEADER": "_IMAGE_DOS_HEADER",
    "DOS_HDR": "_IMAGE_DOS_HEADER",
    "IMAGE_DOS_HEADER": "_IMAGE_DOS_HEADER",
    "PE": "_IMAGE_FILE_HEADER",
    "PE_HEADER": "_IMAGE_FILE_HEADER",
    "PE_HDR": "_IMAGE_FILE_HEADER",
    "FILE_HEADER": "_IMAGE_FILE_HEADER",
    "FILE_HDR": "_IMAGE_FILE_HEADER",
    "IMAGE_FILE_HEADER": "_IMAGE_FILE_HEADER",
    "OPT": "_IMAGE_OPTIONAL_HEADER",
    "OPT_HEADER": "_IMAGE_OPTIONAL_HEADER",
    "OPT_HDR": "_IMAGE_OPTIONAL_HEADER",
    "OPTIONAL": "_IMAGE_OPTIONAL_HEADER",
    "OPTIONAL_HEADER": "_IMAGE_OPTIONAL_HEADER",
    "OPTIONAL_HDR": "_IMAGE_OPTIONAL_HEADER",
    "IMAGE_OPTIONAL_HEADER": "_IMAGE_OPTIONAL_HEADER",
    "SECTION_HEADER": "IMAGE_SECTION_HEADER",
    "SEC_HEADER": "IMAGE_SECTION_HEADER",
    "SEC_HDR": "IMAGE_SECTION_HEADER",
    "SECTION_HDR": "IMAGE_SECTION_HEADER",
    "SECT_HEADER": "IMAGE_SECTION_HEADER",
    "SECT_HDR": "IMAGE_SECTION_HEADER",
}

datadirectory_pos = {0: "IMAGE_DIRECTORY_ENTRY_EXPORT", 1: "IMAGE_DIRECTORY_ENTRY_IMPORT",
                     2: "IMAGE_DIRECTORY_ENTRY_RESOURCE", 3: "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
                     4: "IMAGE_DIRECTORY_ENTRY_SECURITY", 5: "IMAGE_DIRECTORY_ENTRY_BASERELOC",
                     6: "IMAGE_DIRECTORY_ENTRY_DEBUG", 7: "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
                     8: "IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 9: "IMAGE_DIRECTORY_ENTRY_TLS",
                     10: "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 11: "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
                     12: "IMAGE_DIRECTORY_ENTRY_IAT", 13: "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
                     14: "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 15: "IMAGE_DIRECTORY_ENTRY_RESERVED"}

datadirectory_entry_to_pos = {"IMAGE_DIRECTORY_ENTRY_EXPORT": 0, "IMAGE_DIRECTORY_ENTRY_IMPORT": 1,
                              "IMAGE_DIRECTORY_ENTRY_RESOURCE": 2, "IMAGE_DIRECTORY_ENTRY_EXCEPTION": 3,
                              "IMAGE_DIRECTORY_ENTRY_SECURITY": 4, "IMAGE_DIRECTORY_ENTRY_BASERELOC": 5,
                              "IMAGE_DIRECTORY_ENTRY_DEBUG": 6, "IMAGE_DIRECTORY_ENTRY_COPYRIGHT": 7,
                              "IMAGE_DIRECTORY_ENTRY_GLOBALPTR": 8, "IMAGE_DIRECTORY_ENTRY_TLS": 9,
                              "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG": 10, "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT": 11,
                              "IMAGE_DIRECTORY_ENTRY_IAT": 12, "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT": 13,
                              "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR": 14, "IMAGE_DIRECTORY_ENTRY_RESERVED": 15}


def parse_disk_to_header(sample, query_header=None):
    offsets = {}
    # Read DOS Header
    with open(sample, 'rb') as f:
        dos_read = bytearray(f.read(header_sizes["_IMAGE_DOS_HEADER"]))
        dos_header = _IMAGE_DOS_HEADER.from_buffer(dos_read)

        if getattr(dos_header, "e_magic") != 0x5A4D:
            print(f"e_magic = {getattr(dos_header, 'e_magic')}")
            print("Wrong DOS Magic Value (MZ). Aborting...")
            raise InvalidPEFile

        e_lfanew = getattr(dos_header, "e_lfanew")

        if query_header == "e_lfanew":
            return e_lfanew

        if query_header == "_IMAGE_DOS_HEADER":
            return dos_header

        offsets["_IMAGE_DOS_HEADER"] = 0

        # Read PE Header
        pe_hdr_offset = e_lfanew
        f.seek(pe_hdr_offset)
        offsets["_IMAGE_FILE_HEADER"] = pe_hdr_offset
        pe_read = bytearray(f.read(header_sizes["_IMAGE_FILE_HEADER"]))
        pe_header = _IMAGE_FILE_HEADER.from_buffer(pe_read)

        if getattr(pe_header, "Signature") != 0x4550:
            print(f"Signature: {getattr(pe_header, 'Signature')}")
            print("Wrong PE Header Signature. Aborting...")
            raise InvalidPEFile

        number_of_sections = getattr(pe_header, "NumberOfSections")

        if query_header == "NumberOfSections":
            return number_of_sections

        if query_header == "_IMAGE_FILE_HEADER":
            return pe_header

        # Read Optional Header
        opt_hdr_offset = pe_hdr_offset + header_sizes["_IMAGE_FILE_HEADER"]
        f.seek(opt_hdr_offset)
        offsets["_IMAGE_OPTIONAL_HEADER"] = opt_hdr_offset
        opt_read = bytearray(f.read(header_sizes["_IMAGE_OPTIONAL_HEADER"]))
        opt_header = _IMAGE_OPTIONAL_HEADER.from_buffer(opt_read)

        if getattr(opt_header, "Magic") != 0x10B:
            print(f"OPT Magic: {getattr(opt_header, 'Magic')}")
            print("Wrong Optional Header Magic. Aborting...")
            raise InvalidPEFile

        if query_header == "_IMAGE_OPTIONAL_HEADER":
            return opt_header

        if query_header == "_IMAGE_DATA_DIRECTORY":
            return getattr(opt_header, "DataDirectory")

        rva_to_IMAGE_IMPORT_DESCRIPTOR = getattr(getattr(opt_header, "DataDirectory")[1], "VirtualAddress")
        size_import_table = getattr(getattr(opt_header, "DataDirectory")[1], "Size")
        #import_table = get_imp(uc, rva_to_IMAGE_IMPORT_DESCRIPTOR, base_addr, size_import_table)
        import_descriptor_table = []
        # TODO Use this when custom loader finished
        #for x in range(int((size_import_table / header_sizes["IMAGE_IMPORT_DESCRIPTOR"]))):
        #    f.seek(rva_to_IMAGE_IMPORT_DESCRIPTOR)
        #    imp_descriptor_read = bytearray(f.read(header_sizes["IMAGE_IMPORT_DESCRIPTOR"]))
        #    imp_descriptor = IMAGE_IMPORT_DESCRIPTOR.from_buffer(imp_descriptor_read)
        #    if getattr(imp_descriptor, "Characteristics") != 0 or getattr(imp_descriptor, "FirstThunk") != 0:
        #        import_descriptor_table.append(imp_descriptor)
        #        rva_to_IMAGE_IMPORT_DESCRIPTOR += header_sizes["IMAGE_IMPORT_DESCRIPTOR"]
        #    else:
        #        break
        if query_header == "IMPORTS":
            return import_descriptor_table

        # Read Section Header
        section_hdr_offset = opt_hdr_offset + header_sizes["_IMAGE_OPTIONAL_HEADER"]
        offsets["IMAGE_SECTION_HEADER"] = section_hdr_offset
        section_headers = []
        for i in range(number_of_sections):
            f.seek(section_hdr_offset)
            sec_read = bytearray(f.read(header_sizes["IMAGE_SECTION_HEADER"]))
            sec_header = IMAGE_SECTION_HEADER.from_buffer(sec_read)
            section_headers.append(sec_header)
            section_hdr_offset += header_sizes["IMAGE_SECTION_HEADER"]

        if query_header == "IMAGE_SECTION_HEADER":
            return section_headers

        if query_header == "Offsets":
            return offsets

        headers = {"_IMAGE_DOS_HEADER": dos_header, "_IMAGE_FILE_HEADER": pe_header,
                   "_IMAGE_OPTIONAL_HEADER": opt_header,
                   "IMAGE_SECTION_HEADER": section_headers, "IMPORTS": import_descriptor_table, }

        return headers


def get_disk_headers(sample):
    return parse_disk_to_header(sample.path)


def conv_to_class_header(header):
    header_types = {
        _IMAGE_DOS_HEADER: DosHeader,
        _IMAGE_FILE_HEADER: PEHeader,
        _IMAGE_OPTIONAL_HEADER: OptionalHeader,
        IMAGE_SECTION_HEADER: SectionHeader,
        IMAGE_IMPORT_DESCRIPTOR: ImportDescriptor,
        _IMAGE_DATA_DIRECTORY: DataDirectory,
    }
    if isinstance(header, list) or isinstance(header, Array):
        converted = []
        for h in header:
            converted.append(conv_to_class_header(h))
        return converted
    else:
        for hdr_type in header_types:
            if isinstance(header, hdr_type):
                new_header = header_types[hdr_type](header)
                if isinstance(new_header, OptionalHeader):
                    new_header.DataDirectory = conv_to_class_header(new_header.DataDirectory)
                return new_header


def parse_memory_to_header(uc, base_addr, query_header=None):
    # Read DOS Header
    uc_dos = uc.mem_read(base_addr, header_sizes["_IMAGE_DOS_HEADER"])
    dos_header = _IMAGE_DOS_HEADER.from_buffer(uc_dos)

    if getattr(dos_header, "e_magic") != 0x5A4D:
        print(f"e_magic = {getattr(dos_header, 'e_magic')}")
        print("Wrong DOS Magic Value (MZ). Aborting...")
        raise InvalidPEFile

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
        raise InvalidPEFile

    number_of_sections = getattr(pe_header, "NumberOfSections")

    if query_header == "NumberOfSections":
        return number_of_sections

    if query_header == "_IMAGE_FILE_HEADER":
        return pe_header

    # Read Optional Header
    opt_hdr_offset = pe_hdr_offset + header_sizes["_IMAGE_FILE_HEADER"]
    uc_opt = uc.mem_read(opt_hdr_offset, header_sizes["_IMAGE_OPTIONAL_HEADER"])
    opt_header = _IMAGE_OPTIONAL_HEADER.from_buffer(uc_opt)

    if getattr(opt_header, "Magic") != 0x10B:
        print(f"OPT Magic: {getattr(opt_header, 'Magic')}")
        print("Wrong Optional Header Magic. Aborting...")
        raise InvalidPEFile

    if query_header == "_IMAGE_OPTIONAL_HEADER":
        return opt_header

    if query_header == "_IMAGE_DATA_DIRECTORY":
        return getattr(opt_header, "DataDirectory")

    rva_to_IMAGE_IMPORT_DESCRIPTOR = getattr(getattr(opt_header, "DataDirectory")[1], "VirtualAddress")
    size_import_table = getattr(getattr(opt_header, "DataDirectory")[1], "Size")
    import_table = get_imp(uc, rva_to_IMAGE_IMPORT_DESCRIPTOR, base_addr, size_import_table)

    if query_header == "IMPORTS":
        return import_table

    # Read Section Header
    section_hdr_offset = opt_hdr_offset + header_sizes["_IMAGE_OPTIONAL_HEADER"]
    section_headers = []
    for i in range(number_of_sections):
        uc_sec = uc.mem_read(section_hdr_offset, header_sizes["IMAGE_SECTION_HEADER"])
        sec_header = IMAGE_SECTION_HEADER.from_buffer(uc_sec)
        section_headers.append(sec_header)
        section_hdr_offset += header_sizes["IMAGE_SECTION_HEADER"]

    if query_header == "IMAGE_SECTION_HEADER":
        return section_headers

    headers = {"_IMAGE_DOS_HEADER": dos_header, "_IMAGE_FILE_HEADER": pe_header, "_IMAGE_OPTIONAL_HEADER": opt_header,
               "IMAGE_SECTION_HEADER": section_headers, "IMPORTS": import_table, }

    return headers


def get_imp(uc, rva, base_addr, SizeOfImportTable, read_values=False):
    rva += base_addr
    entry_size = len(bytes(IMAGE_IMPORT_DESCRIPTOR()))
    num_of_dll = SizeOfImportTable // entry_size
    imp_info_list = []
    imp_struct_list = []
    for i in range(num_of_dll):
        uc_imp = uc.mem_read(rva, entry_size)
        imp_struct = IMAGE_IMPORT_DESCRIPTOR.from_buffer(uc_imp)
        imp_struct_list.append(imp_struct)
        if read_values:
            try:
                dll_name = get_string(getattr(imp_struct, "Name") + base_addr, uc, break_on_unprintable=True)
                imp_names = []
                rva_to_iat = getattr(imp_struct, "FirstThunk")
                while True:
                    new_val = struct.unpack("<I", uc.mem_read(base_addr + rva_to_iat, 4))[0]
                    if new_val == 0:
                        break
                    imp_name = (get_string(new_val + 2 + base_addr, uc, break_on_unprintable=True), rva_to_iat)
                    imp_names.append(imp_name)
                    rva_to_iat += 4

                imp_info_list.append(ImportValues(imp_struct, dll_name, imp_names))
            except UcError as ue:
                return imp_info_list

        rva += entry_size

    if read_values:
        return imp_info_list
    return imp_struct_list


# Deprecated
def print_struc(s, offset, name):
    print(name + ":")
    for field_name, field_type in s._fields_:
        if isinstance(getattr(s, field_name), Array):
            print(f"\t +0x{offset:02x} {field_name}:")
            sub_offset = offset
            for i in range(len(getattr(s, field_name))):
                for sub_field_name, sub_field_type in getattr(s, field_name)[i]._fields_:
                    print(f"\t\t +{hex(sub_offset)} {sub_field_name}: "
                          f"{getattr(getattr(s, field_name)[i], sub_field_name)}")
                    sub_offset += len(bytes(sub_field_type()))
        else:
            print(f"\t +0x{offset:02x} {field_name}: {getattr(s, field_name)}")
        offset += len(bytes(field_type()))


def print_struc_rec(s, offset, name, indent='\t', array_dict=None):
    if name is not None:
        print(f"\x1b[33m{name}:\x1b[0m")
    for field_name, field_type in s._fields_:
        if isinstance(getattr(s, field_name), Array):
            print(indent + f" +0x{offset:02x} {field_name}:")
            new_indent = indent
            for i in range(len(getattr(s, field_name))):
                if array_dict is not None:
                    new_indent = '\t' + new_indent
                    print(new_indent + f" +0x{offset:02x} {array_dict[i]}:")
                if hasattr(getattr(s, field_name)[i], "_fields_"):
                    offset = print_struc_rec(getattr(s, field_name)[i], offset, None, '\t' + new_indent)
                else:
                    print(indent + f" +0x{offset:02x} {field_name}: {getattr(s, field_name)}")
                new_indent = indent
        else:
            if isinstance(getattr(s, field_name), int):
                if "TimeDateStamp" in field_name:
                    print(f"{indent} +0x{offset:02x} {field_name}: "
                          "\x1b[31m"
                          f"{datetime.utcfromtimestamp(getattr(s, field_name)).strftime('%Y-%m-%d %H:%M:%S')}"
                          "\x1b[0m")
                else:
                    print(f"{indent} +0x{offset:02x} {field_name}: \x1b[31m{hex(getattr(s, field_name))}\x1b[0m")
            else:
                print(f"\t +0x{offset:02x} {field_name}: {getattr(s, field_name)}")
            offset += len(bytes(field_type()))
    return offset


def print_dos_header(uc, base_addr):
    dos_header = parse_memory_to_header(uc, base_addr, "_IMAGE_DOS_HEADER")
    # print_struc(dos_header, 0, "_IMAGE_DOS_HEADER")
    print_struc_rec(dos_header, 0, "_IMAGE_DOS_HEADER")


def print_pe_header(uc, base_addr):
    pe_header = parse_memory_to_header(uc, base_addr, "_IMAGE_FILE_HEADER")
    offset = parse_memory_to_header(uc, base_addr, "e_lfanew")
    print_struc_rec(pe_header, offset, "_IMAGE_FILE_HEADER")


def print_opt_header(uc, base_addr):
    opt_header = parse_memory_to_header(uc, base_addr, "_IMAGE_OPTIONAL_HEADER")
    offset = parse_memory_to_header(uc, base_addr, "e_lfanew") + header_sizes["_IMAGE_FILE_HEADER"]
    print_struc_rec(opt_header, offset, "_IMAGE_OPTIONAL_HEADER", '\t', datadirectory_pos)
    # print_struc(opt_header, offset, "_IMAGE_OPTIONAL_HEADER")


def print_section_table(uc, base_addr):
    section_table = parse_memory_to_header(uc, base_addr, "IMAGE_SECTION_HEADER")
    offset = parse_memory_to_header(uc, base_addr, "e_lfanew") + header_sizes["_IMAGE_FILE_HEADER"] + header_sizes[
        "_IMAGE_OPTIONAL_HEADER"]
    for i in range(len(section_table)):
        print_struc_rec(section_table[i], offset, "IMAGE_SECTION_HEADER")
        offset += header_sizes["IMAGE_SECTION_HEADER"]


def print_iat(uc, base_addr):
    imp = parse_memory_to_header(uc, base_addr, "IMPORTS")
    print("\x1b[33mIMPORT ADDRESS TABLE:\x1b[0m")
    for i in imp:
        indent = '\t'
        if i.Name == 0:
            return
        print(f"{indent} Name: \x1b[31m{get_string(base_addr + i.Name, uc)}\x1b[0m")
        print(f"{indent} Characteristics (Hint/Name): \x1b[31m{hex(i.Characteristics)}\x1b[0m")
        print(f"{indent} TimeDateStamp: \x1b[31m{hex(i.TimeDateStamp)}\x1b[0m")
        print(f"{indent} ForwarderChain: \x1b[31m{hex(i.ForwarderChain)}\x1b[0m")
        print(f"{indent} FirstThunk: \x1b[31m{hex(i.FirstThunk)}\x1b[0m")
        indent = '\t\t'

        if i.Characteristics == 0:
            print(f"{indent} Hint/Name Array is not set")
        else:
            curr_pos = 0
            imp_array_element = struct.unpack("<I", uc.mem_read(base_addr + i.Characteristics, 4))[0]
            if (imp_array_element >> 20) == 0x1 and ((imp_array_element & 0xFFEFFFFF) >> 14) == 0x1:
                print(f"{indent}No resolving of imports as hookaddr values are set")
                continue
            while imp_array_element != 0:
                if imp_array_element >> 0x1f == 1:
                    print(f"{indent} Import by Ordinal: \x1b[31m{hex(imp_array_element - 0x80000000)}\x1b[0m")
                else:
                    print(f"{indent} Import by Name: "
                          f"\x1b[31m{get_string(base_addr + imp_array_element + 0x2, uc)}\x1b[0m")
                curr_pos += 0x4
                imp_array_element = struct.unpack("<I", uc.mem_read(base_addr + i.Characteristics + curr_pos, 4))[0]

            print()


def print_all_headers(uc, base_addr):
    print_dos_header(uc, base_addr)
    print()
    print_pe_header(uc, base_addr)
    print()
    print_opt_header(uc, base_addr)
    print()
    print_section_table(uc, base_addr)
    print()
    print_iat(uc, base_addr)


def calc_offset(e_lfanew, num_of_sec, base_addr, header=None):
    if header in short_hdr_names.keys():
        header = short_hdr_names[header]

    opt_start = base_addr + e_lfanew + header_sizes["_IMAGE_FILE_HEADER"]
    st_start = opt_start + header_sizes["_IMAGE_OPTIONAL_HEADER"]

    offsets = {"_IMAGE_DOS_HEADER": (base_addr, base_addr + header_sizes["_IMAGE_DOS_HEADER"]),
               "_IMAGE_FILE_HEADER": (base_addr + e_lfanew, opt_start), "_IMAGE_OPTIONAL_HEADER": (opt_start, st_start),
               "IMAGE_SECTION_HEADER": (st_start, st_start + (header_sizes["IMAGE_SECTION_HEADER"]) * num_of_sec)}

    if header in offsets.keys():
        return offsets[header]

    return offsets


# TODO update numofsec
def inject_section(uc, base_addr, sec_struct):
    soff, eoff = calc_offset(parse_memory_to_header(uc, base_addr, "e_lfanew"),
                             parse_memory_to_header(uc, base_addr, "NumberOfSections"), base_addr, "SEC_HDR")
    payload = bytes(sec_struct)
    uc.mem_write(eoff, payload)


# TODO broken
def hdr_write(uc, base_addr, header, array_pos, **fields):
    if header in short_hdr_names.keys():
        header = short_hdr_names[header]
    if header in datadirectory_entry_to_pos.keys():
        array_pos = datadirectory_entry_to_pos[header]
        header = "_IMAGE_DATA_DIRECTORY"

    header_struct = parse_memory_to_header(uc, base_addr, header)
    if header_struct is None:
        print("Invalid PE File!")
        return None

    if isinstance(header_struct, Array) or isinstance(header_struct, list):
        if array_pos is None:
            print("The specified header field is an array. No array position spcified. Selecting first array elemnt")
            array_pos = 0
        if hasattr(header_struct[array_pos], "_fields_"):
            header_struct = header_struct[array_pos]

    for k, v in fields:
        if hasattr(header_struct, k):
            setattr(header_struct, k, v)


def pe_write(uc, base_addr, total_size, filename):
    data = uc.mem_read(base_addr, total_size)
    with open(filename, 'wb+') as f:
        f.write(data)


def hdr_read(uc, base_addr, header, field, array_pos=None, str_as_bytes=False):
    if header in short_hdr_names.keys():
        header = short_hdr_names[header]
    if header in datadirectory_entry_to_pos.keys():
        array_pos = datadirectory_entry_to_pos[header]
        header = "_IMAGE_DATA_DIRECTORY"
    header_struct = parse_memory_to_header(uc, base_addr, header)
    if header_struct is None:
        print("Invalid PE File!")
        return None

    if field is None:
        if array_pos is not None:
            header_struct = header_struct[array_pos]
        return header_struct

    if isinstance(header_struct, Array) or isinstance(header_struct, list):
        if array_pos is None:
            print("The specified header field is an array. No array position spcified. Selecting first array elemnt")
            array_pos = 0
        if hasattr(header_struct[array_pos], "_fields_"):
            return getattr(header_struct[array_pos], field)

    if hasattr(header_sizes, field):
        ret_val = getattr(header_struct, field)
        if isinstance(ret_val, bytes) and not str_as_bytes:
            return ret_val.decode('ascii')
        return ret_val

    print("Requested field not found. Returning None")

    return None


class PE(object):
    def __init__(self, uc, base_addr):
        self.base_addr = base_addr
        headers = parse_memory_to_header(uc, self.base_addr)
        self.dos_header = headers["_IMAGE_DOS_HEADER"]
        self.pe_header = headers["_IMAGE_FILE_HEADER"]
        self.opt_header = headers["_IMAGE_OPTIONAL_HEADER"]
        self.data_directories = [directory for directory in getattr(headers["_IMAGE_OPTIONAL_HEADER"], "DataDirectory")]
        self.section_list = headers["IMAGE_SECTION_HEADER"]
        self.DIRECTORY_ENTRY_IMPORT = headers["IMPORTS"]

    def update(self, uc, base_addr):
        self.base_addr = base_addr
        headers = parse_memory_to_header(uc, self.base_addr)
        self.dos_header = headers["_IMAGE_DOS_HEADER"]
        self.pe_header = headers["_IMAGE_FILE_HEADER"]
        self.opt_header = headers["_IMAGE_OPTIONAL_HEADER"]
        self.data_directories = [directory for directory in getattr(headers["_IMAGE_OPTIONAL_HEADER"], "DataDirectory")]
        self.section_list = headers["IMAGE_SECTION_HEADER"]
        self.DIRECTORY_ENTRY_IMPORT = headers["IMPORTS"]

    def sync(self, uc):
        e_lfanew = self.dos_header.e_lfanew
        num_of_sec = self.pe_header.NumberOfSections

        offset = calc_offset(e_lfanew, num_of_sec, self.base_addr)
        dos_offset, _ = offset["_IMAGE_DOS_HEADER"]
        pe_offset, _ = offset["_IMAGE_FILE_HEADER"]

        dos_payload = bytes(self.dos_header)
        pe_payload = bytes(self.pe_header)

        datadirectory_array = _IMAGE_DATA_DIRECTORY * 16
        datadirectory = datadirectory_array(*list(self.data_directories))

        setattr(self.opt_header, "DataDirectory", datadirectory)

        opt_payload = bytes(self.opt_header)

        section_array = IMAGE_SECTION_HEADER * num_of_sec
        section_table_payload = bytes(section_array(*list(self.section_list)))

        combined_payload = pe_payload + opt_payload + section_table_payload

        uc.mem_write(dos_offset, dos_payload)
        uc.mem_write(pe_offset, combined_payload)
