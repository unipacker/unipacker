from ctypes import *


class _IMAGE_DATA_DIRECTORY(Structure):
    _pack_ = 1
    _fields_ = [
        ("VirtualAddress", c_uint32),
        ("Size", c_uint32),
    ]


class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _pack_ = 1
    _fields_ = [
        ("Characteristics", c_uint32),
        ("TimeDateStamp", c_uint32),
        ("ForwarderChain", c_uint32),
        ("Name", c_uint32),
        ("FirstThunk", c_uint32),
    ]


# Array of IMAGE_SECTION_HEADERS is Section TABLE
class IMAGE_SECTION_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("Name", c_char*8),
        ("VirtualSize", c_uint32),
        ("VirtualAddress", c_uint32),
        ("SizeOfRawData", c_uint32),
        ("PointerToRawData", c_uint32),
        ("PointerToRelocations", c_uint32),
        ("PointerToLinenumbers", c_uint32),
        ("NumberOfRelocations", c_uint16),
        ("NumberOfLinenumbers", c_uint16),
        ("Characteristics", c_uint32),
    ]


class _IMAGE_OPTIONAL_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("Magic", c_uint16),
        ("MajorLinkerVersion", c_char),
        ("MinorLinkerVersion", c_char),
        ("SizeOfCode", c_uint32),
        ("SizeOfInitializedData", c_uint32),
        ("SizeOfUninitializedData", c_uint32),
        ("AddressOfEntryPoint", c_uint32),
        ("BaseOfCode", c_uint32),
        ("BaseOfData", c_uint32),
        ("ImageBase", c_uint32),
        ("SectionAlignment", c_uint32),
        ("FileAlignment", c_uint32),
        ("MajorOperatingSystemVersion", c_uint16),
        ("MinorOperatingSystemVersion", c_uint16),
        ("MajorImageVersion", c_uint16),
        ("MinorImageVersion", c_uint16),
        ("MajorSubsystemVersion", c_uint16),
        ("MinorSubsystemVersion", c_uint16),
        ("Win32VersionValue", c_uint32),
        ("SizeOfImage", c_uint32),
        ("SizeOfHeaders", c_uint32),
        ("CheckSum", c_uint32),
        ("Subsystem", c_uint16),
        ("DllCharacteristics", c_uint16),
        ("SizeOfStackReserve", c_uint32),
        ("SizeOfStackCommit", c_uint32),
        ("SizeOfHeapReserve", c_uint32),
        ("SizeOfHeapCommit", c_uint32),
        ("LoaderFlags", c_uint32),
        ("NumberOfRvaAndSizes", c_uint32),
        ("DataDirectory", _IMAGE_DATA_DIRECTORY*16),
    ]


# PE HEADER = COFF HEADER
class _IMAGE_FILE_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("Signature", c_uint32),
        ("Machine", c_uint16),
        ("NumberOfSections", c_uint16),
        ("TimeDateStamp", c_uint32),
        ("PointerToSymbolTable", c_uint32),
        ("NumberOfSymbols", c_uint32),
        ("SizeOfOptionalHeader", c_uint16),
        ("Characteristics", c_uint16),
    ]


# DOS HEADER
class _IMAGE_DOS_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ("e_magic", c_uint16),
        ("e_cblp", c_uint16),
        ("e_cp", c_uint16),
        ("e_crlc", c_uint16),
        ("e_cparhdr", c_uint16),
        ("e_minalloc", c_uint16),
        ("e_maxalloc", c_uint16),
        ("e_ss", c_uint16),
        ("e_sp", c_uint16),
        ("e_csum", c_uint16),
        ("e_ip", c_uint16),
        ("e_cs", c_uint16),
        ("e_lfarlc", c_uint16),
        ("e_ovno", c_uint16),
        ("e_res", c_char*8),
        ("e_oemid", c_uint16),
        ("e_oeminfo", c_uint16),
        ("e_res2", c_char*20),
        ("e_lfanew", c_uint32),
    ]
