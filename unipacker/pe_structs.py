from ctypes import *

from unipacker.utils import convert_to_string


class _IMAGE_DATA_DIRECTORY(Structure):
    _pack_ = 1
    _fields_ = [
        ("VirtualAddress", c_uint32),
        ("Size", c_uint32),
    ]


class DataDirectory(object):
    def __init__(self, image_data_directory):
        self.VirtualAddress = getattr(image_data_directory, "VirtualAddress")
        self.Size = getattr(image_data_directory, "Size")


class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _pack_ = 1
    _fields_ = [
        ("Characteristics", c_uint32),
        ("TimeDateStamp", c_uint32),
        ("ForwarderChain", c_uint32),
        ("Name", c_uint32),
        ("FirstThunk", c_uint32),
    ]


class ImportDescriptor(object):
    def __init__(self, image_import_descriptor, Characteristics=None, TimeDateStamp=None, ForwarderChain=None, Name=None, FirstThunk=None):
        if image_import_descriptor is not None:
            self.Characteristics = getattr(image_import_descriptor, "Characteristics")
            self.TimeDateStamp = getattr(image_import_descriptor, "TimeDataStamp")
            self.ForwarderChain = getattr(image_import_descriptor, "ForwarderChain")
            self.Name = getattr(image_import_descriptor, "Name")
            self.FirstThunk = getattr(image_import_descriptor, "FirstThunk")
        else:
            self.Characteristics = Characteristics
            self.TimeDateStamp = TimeDateStamp
            self.ForwarderChain = ForwarderChain
            self.Name = Name
            self.FirstThunk = FirstThunk


class Import(object):
    def __init__(self, Import_Descriptor, name=None, imports=[], ordinal=None):
        self.ordinal = ordinal  # TODO Update ordinals
        self.Import_Descriptor = Import_Descriptor
        self.name = name
        self.imports = imports



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


class SectionHeader(object):
    def __init__(self, image_section_hdr):
        self.Name = convert_to_string(getattr(image_section_hdr, "Name"))
        self.VirtualSize = getattr(image_section_hdr, "VirtualSize")
        self.VirtualAddress = getattr(image_section_hdr, "VirtualAddress")
        self.SizeOfRawData = getattr(image_section_hdr, "SizeOfRawData")
        self.PointerToRawData = getattr(image_section_hdr, "PointerToRawData")
        self.PointerToRelocations = getattr(image_section_hdr, "PointerToRelocations")
        self.PointerToLinenumbers = getattr(image_section_hdr, "PointerToLinenumbers")
        self.NumberOfRelocations = getattr(image_section_hdr, "NumberOfRelocations")
        self.NumberOfLinenumbers = getattr(image_section_hdr, "NumberOfLinenumbers")
        self.Characteristics = getattr(image_section_hdr, "Characteristics")


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


class OptionalHeader(object):
    def __init__(self, image_optional_header):
        self.Magic = getattr(image_optional_header, "Magic")
        self.MajorLinkerVersion = getattr(image_optional_header, "MajorLinkerVersion")
        self.MinorLinkerVersion = getattr(image_optional_header, "MinorLinkerVersion")
        self.SizeOfCode = getattr(image_optional_header, "SizeOfCode")
        self.SizeOfInitializedData = getattr(image_optional_header, "SizeOfInitializedData")
        self.SizeOfUninitializedData = getattr(image_optional_header, "SizeOfUninitializedData")
        self.AddressOfEntryPoint = getattr(image_optional_header, "AddressOfEntryPoint")
        self.BaseOfCode = getattr(image_optional_header, "BaseOfCode")
        self.BaseOfData = getattr(image_optional_header, "BaseOfData")
        self.ImageBase = getattr(image_optional_header, "ImageBase")
        self.SectionAlignment = getattr(image_optional_header, "SectionAlignment")
        self.FileAlignment = getattr(image_optional_header, "FileAlignment")
        self.MajorOperatingSystemVersion = getattr(image_optional_header, "MajorOperatingSystemVersion")
        self.MinorOperatingSystemVersion = getattr(image_optional_header, "MinorOperatingSystemVersion")
        self.MajorImageVersion = getattr(image_optional_header, "MajorImageVersion")
        self.MinorImageVersion = getattr(image_optional_header, "MinorImageVersion")
        self.MajorSubsystemVersion = getattr(image_optional_header, "MajorSubsystemVersion")
        self.MinorSubsystemVersion = getattr(image_optional_header, "MinorSubsystemVersion")
        self.Win32VersionValue = getattr(image_optional_header, "Win32VersionValue")
        self.SizeOfImage = getattr(image_optional_header, "SizeOfImage")
        self.CheckSum = getattr(image_optional_header, "CheckSum")
        self.Subsystem = getattr(image_optional_header, "Subsystem")
        self.DllCharacteristics = getattr(image_optional_header, "DllCharacteristics")
        self.SizeOfStackReserve = getattr(image_optional_header, "SizeOfStackReserve")
        self.SizeOfStackCommit = getattr(image_optional_header, "SizeOfStackCommit")
        self.SizeOfHeapReserve = getattr(image_optional_header, "SizeOfHeapReserve")
        self.SizeOfHeapCommit = getattr(image_optional_header, "SizeOfHeapCommit")
        self.LoaderFlags = getattr(image_optional_header, "LoaderFlags")
        self.NumberOfRvaAndSizes = getattr(image_optional_header, "NumberOfRvaAndSizes")
        self.DataDirectory = getattr(image_optional_header, "DataDirectory")


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


class PEHeader(object):
    def __init__(self, image_file_header):
        self.Signature = getattr(image_file_header, "Signature")
        self.Machine = getattr(image_file_header, "Machine")
        self.NumberOfSections = getattr(image_file_header, "NumberOfSections")
        self.TimeDateStamp = getattr(image_file_header, "TimeDateStamp")
        self.PointerToSymbolTable = getattr(image_file_header, "PointerToSymbolTable")
        self.NumberOfSymbols = getattr(image_file_header, "NumberOfSymbols")
        self.SizeOfOptionalHeader = getattr(image_file_header, "SizeOfOptionalHeader")
        self.Characteristics = getattr(image_file_header, "Characteristics")


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


class DosHeader(object):
    def __init__(self, image_dos_header):
        self.e_magic = getattr(image_dos_header, "e_magic")
        self.e_cblp = getattr(image_dos_header, "e_cblp")
        self.e_cp = getattr(image_dos_header, "e_cp")
        self.e_crlc = getattr(image_dos_header, "e_crlc")
        self.e_cparhdr = getattr(image_dos_header, "e_cparhdr")
        self.e_minalloc = getattr(image_dos_header, "e_minalloc")
        self.e_maxalloc = getattr(image_dos_header, "e_maxalloc")
        self.e_ss = getattr(image_dos_header, "e_ss")
        self.e_sp = getattr(image_dos_header, "e_sp")
        self.e_csum = getattr(image_dos_header, "e_csum")
        self.e_ip = getattr(image_dos_header, "e_ip")
        self.e_cs = getattr(image_dos_header, "e_cs")
        self.e_lfarlc = getattr(image_dos_header, "e_lfarlc")
        self.e_ovno = getattr(image_dos_header, "e_ovno")
        self.e_res = getattr(image_dos_header, "e_res")
        self.e_oemid = getattr(image_dos_header, "e_oemid")
        self.e_oeminfo = getattr(image_dos_header, "e_oeminfo")
        self.e_res2 = getattr(image_dos_header, "e_res2")
        self.e_lfanew = getattr(image_dos_header, "e_lfanew")
